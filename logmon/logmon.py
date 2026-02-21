from typing import Iterable, Generator, Callable, Match, Optional, NamedTuple, TextIO, Mapping, Protocol

import re
import os
import bz2
import gzip
import logging
import threading

from os import scandir
from os.path import abspath, normpath, split as splitpath
from time import monotonic, sleep
from fnmatch import translate
from errno import EINVAL
from stat import S_ISFIFO
from select import epoll, POLLIN

try:
    from compression import zstd
except ImportError:
    zstd = None # type: ignore

from .types import Compression, EncodingErrors
from .schema import Config, MTConfig, resolve_config
from .limiter import AbstractLimiter, build_limiters
from .systemd import is_systemd_path, logmon_systemd
from .constants import *
from .entry_readers import EntryReaderFactory, LogEntry
from .actions import Action
from .inotify_wait_for_exists import inotify_wait_for_exists
from .inotify import HAS_INOTIFY, PollInotify, TerminalEventException, IN_MODIFY, IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF, IN_MOVED_FROM, IN_MOVED_TO
from .global_state import is_running, handle_keyboard_interrupt, get_read_stopfd

logger = logging.getLogger(__name__)

__all__ = (
    'logmon_mt',
)

def fncompile(pattern: str) -> Callable[[str], Match|None]:
    return re.compile(translate(pattern)).match

def open_logfile(logfile: str, encoding: str, seek_end: bool, compression: Optional[Compression], errors: EncodingErrors) -> TextIO:
    match compression:
        case None:
            logfp = open(logfile, 'rt', encoding=encoding, errors=errors)

        case 'gzip':
            logfp = gzip.open(logfile, 'rt', encoding=encoding, errors=errors)

        case 'bz2':
            logfp = bz2.open(logfile, 'rt', encoding=encoding, errors=errors)

        case 'zstd':
            if zstd is None:
                raise ValueError(f'zstd support requires Python >=3.14')
            logfp = zstd.open(logfile, 'rt', encoding=encoding, errors=errors)

        case _:
            raise ValueError(f'Unsupported compression: {compression!r}')

    try:
        if seek_end:
            try:
                logfp.seek(0, os.SEEK_END)
            except OSError as exc:
                logger.error(f'{logfile}: {exc}', exc_info=exc)
        return logfp
    except:
        logfp.close()
        raise

def _logmon(
        logfile: str,
        config: Config,
        limiters: Mapping[str, AbstractLimiter],
) -> None:
    if is_systemd_path(logfile):
        return logmon_systemd(logfile, config, limiters)

    if config.get('glob'):
        return _logmon_glob(logfile, config, limiters)

    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    wait_for_more = config.get('wait_for_more', DEFAULT_WAIT_FOR_MORE)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    encoding = config.get('encoding', 'UTF-8')
    errors = config.get('encoding_errors', DEFAULT_ENCODING_ERRORS)
    seek_end = config.get('seek_end', True)
    use_inotify = config.get('use_inotify', HAS_INOTIFY)
    compression = config.get('compression')

    reader_factory = EntryReaderFactory.from_config(config)

    with Action.open_actions(config, limiters) as actions:
        stopfd = get_read_stopfd()
        poller: Optional[epoll] = None

        if use_inotify and HAS_INOTIFY:
            inotify = PollInotify(stopfd)
        else:
            inotify = None

        try:
            file_not_found = False
            terminated = False
            logfile_id: Optional[int] = None

            while is_running():
                try:
                    logfp = open_logfile(logfile, encoding, seek_end, compression, errors)
                    if file_not_found:
                        file_not_found = False
                        logger.debug(f"{logfile}: File appeared!")

                    try:
                        logfp_stat = os.fstat(logfp.fileno())
                        logfp_ref = (logfp_stat.st_dev, logfp_stat.st_ino)
                        is_fifo = S_ISFIFO(logfp_stat.st_mode)

                        read_entries: Callable[[bool], int]
                        if is_fifo:
                            if poller is None:
                                poller = epoll(2)
                                if stopfd is not None:
                                    poller.register(stopfd, POLLIN)
                            poller.register(logfp.fileno(), POLLIN)

                            read_entries = lambda do_wait: _read_entries_blocking(logfile, reader, max_entries, actions, poller, stopfd, None if do_wait else 0) # type: ignore
                        else:
                            read_entries = lambda do_wait: _read_entries(logfile, reader, wait_for_more if do_wait else 0, max_entries, actions, wait_on_empty_messages=do_wait)

                        reader = reader_factory.create_reader(logfp)

                        if inotify is not None:
                            terminated = False
                            logfile_id = inotify.add_watch(logfile, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)

                        while is_running():
                            entry_count = read_entries(True)

                            if entry_count < max_entries and is_running():
                                # If there are max_entries that means there are probably already more in the
                                # log file, so try to read those before waiting via inotify.
                                do_reopen = False
                                if inotify is not None:
                                    terminated = False
                                    logger.debug(f'{logfile}: Waiting with inotify for modifications')
                                    try:
                                        new_stat = os.stat(logfile)
                                        new_ref = (new_stat.st_dev, new_stat.st_ino)
                                        if logfp_ref != new_ref:
                                            # verify we're actually waiting on the file that is opened
                                            do_reopen = True
                                        else:
                                            do_wait = True
                                            while do_wait and inotify.wait() and is_running():

                                                for event in inotify.read_events():
                                                    if not is_running():
                                                        break

                                                    mask = event.mask
                                                    inotify_path = normpath(event.full_path())
                                                    if inotify_path == logfile:
                                                        if IN_MODIFY & mask:
                                                            do_wait = False
                                                            break

                                                        if IN_MOVE_SELF & mask:
                                                            do_wait = False
                                                            do_reopen = True
                                                            # this never fires because we have logfp open
                                                            break

                                                        if IN_MOVED_FROM & mask:
                                                            do_wait = False
                                                            do_reopen = True
                                                            break

                                                        if IN_MOVED_TO & mask:
                                                            do_wait = False
                                                            do_reopen = True
                                                            break

                                                        if (IN_DELETE | IN_DELETE_SELF) & mask:
                                                            do_wait = False
                                                            do_reopen = True
                                                            break

                                        if not is_running():
                                            break

                                    except TerminalEventException:
                                        # filesystem unmounted
                                        do_reopen = True
                                        terminated = True

                                else:
                                    logger.debug(f'{logfile}: Sleeping for {wait_no_entries} seconds for modifications')
                                    sleep(wait_no_entries)

                                    try:
                                        new_stat = os.stat(logfile)
                                    except FileNotFoundError:
                                        pass
                                    else:
                                        new_ref = (new_stat.st_dev, new_stat.st_ino)
                                        if logfp_ref != new_ref:
                                            do_reopen = True

                                if do_reopen:
                                    # try to read the rest before closing the file
                                    while read_entries(False) >= max_entries:
                                        pass

                                    logger.info(f"{logfile}: File changed, reopening...")
                                    try: logfp.close()
                                    except: pass
                                    seek_end = False
                                    config['seek_end'] = False
                                    break

                    finally:
                        if poller is not None:
                            try:
                                poller.unregister(logfp.fileno())
                            except Exception as exc:
                                logger.error(f'{logfile}: Unregistering epoll events')
                        try:
                            if inotify is not None:
                                if logfile_id is not None:
                                    try:
                                        inotify.remove_watch(logfile)
                                    except OSError as exc:
                                        if exc.errno == EINVAL:
                                            pass # happens when the file was deleted/moved away
                                        else:
                                            logger.error(f'{logfile}: Error while removing inotify watch: {exc}', exc_info=exc)
                                    except Exception as exc:
                                        logger.error(f'{logfile}: Error while removing inotify watch: {exc}', exc_info=exc)
                                    logfile_id = None

                                if terminated:
                                    try:
                                        inotify.close()
                                    except Exception as exc:
                                        logger.error(f'{logfile}: Error closing inotify: {exc}', exc_info=exc)
                                    inotify = PollInotify(get_read_stopfd())
                        finally:
                            if not logfp.closed:
                                try: logfp.close()
                                except: pass

                except FileNotFoundError:
                    file_not_found = True
                    seek_end = False
                    config['seek_end'] = False
                    if inotify is not None:
                        logger.error(f"{logfile}: File not found, waiting with inotify")
                        if not inotify_wait_for_exists(inotify, logfile):
                            break
                    else:
                        logger.error(f"{logfile}: File not found, waiting for {wait_file_not_found} seconds")
                        sleep(wait_file_not_found)

                except KeyboardInterrupt:
                    handle_keyboard_interrupt()

        finally:
            try:
                if inotify is not None:
                    inotify.close()
            finally:
                if poller is not None:
                    poller.close()

class IGlobEntry(Protocol):
    @property
    def logfile(self) -> str: ...

    @property
    def reader(self) -> Generator[LogEntry|None, None, None]: ...

    @property
    def stream(self) -> TextIO: ...

    @property
    def is_fifo(self) -> bool: ...

class GlobEntry(NamedTuple):
    logfile: str
    watch_id: int
    reader: Generator[LogEntry|None, None, None]
    stream: TextIO
    is_fifo: bool

    def close(self, inotify: PollInotify) -> None:
        try:
            inotify.remove_watch(self.logfile)
        except OSError as exc:
            if exc.errno == EINVAL:
                pass # happens when the file was deleted/moved away
            else:
                logger.error(f'{self.logfile}: Error while removing inotify watch: {exc}', exc_info=exc)
        except Exception as exc:
            logger.error(f'{self.logfile}: Error while removing inotify watch: {exc}', exc_info=exc)

        try:
            if not self.stream.closed:
                self.stream.close()
        except Exception as exc:
            logger.error(f'{self.logfile}: Error closing file: {exc}', exc_info=exc)

class FallbackGlobEntry(NamedTuple):
    logfile: str
    reader: Generator[LogEntry|None, None, None]
    stream: TextIO
    is_fifo: bool

    def close(self) -> None:
        try:
            if not self.stream.closed:
                self.stream.close()
        except Exception as exc:
            logger.error(f'{self.logfile}: Error closing file: {exc}', exc_info=exc)

def _logmon_glob(
        logfile: str,
        config: Config,
        limiters: Mapping[str, AbstractLimiter],
) -> None:
    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_for_more = config.get('wait_for_more', DEFAULT_WAIT_FOR_MORE)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    encoding = config.get('encoding', 'UTF-8')
    errors = config.get('encoding_errors', DEFAULT_ENCODING_ERRORS)
    use_inotify = config.get('use_inotify', HAS_INOTIFY)
    seek_end = config.get('seek_end', True)
    compression = config.get('compression')

    reader_factory = EntryReaderFactory.from_config(config)

    parentdir, pattern = splitpath(logfile)
    if not pattern:
        raise ValueError(f'logfile must have directory and pattern: {logfile!r}')

    fnmatch = fncompile(pattern)
    first = True

    with Action.open_actions(config, limiters) as actions:
        poller: epoll|None = None

        def read_entries(entry: IGlobEntry) -> int:
            nonlocal poller
            if entry.is_fifo:
                if poller is None:
                    poller = epoll(2)
                    if stopfd is not None:
                        poller.register(stopfd, POLLIN)

                poller.register(entry.stream.fileno(), POLLIN)

                try:
                    return _read_entries_blocking(entry.logfile, entry.reader, max_entries, actions, poller, stopfd, 0)
                finally:
                    poller.unregister(entry.stream.fileno())
            else:
                return _read_entries(entry.logfile, entry.reader, 0, max_entries, actions)

        def read_all_entries(entry: IGlobEntry) -> None:
            nonlocal poller
            if entry.is_fifo:
                if poller is None:
                    poller = epoll(2)
                    if stopfd is not None:
                        poller.register(stopfd, POLLIN)

                poller.register(entry.stream.fileno(), POLLIN)

                try:
                    while _read_entries_blocking(entry.logfile, entry.reader, max_entries, actions, poller, stopfd, 0) >= max_entries:
                        pass
                finally:
                    poller.unregister(entry.stream.fileno())
            else:
                while _read_entries(entry.logfile, entry.reader, 0, max_entries, actions) >= max_entries:
                    pass

        try:
            stopfd = get_read_stopfd()
            if use_inotify and HAS_INOTIFY:
                inotify = PollInotify(stopfd)
                try:
                    inotify2 = PollInotify(stopfd)
                except:
                    inotify.close()
                    raise

                try:
                    loghandles: dict[str, GlobEntry] = {}
                    dirwatch_id: Optional[int] = None

                    def _open_logfile(inotify: PollInotify, child_logfile: str, seek_end: bool) -> None:
                        nonlocal poller
                        old_entry = loghandles.pop(child_logfile, None)
                        if old_entry is not None:
                            logger.debug(f'{child_logfile}: Closing old entry')
                            read_all_entries(old_entry)
                            old_entry.close(inotify)

                        logger.debug(f'{child_logfile}: New logfile matched!')

                        try:
                            watch_id: Optional[int] = inotify.add_watch(child_logfile, IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY)
                        except FileNotFoundError:
                            pass
                        else:
                            if watch_id is None:
                                logger.error(f"{child_logfile}: Didn't create a watch handle!")
                            else:
                                try:
                                    fp = open_logfile(child_logfile, encoding, seek_end, compression, errors)

                                except FileNotFoundError:
                                    try:
                                        inotify.remove_watch(child_logfile)
                                    except OSError as exc:
                                        if exc.errno == EINVAL:
                                            pass # happens when the file was deleted/moved away
                                        else:
                                            logger.error(f'{child_logfile}: Error while removing inotify watch: {exc}', exc_info=exc)
                                    except Exception as exc:
                                        logger.error(f'{child_logfile}: Error while removing inotify watch: {exc}', exc_info=exc)

                                except Exception as exc:
                                    logger.error(f"{child_logfile}: Error opening logfile: {exc}", exc_info=exc)

                                else:
                                    logfp_stat = os.fstat(fp.fileno())
                                    entry = loghandles[child_logfile] = GlobEntry(
                                        logfile = child_logfile,
                                        watch_id = watch_id,
                                        reader = reader_factory.create_reader(fp),
                                        stream = fp,
                                        is_fifo = S_ISFIFO(logfp_stat.st_mode),
                                    )

                                    read_entries(entry)

                    while is_running():
                        terminal = False
                        try:
                            try:
                                if dirwatch_id is None:
                                    dirwatch_id = inotify.add_watch(parentdir, IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
                            except FileNotFoundError:
                                if inotify2 is not None:
                                    if not inotify_wait_for_exists(inotify2, parentdir):
                                        break
                                else:
                                    sleep(wait_file_not_found)

                                continue # ensure watch is added before anything else happens so we won't miss events
                            else:
                                if first:
                                    first = False

                                    try:
                                        new_paths = set(
                                            normpath(child.path)
                                            for child in scandir(parentdir)
                                            if fnmatch(child.name)
                                        )
                                    except FileNotFoundError:
                                        continue

                                    for added_logfile in new_paths:
                                        _open_logfile(inotify, added_logfile, seek_end)

                                do_wait = True
                                # FIXME: inotify.wait() doesn't fire for fifo?! guess I need to poll the open files.
                                while do_wait and inotify.wait() and is_running():
                                    for event in inotify.read_events():
                                        if not is_running():
                                            break

                                        mask = event.mask

                                        event_path = normpath(event.full_path())

                                        if event_path == parentdir:
                                            if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                                logger.debug(f'{parentdir}: Parent dir went away! Stopping monitoring and waiting for it to reapear')
                                                break

                                        else:
                                            if mask & IN_MODIFY:
                                                entry = loghandles.get(event_path)
                                                if entry is not None:
                                                    read_entries(entry)

                                            if event.filename is not None and fnmatch(event.filename):
                                                if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                                    entry = loghandles.pop(event_path, None)
                                                    if entry is not None:
                                                        logger.debug(f"{entry.logfile}: Logfile went away, stopping monitoring")
                                                        try:
                                                            # just in case try to read any tailing entries
                                                            read_all_entries(entry)
                                                        finally:
                                                            entry.close(inotify)

                                                if mask & (IN_CREATE | IN_MOVED_TO):
                                                    _open_logfile(inotify, event_path, False)

                        except KeyboardInterrupt:
                            handle_keyboard_interrupt()

                        except TerminalEventException:
                            # filesystem unmounted
                            terminal = True

                        finally:
                            if dirwatch_id is not None:
                                try:
                                    inotify.remove_watch(parentdir)
                                except OSError as exc:
                                    if exc.errno == EINVAL:
                                        pass # happens when the file was deleted/moved away
                                    else:
                                        logger.error(f'{parentdir}: Error while removing inotify watch: {exc}', exc_info=exc)
                                except Exception as exc:
                                    logger.error(f'{parentdir}: Error while removing inotify watch: {exc}', exc_info=exc)
                                dirwatch_id = None

                            for entry in loghandles.values():
                                try:
                                    if is_running():
                                        # just in case try to read any tailing entries
                                        read_all_entries(entry)
                                finally:
                                    entry.close(inotify)

                            loghandles.clear()

                            if terminal:
                                try:
                                    inotify.close()
                                except Exception as exc:
                                    logger.error(f'{logfile}: Error closing inotify: {exc}', exc_info=exc)

                                try:
                                    inotify2.close()
                                except Exception as exc:
                                    logger.error(f'{parentdir}: Error closing inotify: {exc}', exc_info=exc)

                                inotify = PollInotify(get_read_stopfd())
                                inotify2 = PollInotify(get_read_stopfd())
                finally:
                    try:
                        inotify.close()
                    finally:
                        inotify2.close()
            else:
                logfiles: set[tuple[int, str]] = set()
                entries: dict[str, FallbackGlobEntry] = {}

                def open_entry(child_logfile: str, seek_end: bool) -> None:
                    old_entry = entries.pop(child_logfile, None)
                    if old_entry is not None:
                        read_all_entries(old_entry)
                        old_entry.close()

                    try:
                        fp = open_logfile(child_logfile, encoding, seek_end, compression, errors)

                    except FileNotFoundError:
                        pass

                    except Exception as exc:
                        logger.error(f"{child_logfile}: Error opening logfile: {exc}", exc_info=exc)

                    else:
                        logfp_stat = os.fstat(fp.fileno())
                        fb_entry = entries[child_logfile] = FallbackGlobEntry(
                            logfile = child_logfile,
                            reader = reader_factory.create_reader(fp),
                            stream = fp,
                            is_fifo = S_ISFIFO(logfp_stat.st_mode),
                        )

                        read_entries(fb_entry)

                first = False
                while is_running():
                    if first:
                        first = False
                    else:
                        seek_end = False

                    try:
                        new_logfiles = set(
                            (child.inode(), normpath(child.path))
                            for child in scandir(parentdir)
                            if fnmatch(child.name)
                        )
                    except FileNotFoundError:
                        sleep(wait_file_not_found)
                        continue

                    added_logfiles = new_logfiles - logfiles
                    removed_logfiles = logfiles - new_logfiles

                    for _, removed_logfile in removed_logfiles:
                        maybe_entry = entries.pop(removed_logfile, None)
                        if maybe_entry is not None:
                            read_all_entries(maybe_entry)

                    for _, added_logfile in added_logfiles:
                        open_entry(added_logfile, seek_end)

                    entry_count = 0
                    for fb_entry in entries.values():
                        if not is_running():
                            break

                        entry_count += read_entries(fb_entry)

                    if not is_running():
                        break

                    if entry_count == 0:
                        sleep(wait_no_entries)

                    logfiles = new_logfiles
        finally:
            if poller is not None:
                poller.close()

def logmon_mt(config: MTConfig):
    action_config = config.get('do') or {}
    default_config = config.get('default') or {}

    logfiles = config.get('logfiles')

    if not logfiles:
        raise ValueError('no logfiles given')

    limiters = build_limiters(config)

    threads: list[threading.Thread] = []

    try:
        items: Iterable[tuple[str, Config]]

        if isinstance(logfiles, dict):
            items = logfiles.items()
        else:
            items = [(logfile, { 'do': [action_config] }) for logfile in logfiles]

        for logfile, cfg in items:
            cfg = resolve_config(default_config, action_config, cfg)

            thread = threading.Thread(
                target = _logmon_thread,
                args = (logfile, cfg, limiters),
                name = logfile,
            )

            thread.start()
            threads.append(thread)

    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    for thread in threads:
        try:
            thread.join()
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
        except Exception as exc:
            logger.error(f"{thread.name}: Error waiting for thread: {exc}", exc_info=exc)

def _logmon_thread(logfile: str, config: Config, limiters: Mapping[str, AbstractLimiter]) -> None:
    logfile = normpath(abspath(logfile)) if not is_systemd_path(logfile) else logfile
    wait_after_crash = config.get('wait_after_crash', DEFAULT_WAIT_AFTER_CRASH)

    while is_running():
        try:
            _logmon(
                logfile = logfile,
                config = config,
                limiters = limiters,
            )
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
            break
        except Exception as exc:
            logger.error(f"{logfile}: Restarting after crash: {exc}", exc_info=exc)
            logger.debug(f"{logfile}: Waiting for {wait_after_crash} seconds after crash")
            sleep(wait_after_crash)
        else:
            break

def _read_entries_blocking(
        logfile: str,
        reader: Generator[LogEntry|None, None, None],
        max_entries: int,
        actions: list[Action],
        poller: epoll,
        stopfd: int|None,
        timeout: int|None,
) -> int:
    entries: list[LogEntry] = []
    try:
        while is_running():
            events = poller.poll(timeout)
            if not events or any(fd == stopfd for fd, _event in events):
                break
            timeout = 0

            try:
                entry = next(reader)
            except StopIteration:
                break

            if entry is None:
                break

            entries.append(entry)

            if len(entries) >= max_entries:
                break

    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    except OSError as exc:
        logger.error(f'{logfile}: Error reading log entries: {exc}', exc_info=exc)

    for offset in range(0, len(entries), max_entries):
        try:
            chunk = entries[offset:offset + max_entries]
            brief = chunk[0].brief

            for action in actions:
                if action.perform_action(
                    logfile = logfile,
                    entries = chunk,
                    brief = brief,
                ):
                    pass
                elif logger.isEnabledFor(logging.DEBUG):
                    templ_params = action.get_templ_params(logfile, chunk, brief)
                    subject = action.subject_templ.format_map(templ_params)

                    logger.debug(f'{logfile}: Action with {len(chunk)} entries was rate limited: {subject}')

        except Exception as exc:
            logger.error(f'{logfile}: Error performing action: {exc}', exc_info=exc)

    return len(entries)

def _read_entries(
        logfile: str,
        reader: Generator[LogEntry|None, None, None],
        wait_for_more: float,
        max_entries: int,
        actions: list[Action],
        wait_on_empty_messages: bool = True,
) -> int:
    start_ts = monotonic()
    entries: list[LogEntry] = []
    try:
        for entry in reader:
            if entry is None:
                duration = monotonic() - start_ts
                if duration >= wait_for_more:
                    break

                if not entries and not wait_on_empty_messages:
                    return 0

                rem_time = wait_for_more - duration
                logger.debug(f'{logfile}: Waiting for {rem_time} seconds to gather more messages')
                sleep(rem_time)
                continue

            entries.append(entry)

            if len(entries) >= max_entries:
                break

    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    except OSError as exc:
        logger.error(f'{logfile}: Error reading log entries: {exc}', exc_info=exc)

    for offset in range(0, len(entries), max_entries):
        try:
            chunk = entries[offset:offset + max_entries]
            brief = chunk[0].brief

            for action in actions:
                if action.perform_action(
                    logfile = logfile,
                    entries = chunk,
                    brief = brief,
                ):
                    pass
                elif logger.isEnabledFor(logging.DEBUG):
                    templ_params = action.get_templ_params(logfile, chunk, brief)
                    subject = action.subject_templ.format_map(templ_params)

                    logger.debug(f'{logfile}: Action with {len(chunk)} entries was rate limited: {subject}')

        except Exception as exc:
            logger.error(f'{logfile}: Error performing action: {exc}', exc_info=exc)

    return len(entries)
