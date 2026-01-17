from typing import Iterable, Generator, Callable, Match, Optional, NamedTuple, TextIO

import re
import os
import logging
import threading

from os import scandir
from os.path import abspath, normpath, dirname, join as joinpath, split as splitpath
from time import monotonic, sleep
from select import poll, POLLIN
from fnmatch import translate
from errno import ENOENT

from .schema import Config, MTConfig, resolve_config
from .limits_service import LimitsService
from .systemd import is_systemd_path, logmon_systemd
from .constants import *
from .entry_readers import EntryReaderFactory, LogEntry
from .actions import Action
from .inotify import HAS_INOTIFY, Inotify, InotifyError, TerminalEventException, IN_MODIFY, IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF, IN_MOVED_FROM, IN_MOVED_TO, inotify_wait_for_exists
from .global_state import is_running, handle_keyboard_interrupt, open_stopfds, close_stopfds, get_read_stopfd

logger = logging.getLogger(__name__)

def fncompile(pattern: str) -> Callable[[str], Match|None]:
    return re.compile(translate(pattern)).match

def logmon(logfile: str, config: Config) -> None:
    logfile = normpath(abspath(logfile))
    limits = LimitsService.from_config(config)
    _logmon(logfile, config, limits)

def _logmon(
        logfile: str,
        config: Config,
        limits: LimitsService,
) -> None:
    if is_systemd_path(logfile):
        return logmon_systemd(logfile, config, limits)

    if config.get('glob'):
        return _logmon_glob(logfile, config, limits)

    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    encoding = config.get('encoding', 'UTF-8')
    seek_end = config.get('seek_end', True)
    use_inotify = config.get('use_inotify', HAS_INOTIFY)

    reader_factory = EntryReaderFactory.from_config(config)

    with Action.open_actions(config) as actions:
        if use_inotify and HAS_INOTIFY:
            inotify = Inotify()
        else:
            inotify = None

        file_not_found = False
        terminated = False
        logfile_id: Optional[int] = None

        while is_running():
            try:
                logfp = open(logfile, 'r', encoding=encoding)
                if file_not_found:
                    file_not_found = False
                    logger.debug(f"{logfile}: File appeared!")
                try:
                    logfp_stat = os.fstat(logfp.fileno())
                    logfp_ref = (logfp_stat.st_dev, logfp_stat.st_ino)
                    if seek_end:
                        logfp.seek(0, os.SEEK_END)

                    reader = reader_factory.create_reader(logfp)

                    if inotify is not None:
                        terminated = False
                        try:
                            logfile_id = inotify.add_watch(logfile, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)
                        except InotifyError as exc:
                            if exc.errno == ENOENT:
                                raise FileNotFoundError(ENOENT, 'No such file or directory', logfile) from exc
                            raise

                    while is_running():
                        entry_count = _read_entries(logfile, reader, wait_before_send, max_entries, actions, limits)

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
                                        stopfd = get_read_stopfd()
                                        if stopfd is not None:
                                            poller = poll()
                                            poller.register(stopfd, POLLIN)
                                            # why is there no official way to get that file discriptor!?
                                            poller.register(inotify._Inotify__inotify_fd, POLLIN) # type: ignore
                                            pevents = poller.poll()
                                            if not pevents:
                                                break

                                            if any(fd == stopfd for fd, _pevent in pevents):
                                                break

                                        for event in inotify.event_gen():
                                            if not is_running():
                                                break

                                            if event is None:
                                                continue

                                            header, type_names, event_path, event_filename = event
                                            mask = header.mask
                                            inotify_path = normpath(joinpath(event_path, event_filename))
                                            if inotify_path == logfile:
                                                if IN_MODIFY & mask:
                                                    break

                                                if IN_MOVE_SELF & mask:
                                                    do_reopen = True
                                                    # this never fires because we have logfp open
                                                    break

                                                if IN_MOVED_FROM & mask:
                                                    do_reopen = True
                                                    break

                                                if IN_MOVED_TO & mask:
                                                    do_reopen = True
                                                    break

                                                if (IN_DELETE | IN_DELETE_SELF) & mask:
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
                                logger.info(f"{logfile}: File changed, reopening...")
                                try: logfp.close()
                                except: pass
                                seek_end = False
                                config['seek_end'] = False
                                break

                finally:
                    try:
                        if inotify is not None:
                            if logfile_id is not None:
                                try:
                                    inotify.remove_watch(logfile)
                                except Exception as exc:
                                    logger.error(f'{logfile}: Error while removing inotify watch: {exc}', exc_info=exc)
                                logfile_id = None

                            if terminated:
                                inotify = Inotify()
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
class GlobEntry(NamedTuple):
    logfile: str
    watch_id: int
    reader: Generator[LogEntry|None, None, None]
    stream: TextIO

    def close(self, inotify: Inotify) -> None:
        try:
            inotify.remove_watch(self.logfile)
        except Exception as exc:
            logger.error(f'{self.logfile}: Error while removing inotify watch: {exc}', exc_info=exc)

        try:
            if not self.stream.closed:
                self.stream.close()
        except Exception as exc:
            logger.error(f'{self.logfile}: Error closing file: {exc}', exc_info=exc)

def _logmon_glob(
        logfile: str,
        config: Config,
        limits: LimitsService,
) -> None:
    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    encoding = config.get('encoding', 'UTF-8')
    use_inotify = config.get('use_inotify', HAS_INOTIFY)
    seek_end = config.get('seek_end', True)

    reader_factory = EntryReaderFactory.from_config(config)

    parentdir, pattern = splitpath(logfile)
    if not pattern:
        raise ValueError(f'logfile must have directory and pattern: {logfile!r}')

    fnmatch = fncompile(pattern)
    first = True

    with Action.open_actions(config) as actions:
        if use_inotify and HAS_INOTIFY:
            inotify = Inotify()
            inotify2 = Inotify()
            event_gen = None
            loghandles: dict[str, GlobEntry] = {}
            dirwatch_id: Optional[int] = None

            def open_logfile(inotify: Inotify, child_logfile: str, seek_end: bool) -> None:
                old_entry = loghandles.pop(child_logfile, None)
                if old_entry is not None:
                    logger.debug(f'{child_logfile}: Closing old entry')
                    _read_entries(child_logfile, old_entry.reader, 0, max_entries, actions, limits)
                    old_entry.close(inotify)

                logger.debug(f'{child_logfile}: New logfile matched!')

                try:
                    watch_id: Optional[int] = inotify.add_watch(child_logfile, IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY)
                except InotifyError as exc:
                    if exc.errno != ENOENT:
                        raise
                else:
                    if watch_id is None:
                        logger.error(f"{child_logfile}: Didn't create a watch handle!")
                    else:
                        try:
                            fp = open(child_logfile, 'r', encoding=encoding)

                            if seek_end:
                                fp.seek(0, os.SEEK_END)

                        except FileNotFoundError:
                            inotify.remove_watch(child_logfile)

                        except Exception as exc:
                            logger.error(f"{child_logfile}: Error opening logfile: {exc}", exc_info=exc)
                        else:
                            entry = loghandles[child_logfile] = GlobEntry(
                                logfile = child_logfile,
                                watch_id = watch_id,
                                reader = reader_factory.create_reader(fp),
                                stream = fp,
                            )

                            _read_entries(child_logfile, entry.reader, wait_before_send, max_entries, actions, limits)

            while is_running():
                terminal = False
                try:
                    try:
                        if dirwatch_id is None:
                            dirwatch_id = inotify.add_watch(parentdir, IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
                    except InotifyError as exc:
                        if exc.errno != ENOENT:
                            raise

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
                                added_logfiles = set(
                                    normpath(child.path)
                                    for child in scandir(parentdir)
                                    if fnmatch(child.name)
                                )
                            except FileNotFoundError:
                                continue

                            for added_logfile in added_logfiles:
                                open_logfile(inotify, added_logfile, seek_end)

                        stopfd = get_read_stopfd()
                        if stopfd is not None:
                            poller = poll()
                            poller.register(stopfd, POLLIN)
                            # why is there no official way to get that file discriptor!?
                            poller.register(inotify._Inotify__inotify_fd, POLLIN) # type: ignore
                            pevents = poller.poll()
                            if not pevents:
                                break

                            if any(fd == stopfd for fd, _pevent in pevents):
                                break

                        if event_gen is None:
                            event_gen = inotify.event_gen()

                        for event in event_gen:
                            if not is_running():
                                break

                            if event is None:
                                continue

                            header, type_names, event_dir, event_filename = event
                            mask = header.mask

                            #logger.debug(f'{event_filename}: {', '.join(type_names)}')
                            event_path = normpath(joinpath(event_dir, event_filename))

                            if event_path == parentdir:
                                if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                    logger.debug(f'{parentdir}: Parent dir went away! Stopping monitoring and waiting for it to reapear')
                                    break

                            else:
                                if mask & IN_MODIFY:
                                    entry = loghandles.get(event_path)
                                    if entry is not None:
                                        _read_entries(entry.logfile, entry.reader, wait_before_send, max_entries, actions, limits)

                                if fnmatch(event_filename):
                                    if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                        entry = loghandles.pop(event_path, None)
                                        if entry is not None:
                                            logger.debug(f"{entry.logfile}: Logfile went away, stopping monitoring")
                                            try:
                                                # just in case try to read any tailing entries
                                                _read_entries(entry.logfile, entry.reader, (wait_before_send if mask & IN_DELETE_SELF else 0), max_entries, actions, limits)
                                            finally:
                                                entry.close(inotify)

                                    if mask & (IN_CREATE | IN_MOVED_TO):
                                        open_logfile(inotify, event_path, False)

                except KeyboardInterrupt:
                    handle_keyboard_interrupt()

                except TerminalEventException:
                    # filesystem unmounted
                    terminal = True

                finally:
                    if dirwatch_id is not None:
                        try:
                            inotify.remove_watch(parentdir)
                        except Exception as exc:
                            logger.error(f'{parentdir}: Error while removing inotify watch: {exc}', exc_info=exc)
                        dirwatch_id = None

                    for entry in loghandles.values():
                        try:
                            if is_running():
                                # just in case try to read any tailing entries
                                _read_entries(entry.logfile, entry.reader, 0, max_entries, actions, limits)
                        finally:
                            entry.close(inotify)

                    loghandles.clear()

                    if terminal:
                        event_gen = None
                        inotify = Inotify()
                        inotify2 = Inotify()
        else:
            # TODO: no inotify fallback!
            raise NotImplementedError('no non-inotify fallback')

def logmon_mt(config: MTConfig):
    action_config = config.get('do') or {}
    default_config = config.get('default') or {}

    logfiles = config.get('logfiles')

    if not logfiles:
        raise ValueError('no logfiles given')

    limits = LimitsService.from_config(config.get('limits') or {})

    threads: list[threading.Thread] = []

    try:
        items: Iterable[tuple[str, Config]]

        if isinstance(logfiles, dict):
            items = logfiles.items()
        else:
            items = [(logfile, { 'do': [action_config] }) for logfile in logfiles]

        open_stopfds()

        for logfile, cfg in items:
            cfg = resolve_config(default_config, action_config, cfg)

            thread = threading.Thread(
                target = _logmon_thread,
                args = (logfile, cfg, limits),
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

    close_stopfds()

def _logmon_thread(logfile: str, config: Config, limits: LimitsService) -> None:
    logfile = normpath(abspath(logfile)) if not is_systemd_path(logfile) else logfile
    wait_after_crash = config.get('wait_after_crash', DEFAULT_WAIT_AFTER_CRASH)

    while is_running():
        try:
            _logmon(
                logfile = logfile,
                config = config,
                limits = limits,
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

def _read_entries(
        logfile: str,
        reader: Generator[LogEntry|None, None, None],
        wait_before_send: float|int,
        max_entries: int,
        actions: list[Action],
        limits: LimitsService,
) -> int:
    start_ts = monotonic()
    entries: list[LogEntry] = []
    try:
        for entry in reader:
            if entry is None:
                duration = monotonic() - start_ts
                if duration >= wait_before_send:
                    break
                rem_time = wait_before_send - duration
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
                if limits.check():
                    action.perform_action(
                        logfile = logfile,
                        entries = chunk,
                        brief = brief,
                    )
                elif logger.isEnabledFor(logging.DEBUG):
                    templ_params = action.get_templ_params(logfile, chunk, brief)
                    subject = action.subject_templ.format_map(templ_params)

                    logger.debug(f'{logfile}: Action with {len(chunk)} entries was rate limited: {subject}')

        except Exception as exc:
            logger.error(f'{logfile}: Error performing action: {exc}', exc_info=exc)

    return len(entries)
