from typing import Iterable, Generator, Callable, Match

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
        parentdir = dirname(logfile)
        if use_inotify and HAS_INOTIFY:
            inotify = Inotify()
        else:
            inotify = None

        try:
            file_not_found = False

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

                        while is_running():
                            entries = _read_entries(logfile, reader, wait_before_send, max_entries, actions, limits)

                            if len(entries) < max_entries and is_running():
                                # If there are max_entries that means there are probably already more in the
                                # log file, so try to read those before waiting via inotify.
                                do_reopen = False
                                if inotify is not None:
                                    logger.debug(f'{logfile}: Waiting with inotify for modifications')
                                    try:
                                        inotify.add_watch(logfile, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)
                                    except InotifyError:
                                        if not os.path.exists(logfile):
                                            raise FileNotFoundError
                                        raise

                                    try:
                                        inotify.add_watch(parentdir, IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)
                                    except InotifyError:
                                        if not os.path.exists(parentdir):
                                            raise FileNotFoundError
                                        raise
                                    except:
                                        try: inotify.remove_watch(logfile)
                                        except: pass

                                    deleted = False
                                    terminated = False
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
                                                        deleted = True
                                                        break

                                                    if IN_MOVED_TO & mask:
                                                        do_reopen = True
                                                        deleted = True
                                                        break

                                                    if (IN_DELETE | IN_DELETE_SELF) & mask:
                                                        do_reopen = True
                                                        deleted = True
                                                        break

                                        if not is_running():
                                            break

                                    except TerminalEventException:
                                        # filesystem unmounted
                                        do_reopen = True
                                        deleted = True
                                        terminated = True

                                    finally:
                                        try:
                                            if not deleted:
                                                inotify.remove_watch(logfile)
                                        except Exception as exc:
                                            logger.error(f'{logfile}: Error while removing inotify watch: {exc}', exc_info=exc)

                                        try:
                                            inotify.remove_watch(parentdir)
                                        except Exception as exc:
                                            logger.error(f'{parentdir}: Error while removing inotify watch: {exc}', exc_info=exc)

                                        if terminated:
                                            inotify = Inotify()
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
            if inotify is not None:
                try: inotify.remove_watch(logfile)
                except: pass

                try: inotify.remove_watch(parentdir)
                except: pass

def _logmon_file_if_exists(
        logfile: str,
        config: Config,
        limits: LimitsService,
        seek_end: bool,
) -> None:
    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    encoding = config.get('encoding', 'UTF-8')
    use_inotify = config.get('use_inotify', HAS_INOTIFY)

    reader_factory = EntryReaderFactory.from_config(config)

    with Action.open_actions(config) as actions:
        parentdir = dirname(logfile)
        if use_inotify and HAS_INOTIFY:
            inotify = Inotify()
        else:
            inotify = None

        try:
            try:
                logfp = open(logfile, 'r', encoding=encoding)

                try:
                    logfp_stat = os.fstat(logfp.fileno())
                    logfp_ref = (logfp_stat.st_dev, logfp_stat.st_ino)
                    if seek_end:
                        logfp.seek(0, os.SEEK_END)

                    reader = reader_factory.create_reader(logfp)

                    while is_running():
                        entries = _read_entries(logfile, reader, wait_before_send, max_entries, actions, limits)

                        if len(entries) < max_entries and is_running():
                            # If there are max_entries that means there are probably already more in the
                            # log file, so try to read those before waiting via inotify.
                            if inotify is not None:
                                logger.debug(f'{logfile}: Waiting with inotify for modifications')
                                try:
                                    inotify.add_watch(logfile, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)
                                except InotifyError:
                                    if not os.path.exists(logfile):
                                        return
                                    raise

                                try:
                                    inotify.add_watch(parentdir, IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
                                except InotifyError:
                                    if not os.path.exists(parentdir):
                                        return
                                    raise
                                except:
                                    try: inotify.remove_watch(logfile)
                                    except: pass

                                deleted = False
                                try:
                                    new_stat = os.stat(logfile)
                                    new_ref = (new_stat.st_dev, new_stat.st_ino)
                                    if logfp_ref != new_ref:
                                        # verify we're actually waiting on the file that is opened
                                        return
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
                                            event_path = normpath(joinpath(event_path, event_filename))
                                            if event_path == logfile:
                                                if IN_MODIFY & mask:
                                                    break

                                                if (IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_DELETE_SELF) & mask:
                                                    return

                                            elif event_path == parentdir:
                                                if (IN_MOVE_SELF | IN_DELETE_SELF) & mask:
                                                    return

                                    if not is_running():
                                        break

                                except TerminalEventException:
                                    # filesystem unmounted
                                    return

                                finally:
                                    try:
                                        if not deleted:
                                            inotify.remove_watch(logfile)
                                    except Exception as exc:
                                        logger.error(f'{logfile}: Error while removing inotify watch: {exc}', exc_info=exc)

                                    try:
                                        inotify.remove_watch(parentdir)
                                    except Exception as exc:
                                        logger.error(f'{parentdir}: Error while removing inotify watch: {exc}', exc_info=exc)
                            else:
                                logger.debug(f'{logfile}: Sleeping for {wait_no_entries} seconds for modifications')
                                sleep(wait_no_entries)

                                try:
                                    new_stat = os.stat(logfile)
                                except FileNotFoundError:
                                    return
                                else:
                                    new_ref = (new_stat.st_dev, new_stat.st_ino)
                                    if logfp_ref != new_ref:
                                        # inode changed!
                                        return
                finally:
                    if not logfp.closed:
                        try: logfp.close()
                        except: pass

            except FileNotFoundError:
                return

        finally:
            if inotify is not None:
                try: inotify.remove_watch(logfile)
                except: pass

                try: inotify.remove_watch(parentdir)
                except: pass

def _logmon_glob(
        logfile: str,
        config: Config,
        limits: LimitsService,
) -> None:
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    use_inotify = config.get('use_inotify', HAS_INOTIFY)
    seek_end = config.get('seek_end', True)

    parentdir, pattern = splitpath(logfile)
    if not pattern:
        raise ValueError(f'logfile must have directory and pattern: {logfile!r}')

    fnmatch = fncompile(pattern)

    if use_inotify and HAS_INOTIFY:
        inotify = Inotify()
        inotify2 = Inotify()
    else:
        inotify = None
        inotify2 = None

    threads: dict[str, threading.Thread] = {}
    logfiles: set[tuple[int, str]] = set()
    watching = False
    first = True

    try:
        while is_running():
            if inotify is not None:
                try:
                    try:
                        if not watching:
                            inotify.add_watch(parentdir, IN_DELETE | IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
                    except InotifyError as exc:
                        if exc.errno != ENOENT:
                            raise

                        if inotify2 is not None:
                            if not inotify_wait_for_exists(inotify2, parentdir):
                                break

                            continue # ensure watch is added before anything else happens so we won't miss events
                        else:
                            sleep(wait_file_not_found)
                    else:
                        watching = True

                        if first:
                            first = False
                        else:
                            seek_end = False
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

                                mask = event[0].mask

                                if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                    try: inotify.remove_watch(parentdir)
                                    except: pass
                                    watching = False
                                    break

                                break

                except TerminalEventException:
                    # unmount
                    if watching:
                        try: inotify.remove_watch(parentdir)
                        except: pass

                    inotify = Inotify()
                    inotify2 = Inotify()

            else:
                if first:
                    first = False
                else:
                    seek_end = False
                    sleep(wait_file_not_found)

            try:
                new_logfiles = set(
                    (child.inode(), normpath(child.path))
                    for child in scandir(parentdir)
                    if fnmatch(child.name)
                )
            except FileNotFoundError:
                if inotify is not None and watching:
                    try: inotify.remove_watch(parentdir)
                    except: pass
                    watching = False
                new_logfiles = set()

            added_logfiles = new_logfiles - logfiles
            removed_logfiles = logfiles - new_logfiles

            for removed_inode, removed_logfile in removed_logfiles:
                logger.info(f"{removed_logfile}: Logfile went away, stopping monitoring")

                thread = threads.pop(removed_logfile, None)

                if thread is not None:
                    try:
                        thread.join()
                    except KeyboardInterrupt:
                        handle_keyboard_interrupt()
                    except Exception as exc:
                        logger.error(f"{thread.name}: Error waiting for thread: {exc}", exc_info=exc)

            for added_inode, added_logfile in added_logfiles:
                logger.info(f"{added_logfile}: New matched logfile")

                thread = threading.Thread(
                    target = _logmon_file_if_exists,
                    args = (added_logfile, config, limits, seek_end),
                    name = added_logfile,
                )

                thread.start()
                threads[added_logfile] = thread

            logfiles = new_logfiles

    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    finally:
        if inotify is not None:
            try: inotify.remove_watch(parentdir)
            except: pass

        for thread in threads.values():
            try:
                thread.join()
            except KeyboardInterrupt:
                handle_keyboard_interrupt()
            except Exception as exc:
                logger.error(f"{thread.name}: Error waiting for thread: {exc}", exc_info=exc)

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

def _read_entries(logfile: str, reader: Generator[LogEntry|None, None, None], wait_before_send: float|int, max_entries: int, actions: list[Action], limits: LimitsService) -> list[LogEntry]:
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

    if entries:
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

    return entries
