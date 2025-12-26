import os
import logging
import threading

from os.path import abspath, normpath, dirname, join as joinpath
from time import monotonic, sleep
from select import poll, POLLIN

from .schema import Config, MTConfig
from .limits_service import LimitsService
from .systemd import is_systemd_path, logmon_systemd
from .constants import *
from .entry_readers import EntryReaderFactory, LogEntry
from .email_senders import EmailSender
from .inotify import HAS_INOTIFY, Inotify, InotifyError, TerminalEventException, IN_MODIFY, IN_DELETE, IN_MOVE_SELF, IN_MOVED_FROM, IN_MOVED_TO, inotify_wait_for_exists
from .global_state import is_running, handle_keyboard_interrupt, open_stopfds, close_stopfds, get_read_stopfd

logger = logging.getLogger(__name__)

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

    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)

    reader_factory = EntryReaderFactory.from_config(config)

    with EmailSender.from_config(config) as email_sender:
        seek_end = config.get('seek_end', True)
        use_inotify = config.get('use_inotify', HAS_INOTIFY)

        parentdir = dirname(logfile)
        if use_inotify and HAS_INOTIFY:
            inotify = Inotify()
        else:
            inotify = None

        try:
            file_not_found = False

            while is_running():
                try:
                    logfp = open(logfile, 'r')
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
                                try:
                                    if limits.check():
                                        email_sender.send_email(
                                            logfile = logfile,
                                            entries = entries,
                                            brief = entries[0].brief,
                                        )
                                    elif logger.isEnabledFor(logging.DEBUG):
                                        brief = entries[0].brief
                                        templ_params = email_sender.get_templ_params(logfile, entries, brief)
                                        subject = email_sender.subject_templ.format_map(templ_params)

                                        logger.debug(f'{logfile}: Email with {len(entries)} entries was rate limited: {subject}')

                                except Exception as exc:
                                    logger.error(f'{logfile}: Error sending email: {exc}', exc_info=exc)

                            if len(entries) < max_entries and is_running():
                                # If there are max_entries that means there are probably already more in the
                                # log file, so try to read those before waiting via inotify.
                                do_reopen = False
                                if inotify is not None:
                                    logger.debug(f'{logfile}: Waiting with inotify for modifications')
                                    try:
                                        inotify.add_watch(logfile, IN_MODIFY | IN_MOVE_SELF)
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

                                                _, type_names, event_path, event_filename = event
                                                if normpath(joinpath(event_path, event_filename)) == logfile:
                                                    if 'IN_MODIFY' in type_names:
                                                        break

                                                    if 'IN_MOVE_SELF' in type_names:
                                                        do_reopen = True
                                                        # this never fires because we have logfp open
                                                        break

                                                    if 'IN_MOVED_FROM' in type_names:
                                                        do_reopen = True
                                                        deleted = True
                                                        break

                                                    if 'IN_MOVED_TO' in type_names:
                                                        do_reopen = True
                                                        deleted = True
                                                        break

                                                    if 'IN_DELETE' in type_names or 'IN_DELETE_SELF' in type_names:
                                                        do_reopen = True
                                                        deleted = True
                                                        break

                                        if not is_running():
                                            break

                                    except TerminalEventException as exc:
                                        # filesystem unmounted
                                        do_reopen = True
                                        deleted = True

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

def logmon_mt(config: MTConfig):
    email_config = config.get('email')
    base_config = dict(email_config)

    default = config.get('default')
    if default:
        base_config.update(default)

    logfiles = config.get('logfiles')

    if not logfiles:
        raise ValueError('no logfiles given')

    limits = LimitsService.from_config(config.get('limits') or {})

    threads: list[threading.Thread] = []

    try:
        items = logfiles.items() if isinstance(logfiles, dict) else [(logfile, {}) for logfile in logfiles]
        open_stopfds()

        for logfile, cfg in items:
            cfg = {
                **base_config,
                **cfg
            }

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
