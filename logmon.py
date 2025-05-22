#!/usr/bin/env python3

# a very simple log monitor

from typing import Callable, Generator, TextIO, Pattern, Optional, TypedDict, NotRequired, Literal
from time import sleep, monotonic
from email.message import EmailMessage
from email.policy import SMTP
from math import inf
from os.path import dirname, abspath, join as joinpath, normpath

import re
import os
import sys
import ssl
import smtplib
import imaplib
import logging
import threading
import pydantic

__version__ = '0.1.0'

try:
    from inotify.adapters import Inotify, TerminalEventException
    from inotify.constants import IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_MOVE_SELF
    from inotify.calls import InotifyError

    def _inotify_wait_for_exists(inotify: Inotify, path: str) -> bool: # type: ignore
        path = normpath(path)
        dirpath = dirname(path)
        while _running:
            try:
                inotify.add_watch(dirpath, IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
            except InotifyError:
                if not os.path.exists(dirpath):
                    parentdir = dirname(dirpath)
                    if parentdir == dirpath:
                        raise Exception(f'Root dir ({dirpath}) does not exist?')
                    _inotify_wait_for_exists(inotify, parentdir)
                    continue
                raise
            except FileNotFoundError:
                parentdir = dirname(dirpath)
                if parentdir == dirpath:
                    raise Exception(f'Root dir ({dirpath}) does not exist?')
                _inotify_wait_for_exists(inotify, parentdir)
                continue
            else:
                deleted = False
                try:
                    if os.path.exists(path):
                        return True

                    for event in inotify.event_gen():
                        if not _running:
                            return False

                        if event is None:
                            continue

                        _, type_names, event_path, event_filename = event
                        if normpath(joinpath(event_path, event_filename)) == path:
                            if 'IN_CREATE' in type_names or 'IN_MOVED_TO' in type_names:
                                return True

                        elif normpath(event_path) == dirpath:
                            if 'IN_DELETE_SELF' in type_names or 'IN_MOVE_SELF' in type_names:
                                # continue outer loop
                                deleted = True
                                break

                except TerminalEventException as exc:
                    # filesystem unmounted
                    logger.debug(f'{path}: Retrying because of: {exc}')
                    continue

                finally:
                    try:
                        if not deleted:
                            inotify.remove_watch(dirpath)
                    except Exception as exc:
                        logger.error(f'{dirpath}: Error while removing inotify watch: {exc}', exc_info=exc)
        return False

except ImportError:
    Inotify = None

    # to appease the type checker:
    InotifyError = Exception
    TerminalEventException = Exception
    IN_MODIFY = 2
    IN_MOVED_FROM = 64
    IN_MOVED_TO = 128
    IN_CREATE = 256
    IN_DELETE = 512
    IN_MOVE_SELF = 2048

    def _inotify_wait_for_exists(inotify, path: str) -> bool:
        raise Exception('needs inotify')

logger = logging.getLogger(__name__)

SecureOption = Literal[None, 'STARTTLS', 'SSL/TLS']
EmailProtocol = Literal['SMTP', 'IMAP']

DEFAULT_EMAIL_HOST = 'localhost'
DEFAULT_EMAIL_PORT: dict[EmailProtocol, int] = {
    'SMTP': 587, # or 25 for insecure
    'IMAP': 143,
}
DEFAULT_EMAIL_PROTOCOL = 'SMTP'

DEFAULT_SUBJECT = '[ERROR] {line1}'
DEFAULT_BODY = '{logfile}\n\n{entries}'
DEFAULT_WAIT_FILE_NOT_FOUND = 30
DEFAULT_WAIT_LINE_INCOMPLETE = 0.1
DEFAULT_WAIT_NO_ENTRIES = 5
DEFAULT_WAIT_BEFORE_SEND = 1
DEFAULT_WAIT_AFTER_CRASH = 10
DEFAULT_MAX_ENTRIES = 20
DEFAULT_MAX_EMAILS_PER_MINUTE = 6
DEFAULT_MAX_EMAILS_PER_HOUR = 60
DEFAULT_MAX_ENTRY_LINES = 2048
DEFAULT_LOG_FORMAT = '[%(asctime)s] [%(process)d] %(levelname)s: %(message)s'
DEFAULT_LOG_DATEFMT = '%Y-%m-%dT%H:%M:%S%z'

DEFAULT_ENTRY_START_PATTERN = re.compile(r'^\[\d\d\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?: ?(?:[-+]\d\d:?\d\d|Z))?\]')
DEFAULT_WARNING_PATTERN = re.compile(r'WARNING', re.I)
DEFAULT_ERROR_PATTERN = re.compile(r'ERROR|CRITICAL|Exception', re.I)

ROOT_CONFIG_PATH = '/etc/logmonrc'

Num = int|float
def in_range(parse: Callable[[str], Num], min: Optional[Num] = None, max: Optional[Num] = None) -> Callable[[str], Num]:
    def parse_in_range(value: str) -> Num:
        num = parse(value)
        if min is not None and num < min:
            raise ValueError(f'value may not be less than {min} but was {num}')
        if max is not None and num > max:
            raise ValueError(f'value may not be greater than {max} but was {num}')
        return num
    parse_in_range.__name__ = f'{parse.__name__}_between_{min}_and_{max}'
    return parse_in_range

def non_negative(parse: Callable[[str], Num]) -> Callable[[str], Num]:
    min: Num = 0
    return in_range(parse, min=min)

def positive(parse: Callable[[str], Num]) -> Callable[[str], Num]:
    def parse_positive(value: str) -> Num:
        num = parse(value)
        if num <= 0:
            raise ValueError(f'value needs to be greater than 0 but was {num}')
        return num
    parse_positive.__name__ = f'positive_{parse.__name__}'
    return parse_positive

def remove_smaller(items: list[float], cutoff: float) -> None:
    index = 0
    while index < len(items):
        start_index = index
        while index < len(items):
            item = items[index]
            if item >= cutoff:
                break
            index += 1
        end_index = index
        if start_index != end_index:
            del items[start_index:end_index]
            index = start_index
        else:
            index += 1

def _parse_comma_list(value: str) -> list[str]:
    result: list[str] = []
    for item in value.split(','):
        item = item.strip()
        if item:
            result.append(item)
    return result

class EMailConfig(TypedDict):
    sender: str
    receivers: list[str]
    subject: NotRequired[str]
    body: NotRequired[str]
    host: NotRequired[str]
    port: NotRequired[int]
    user: NotRequired[str]
    password: NotRequired[str]
    secure: NotRequired[SecureOption]
    protocol: NotRequired[EmailProtocol]
    logmails: NotRequired[bool] # if True write emails to log instead

class LogfileConfig(TypedDict):
    entry_start_pattern: NotRequired[str | list[str]]
    error_pattern: NotRequired[str | list[str]]
    #warning_pattern: NotRequired[str|list[str]]
    ignore_pattern: NotRequired[str | list[str] | None]
    wait_line_incomplete: NotRequired[int | float]
    wait_file_not_found: NotRequired[int | float]
    wait_no_entries: NotRequired[int | float]
    wait_before_send: NotRequired[int | float]
    wait_after_crash: NotRequired[int | float]
    max_entries: NotRequired[int]
    max_entry_lines: NotRequired[int]
    max_emails_per_minute: NotRequired[int]
    max_emails_per_hour: NotRequired[int]
    use_inotify: NotRequired[bool]
    seek_end: NotRequired[bool] # default: True

class Config(EMailConfig, LogfileConfig):
    pass

class MTConfig(TypedDict):
    email: EMailConfig
    default: NotRequired[LogfileConfig]
    logfiles: dict[str, LogfileConfig]|list[str]

class AppLogConfig(TypedDict):
    """
    Configuration of this apps own logging.
    """
    file: NotRequired[str]
    level: NotRequired[str]
    format: NotRequired[str]
    datefmt: NotRequired[str]

class AppConfig(MTConfig):
    log: NotRequired[AppLogConfig]
    pidfile: NotRequired[str]

class ConfigFile(pydantic.BaseModel):
    config: AppConfig

def send_email(
        subject: str,
        body: str,
        sender: str,
        receivers: list[str],
        host: str = DEFAULT_EMAIL_HOST,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        secure: SecureOption = None,
        protocol: EmailProtocol = 'SMTP',
        ssl_context: Optional[ssl.SSLContext] = None,
        logmails: bool = False,
) -> None:
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(receivers)
    msg.set_content(body)

    port = DEFAULT_EMAIL_PORT[protocol]

    if logmails:
        logger.info('Simulate sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))
    elif protocol == 'IMAP':
        if secure == 'SSL/TLS':
            context = ssl_context or ssl.create_default_context()
            with imaplib.IMAP4_SSL(host, port, ssl_context=context) as server:
                if user or password:
                    server.login(user or '', password or '')
                server.send(msg.as_bytes())
        else:
            with imaplib.IMAP4(host, port) as server:
                if secure == 'STARTTLS':
                    context = ssl_context or ssl.create_default_context()
                    server.starttls(ssl_context=context)
                if user or password:
                    server.login(user or '', password or '')
                server.send(msg.as_bytes())

    elif secure == 'SSL/TLS':
        context = ssl_context or ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=context) as server:
            if user or password:
                server.login(user or '', password or '')
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as server:
            if secure == 'STARTTLS':
                context = ssl_context or ssl.create_default_context()
                server.starttls(context=context)
            if user or password:
                server.login(user or '', password or '')
            server.send_message(msg)

_running = True

def read_log_entries(
        logfile: TextIO,
        entry_start: Pattern[str],
        wait_line_incomplete: int|float = DEFAULT_WAIT_LINE_INCOMPLETE,
        max_entry_lines: int = DEFAULT_MAX_ENTRY_LINES,
) -> Generator[str|None, None, None]:
    buf: list[str] = []
    next_line: Optional[str] = None
    while _running:
        if next_line is not None:
            line = next_line
            next_line = None
        else:
            line = logfile.readline()

        if not line:
            # singal no more entries for now
            yield None
            continue

        buf.append(line)
        if not line.endswith('\n'):
            sleep(wait_line_incomplete)
            buf.append(logfile.readline())

        line_count = 1
        while line_count < max_entry_lines:
            line = logfile.readline()

            if not line:
                break

            if not line.endswith('\n'):
                sleep(wait_line_incomplete)
                line += logfile.readline()

            if entry_start.match(line):
                next_line = line
                break

            buf.append(line)
            line_count += 1

        entry = ''.join(buf)
        buf.clear()
        yield entry

def logmon(logfile: str, config: Config) -> None:
    logfile = normpath(abspath(logfile))
    _logmon(logfile, config, [], [])

def _logmon(
        logfile: str,
        config: Config,
        hour_timestamps: list[float],
        minute_timestamps: list[float],
) -> None:
    entry_start_pattern = config.get('entry_start_pattern')
    if entry_start_pattern is None:
        entry_start_pattern = DEFAULT_ENTRY_START_PATTERN
    else:
        if isinstance(entry_start_pattern, list):
            entry_start_pattern = '|'.join(f'(?:{pattern})' for pattern in entry_start_pattern)
        entry_start_pattern = re.compile(entry_start_pattern)

    error_pattern = config.get('error_pattern')
    if error_pattern is None:
        error_pattern = DEFAULT_ERROR_PATTERN
    else:
        if isinstance(error_pattern, list):
            error_pattern = '|'.join(f'(?:{pattern})' for pattern in error_pattern)
        error_pattern = re.compile(error_pattern)

    ignore_pattern = config.get('ignore_pattern')
    if ignore_pattern is not None:
        if not ignore_pattern:
            ignore_pattern = None
        else:
            if isinstance(ignore_pattern, list):
                ignore_pattern = '|'.join(f'(?:{pattern})' for pattern in ignore_pattern)
            ignore_pattern = re.compile(ignore_pattern)

    wait_line_incomplete = config.get('wait_line_incomplete', DEFAULT_WAIT_LINE_INCOMPLETE)
    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    max_entry_lines = config.get('max_entry_lines', DEFAULT_MAX_ENTRY_LINES)
    max_emails_per_minute = config.get('max_emails_per_minute', DEFAULT_MAX_EMAILS_PER_MINUTE)
    max_emails_per_hour = config.get('max_emails_per_hour', DEFAULT_MAX_EMAILS_PER_HOUR)

    subject_templ = config.get('subject', DEFAULT_SUBJECT)
    body_templ = config.get('body', DEFAULT_BODY)

    sender = config['sender']
    receivers = config['receivers']
    email_host = config.get('host', DEFAULT_EMAIL_HOST)
    email_protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)
    email_port = config.get('port', DEFAULT_EMAIL_PORT[email_protocol])
    email_user = config.get('user')
    email_password = config.get('password')
    email_secure = config.get('secure')
    logmails = config.get('logmails', False)
    seek_end = config.get('seek_end', True)
    use_inotify = config.get('use_inotify', Inotify is not None)

    parentdir = dirname(logfile)
    if use_inotify and Inotify is not None:
        inotify = Inotify()
    else:
        inotify = None

    try:
        context = ssl.create_default_context() if email_secure else None

        last_minute_warning_ts = -inf
        last_hour_warning_ts = -inf
        file_not_found = False

        while _running:
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

                    reader = read_log_entries(logfp, entry_start_pattern, wait_line_incomplete, max_entry_lines)

                    while _running:
                        start_ts = monotonic()
                        entries: list[str] = []
                        count = 0
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

                                if error_match := error_pattern.search(entry):
                                    if ignore_pattern is not None and (ignore_match := ignore_pattern.search(entry)):
                                        if logger.isEnabledFor(logging.DEBUG):
                                            error_reason  = error_match.group(0)
                                            ignore_reason = ignore_match.group(0)
                                            logger.debug(f'{logfile}: IGNORED: {error_reason} for {ignore_reason}')
                                    else:
                                        entries.append(entry)

                                count += 1
                                if count >= max_entries:
                                    break

                        except KeyboardInterrupt:
                            _keyboard_interrupt()

                        if entries:
                            now = monotonic()

                            hour_cuttoff = now - (60 * 60)
                            minute_cutoff = now - 60

                            remove_smaller(minute_timestamps, minute_cutoff)
                            remove_smaller(hour_timestamps, hour_cuttoff)

                            if len(minute_timestamps) > max_emails_per_minute:
                                if last_minute_warning_ts < minute_cutoff:
                                    logger.warning(f"{logfile}: Maximum emails per minute exceeded! {len(minute_timestamps)} > {max_emails_per_minute}")
                                    last_minute_warning_ts = now
                            elif len(hour_timestamps) > max_emails_per_hour:
                                if last_hour_warning_ts < hour_cuttoff:
                                    logger.warning(f"{logfile}: Maximum emails per hour exceeded! {len(hour_timestamps)} > {max_emails_per_hour}")
                                    last_hour_warning_ts = now
                            else:
                                minute_timestamps.append(now)
                                hour_timestamps.append(now)

                                try:
                                    entries_str = '\n\n'.join(entries)
                                    first_entry = entries[0]
                                    first_line = first_entry.split('\n', 1)[0].lstrip().rstrip(' \r\n\t:{')

                                    params = {
                                        'entries': entries_str,
                                        'logfile': logfile,
                                        'line1': first_line,
                                        'entry1': first_entry,
                                        'entrynum': str(len(entries)),
                                    }

                                    subject = subject_templ.format_map(params)
                                    body = body_templ.format_map(params)

                                    logger.debug(f'{logfile}: Sending email with subject: {subject}')
                                    send_email(
                                        subject = subject,
                                        body = body,
                                        sender = sender,
                                        receivers = receivers,
                                        host = email_host,
                                        port = email_port,
                                        user = email_user,
                                        password = email_password,
                                        secure = email_secure,
                                        protocol = email_protocol,
                                        ssl_context = context,
                                        logmails = logmails,
                                    )
                                except Exception as exc:
                                    logger.error(f'{logfile}: Error sending email: {exc}', exc_info=exc)

                        if count < max_entries and _running:
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
                                        for event in inotify.event_gen():
                                            if not _running:
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

                                    if not _running:
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
                    if not _inotify_wait_for_exists(inotify, logfile):
                        break
                else:
                    logger.error(f"{logfile}: File not found, waiting for {wait_file_not_found} seconds")
                    sleep(wait_file_not_found)

            except KeyboardInterrupt:
                _keyboard_interrupt()
    finally:
        if inotify is not None:
            try: inotify.remove_watch(logfile)
            except: pass

            try: inotify.remove_watch(parentdir)
            except: pass

def _keyboard_interrupt() -> None:
    global _running
    if _running:
        logger.info("Shutting down on SIGINT...")
        _running = False

def _logmon_thread(logfile: str, config: Config) -> None:
    logfile = normpath(abspath(logfile))
    wait_after_crash = config.get('wait_after_crash', DEFAULT_WAIT_AFTER_CRASH)

    # Preserve list of timestamps over crashes, so that a crash won't cause more emails to be sent.
    hour_timestamps:   list[float] = []
    minute_timestamps: list[float] = []

    while _running:
        try:
            _logmon(
                logfile = logfile,
                config = config,
                hour_timestamps = hour_timestamps,
                minute_timestamps = minute_timestamps,
            )
        except KeyboardInterrupt:
            _keyboard_interrupt()
            return
        except Exception as exc:
            logger.error(f"{logfile}: Restarting after crash: {exc}", exc_info=exc)
            logger.debug(f"{logfile}: Waiting for {wait_after_crash} seconds after crash")
            sleep(wait_after_crash)
        else:
            return

def logmon_mt(config: MTConfig):
    global _running
    email_config = config.get('email')
    base_config = dict(email_config)

    default = config.get('default')
    if default:
        base_config.update(default)

    logfiles = config.get('logfiles')

    if not logfiles:
        raise ValueError('no logfiles given')

    threads: list[threading.Thread] = []
    try:
        items = logfiles.items() if isinstance(logfiles, dict) else [(logfile, {}) for logfile in logfiles]
        for logfile, cfg in items:
            cfg = {
                **base_config,
                **cfg
            }

            thread = threading.Thread(
                target = _logmon_thread,
                args = (logfile, cfg),
                name = logfile,
            )

            thread.start()
            threads.append(thread)
    except KeyboardInterrupt:
        _keyboard_interrupt()

    for thread in threads:
        try:
            thread.join()
        except KeyboardInterrupt:
            _keyboard_interrupt()
        except Exception as exc:
            logger.error(f"{thread.name}: Error waiting for thread: {exc}", exc_info=exc)

# based on http://code.activestate.com/recipes/66012/
def daemonize(stdout: str = '/dev/null', stderr: Optional[str] = None, stdin: str = '/dev/null', rundir: str = '/') -> None:
    # Do first fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0) # Exit first parent.
    except OSError as e:
        sys.stderr.write(f"fork #1 failed: ({e.errno}) {e.strerror}\n")
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir(rundir)
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0) # Exit second parent.
    except OSError as e:
        sys.stderr.write(f"fork #2 failed: ({e.errno}) {e.strerror}\n")
        sys.exit(1)

    # Open file descriptors
    if not stderr:
        stderr = stdout

    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+')

    # Redirect standard file descriptors.
    sys.stdout.flush()
    sys.stderr.flush()

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    si.close()
    so.close()
    se.close()

def main() -> None:
    from pathlib import Path
    import argparse
    import signal
    import json

    SPACE = re.compile(r'\s')
    NON_SPACE = re.compile(r'\S')

    class SmartFormatter(argparse.HelpFormatter):
        def _split_lines(self, text: str, width: int) -> list[str]:
            lines: list[str] = []
            for line_str in text.split('\n'):
                match = NON_SPACE.search(line_str)
                if not match:
                    lines.append('')
                    continue

                prefix = line_str[:match.start()]

                if len(prefix) >= width:
                    lines.append('')
                    prefix = ''

                line_len = prefix_len = len(prefix)
                line: list[str] = [prefix]
                pos = match.start()

                while pos < len(line_str):
                    match = NON_SPACE.search(line_str, pos)
                    if not match:
                        break

                    next_pos = match.start()
                    space = line_str[pos:next_pos]
                    line_len += len(space)

                    if line_len >= width:
                        lines.append(''.join(line))
                        line.clear()
                        line.append(prefix)
                        line_len = prefix_len
                    else:
                        line.append(space)

                    pos = next_pos
                    match = SPACE.search(line_str, pos)
                    if not match:
                        next_pos = len(line_str)
                    else:
                        next_pos = match.start()

                    word = line_str[pos:next_pos]
                    word_len = len(word)
                    line_len += word_len
                    if line_len > width:
                        lines.append(''.join(line).rstrip())
                        line.clear()
                        line.append(prefix)
                        line_len = prefix_len + word_len
                    elif word_len >= 3:
                        if all(c == '.' for c in word) and line_str[next_pos:next_pos + 1].isspace():
                            prefix_len = line_len + 1
                            prefix = ' ' * prefix_len
                        elif all(c == ' ' for c in word):
                            prefix_len = line_len
                            prefix = ' ' * prefix_len
                    line.append(word)
                    pos = next_pos

                lines.append(''.join(line).rstrip())
            return lines

        def _fill_text(self, text: str, width: int, indent: str) -> str:
            return '\n'.join(indent + line for line in self._split_lines(text, width - len(indent)))
        
        def _format_usage(self, usage, actions, groups, prefix):
            if prefix is None:
                # don't like the default texts
                prefix = 'Usage: '
            return super()._format_usage(usage, actions, groups, prefix)

    config_path = str(Path.home() / '.logmonrc')

    is_root = os.getpid() == 0
    esc_config_path = config_path.replace('%', '%%')
    esc_root_config_path = ROOT_CONFIG_PATH.replace('%', '%%')
    esc_default_config_path = esc_config_path if not is_root else esc_root_config_path
    esc_default_subject = DEFAULT_SUBJECT.replace('%', '%%')
    esc_default_body = DEFAULT_BODY.replace('%', '%%')
    esc_default_entry_start_pattern = DEFAULT_ENTRY_START_PATTERN.pattern.replace('%', '%%')
    esc_default_error_pattern = DEFAULT_ERROR_PATTERN.pattern.replace('%', '%%')
    esc_default_log_format = DEFAULT_LOG_FORMAT.replace('%', '%%')
    esc_default_log_datefmt = DEFAULT_LOG_DATEFMT.replace('%', '%%')

    ap = argparse.ArgumentParser(formatter_class=SmartFormatter,
        description='Monitor log files and send emails if errors are detected.\n'
                    '\n'
                   f'The settings are read from `{esc_config_path}`, or if run as root from `{esc_root_config_path}`. '
                    "But don't run it as root, use a dedicated user that can only read the log files. The "
                    'command line options overwrite the default settings, but not the per-logfile settings. '
                    'See below for the settings file format.',
        epilog='Settings:\n'
               '\n'
               'The settings file uses YAML, although if `PyYAML` is not installed it falls back to just JSON.\n'
               '\n'
               'Example:\n'
               '\n'
               '    ---\n'
               '    email:\n'
               '      protocol: SMTP # or IMAP\n'
               '      host: mail.example.com\n'
               '      port: 25\n'
               '      secure: STARTTLS # or SSL/TLS or None\n'
               '      sender: "Alice <alice@example.com>"\n'
               '      receivers:\n'
               '      - bob@example.com\n'
               '      - charly@example.com\n'
               '      user: alice@example.com\n'
               '      password: password1234\n'
               '    \n'
               '    default:\n'
               '      # Default configuration for every log\n'
               '      # entry that doesn\'t overwrite this.\n'
               '      # This secion and everything in it is\n'
               '      # optional.\n'
               '      entry_start_pattern: >-\n'
              r'        ^\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\]''\n'
               '      error_pattern: "(?i)ERROR|CRIT"\n'
               '      ignore_pattern: "SSL: error:0A00006C:"\n'
              f'      wait_line_incomplete: {DEFAULT_WAIT_LINE_INCOMPLETE}\n'
              f'      wait_file_not_found: {DEFAULT_WAIT_FILE_NOT_FOUND}\n'
              f'      wait_no_entries: {DEFAULT_WAIT_NO_ENTRIES}\n'
              f'      wait_before_send: {DEFAULT_WAIT_BEFORE_SEND}\n'
              f'      wait_after_crash: {DEFAULT_WAIT_AFTER_CRASH}\n'
              f'      max_entries: {DEFAULT_MAX_ENTRIES}\n'
              f'      max_entry_lines: {DEFAULT_MAX_ENTRY_LINES}\n'
              f'      max_emails_per_minute: {DEFAULT_MAX_EMAILS_PER_MINUTE}\n'
              f'      max_emails_per_hour: {DEFAULT_MAX_EMAILS_PER_HOUR}\n'
              f'      use_inotify: true\n'
              f'      seek_end: true\n'
               '    \n'
               '    logfiles:\n'
               '      # This can be a simple list of strings,\n'
               '      # which will then use the default settings\n'
               '      # for every file, or a mapping with\n'
               '      # overloaded settings for each file.\n'
               '      /var/log/service1.log:\n'
               '        entry_start_pattern: >-\n'
              r'          ^\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d:''\n'
               '      /var/log/service2.log: {}\n'
               '      /var/log/service3.log:\n'
               '        receivers:\n'
               '        - daniel@example.com\n'
               '    log:\n'
               '      # These are the logging settings for logmon\n'
               '      # itself. This section and everthing in it is\n'
               '      # optional.\n'
               '      \n'
               '      # Per default logs are written to standard\n'
               '      # output.\n'
               '      file: /var/log/logmon.log\n'
              f'      level: INFO\n'
              f'      format: {json.dumps(DEFAULT_LOG_FORMAT)}\n'
              f'      datefmt: {json.dumps(DEFAULT_LOG_DATEFMT)}\n'
               '    \n'
               '    # Per default no pidfile is written. Optional.\n'
               '    pidfile: /var/run/logmon.pid\n'
               '\n'
               'Copyright (c) 2025 Mathias Panzenböck\n'
    )
    try:
        # don't like the default texts
        ap._optionals.title = 'Options'
        ap._positionals.title = 'Positional Arguments'
    except: pass

    ap.add_argument('-v', '--version', default=False, action='store_true',
        help='Print version and exit.')
    ap.add_argument('--config', default=None, metavar='PATH',
        help=f'Read settings from PATH. [default: {esc_default_config_path}]')
    ap.add_argument('--sender', default=None, metavar='EMAIL')
    ap.add_argument('--receivers', default=None, metavar='EMAIL,...')
    ap.add_argument('--subject', default=None, metavar='TEMPLATE',
        help=f'Subject template for the emails. See --body for the template variables. [default: {esc_default_subject!r}]')
    ap.add_argument('--body', default=None, metavar='TEMPLATE',
        help='Body template for the emails.\n'
             '\n'
             'Template variables:\n'
             '  {entries} .... All entries for the message concatenated into a string with two newlines between each.\n'
             '  {logfile} .... The path of the logfile.\n'
             '  {entry1} ..... The first log entry of the message.\n'
             '  {line1} ...... The first line of the first log entry.\n'
             '  {entrynum} ... The number of entries in this message.\n'
             '  {{ ........... A literal {\n'
             '  }} ........... A literal }\n'
             '\n'
            f'[default: {esc_default_body!r}]')
    ap.add_argument('--wait-file-not-found', type=non_negative(float), default=None, metavar='SECONDS',
        help=f'Wait SECONDS before retry if file was not found. Not used if inotify is used. '
             f'[default: {DEFAULT_WAIT_FILE_NOT_FOUND}]')
    ap.add_argument('--wait-line-incomplete', type=non_negative(float), default=None, metavar='SECONDS',
        help=f'Wait SECOONDS for a 2nd read if the read line was not terminated with a newline. '
             f'Only one wait is performed. [default: {DEFAULT_WAIT_LINE_INCOMPLETE}]')
    ap.add_argument('--wait-no-entries', type=non_negative(float), default=None, metavar='SECONDS',
        help=f'Wait SECONDS before retry if no new entries where found. Not used if inotify is used. [default: {DEFAULT_WAIT_NO_ENTRIES}]')
    ap.add_argument('--wait-before-send', type=non_negative(float), default=None, metavar='SECONDS',
        help=f'Wait SECONDS for more entries before sending email. [default: {DEFAULT_WAIT_BEFORE_SEND}]')
    ap.add_argument('--wait-after-crash', type=non_negative(float), default=None, metavar='SECONDS',
        help=f'Wait SECONDS after a monitoring thread crashed. [default: {DEFAULT_WAIT_AFTER_CRASH}]')
    ap.add_argument('--max-entries', type=positive(int), default=None, metavar='COUNT',
        help=f'Only gather up to COUNT entries before sending an email. [default: {DEFAULT_MAX_ENTRIES}]')
    ap.add_argument('--max-entry-lines', type=positive(int), default=None, metavar='COUNT',
        help=f'Limit the length of a log entry to COUNT lines. [default: {DEFAULT_MAX_ENTRY_LINES}]')
    ap.add_argument('--max-emails-per-minute', type=positive(int), default=None, metavar='COUNT',
        help=f'Limit emails sent per minute to COUNT. Once the limit is reached an error will be logged and '
             f'no more emails are sent until the message count in the last 60 seconds dropped below COUNT. '
             f'This limit is only evaluated on a per-logfile basis, adjust it accordingly. '
             f'[default: {DEFAULT_MAX_EMAILS_PER_MINUTE}]')
    ap.add_argument('--max-emails-per-hour', type=positive(int), default=None, metavar='COUNT',
        help=f'Same as --max-emails-per-minute but for a span of 60 minutes. Both options are evaluated one after another. '
             f'[default: {DEFAULT_MAX_EMAILS_PER_HOUR}]')
    ap.set_defaults(use_inotify=None)
    inotify_grp = ap.add_mutually_exclusive_group()
    inotify_grp.add_argument('--use-inotify', default=None, action='store_true',
        help=f'This is the default if the `inotify` Python package is installed. [default: {Inotify is not None}]')
    inotify_grp.add_argument('--no-use-inotify', default=None, action='store_false', dest='use_inotify',
        help='Opposite of --use-inotify')
    ap.add_argument('--entry-start-pattern', default=None, metavar='REGEXP',
        help=f'This pattern defines the start of a log entry. A multiline log entry is parsed up until the next start '
             f'pattern is matched or the end of the file is reached. [default: {esc_default_entry_start_pattern}]')
    ap.add_argument('--error-pattern', default=None, metavar='REGEXP',
        help=f'If this pattern is found within a log entry the whole entry will be sent to the configured receivers. '
             f'[default: {esc_default_error_pattern}]')
    ap.add_argument('--ignore-pattern', default=None, metavar='REGEXP',
        help='Even if the error pattern matches, if this pattern also matches ignore the message anyway. '
             'Pass an empty string to clear the pattern form the settings file. Per default this is not set.')
    ap.set_defaults(seek_end=None)
    seek_end_grp = ap.add_mutually_exclusive_group()
    seek_end_grp.add_argument('--seek-end', default=None, action='store_true',
        help="Seek to the end of existing files. [default: True]")
    seek_end_grp.add_argument('--no-seek-end', default=None, action='store_false', dest='seek_end',
        help='Opposite of --seek-end')
    ap.add_argument('--email-host', default=None, metavar='HOST')
    ap.add_argument('--email-port', type=positive(int), default=None, metavar='PORT')
    ap.add_argument('--email-user', default=None, metavar='USER')
    ap.add_argument('--email-password', default=None, metavar='PASSWORD')
    ap.add_argument('--email-secure', default=None, choices=[str(arg) for arg in SecureOption.__args__])
    ap.add_argument('--email-protocol', default=None, choices=list(EmailProtocol.__args__))
    ap.add_argument('-d', '--daemonize', default=False, action='store_true',
        help='Fork process to the background. Send SIGTERM to the logmon process for shutdown.')
    ap.add_argument('--pidfile', default=None, metavar='PATH',
        help='Write logmons PID to given file. Useful in combination with --background.')
    ap.add_argument('--log-file', default=None, metavar='PATH',
        help='Logfile of logmon itself. If not given writes to standard out.')
    ap.add_argument('--log-level', default=None, choices=list(logging.getLevelNamesMapping()),
        help='Log level of logmon itself.')
    ap.add_argument('--log-format', default=DEFAULT_LOG_FORMAT, metavar='FORMAT',
        help=f'Format of log entries of logmon itself. [default: {esc_default_log_format}]')
    ap.add_argument('--log-datefmt', default=DEFAULT_LOG_DATEFMT, metavar='DATEFMT',
        help=f'Format of the timestamp of log entries of logmon itself. [default: {esc_default_log_datefmt}]')
    ap.add_argument('--logmails', default=None, action='store_true',
        help="Log emails instead of sending them. Use this for debugging.")
    ap.add_argument('logfiles', nargs='*', default=[],
        help='Overwrite the logfiles form the settings. If the given logfile is also configured in the '
             'settings it still uses the logfile specific settings for the given logfile.')
    args = ap.parse_args()

    if args.version:
        print(__version__)
        return

    config_path: str
    if args.config:
        config_path = abspath(args.config)
    elif is_root:
        config_path = ROOT_CONFIG_PATH
    else:
        config_path = str(Path.home() / '.logmonrc')

    config: dict
    try:
        config_path_lower = config_path.lower()
        if config_path_lower.endswith(('.yml', '.yaml')):
            import yaml
            with open(config_path, 'r') as configfp:
                config = yaml.safe_load(configfp)
        else:
            try:
                import yaml
            except ImportError:
                with open(config_path, 'r') as configfp:
                    config = json.load(configfp)
            else:
                with open(config_path, 'r') as configfp:
                    config = yaml.safe_load(configfp)

        if config is None:
            config = {}
        elif not isinstance(config, dict):
            print(f"{config_path}: Config file format error", file=sys.stderr)
            sys.exit(1)

    except FileNotFoundError:
        if args.config:
            print(f"{args.config}: File not found", file=sys.stderr)
            sys.exit(1)
        config = {}

    except Exception as exc:
        print(f"{config_path}: Config file format error: {exc}", file=sys.stderr)
        sys.exit(1)

    default_config = config.get('default')
    if default_config is None:
        default_config = config['default'] = {}

    email_config = config.get('email')
    if email_config is None:
        email_config = config['email'] = {}

    if args.sender is not None:
        email_config['sender'] = args.sender

    if args.receivers is not None:
        email_config['receivers'] = _parse_comma_list(args.receivers)
    else:
        receivers_str = email_config.get('receivers')
        if isinstance(receivers_str, str):
            email_config['receivers'] = _parse_comma_list(receivers_str)
        receiver = email_config.get('receiver')

        if receiver is not None:
            if receivers_str is not None:
                print(f"{config_path}: Only either email.receivers or email.receiver may be set!")
                sys.exit(1)
            email_config['receivers'] = [receiver]

    if args.body is not None:
        email_config['body'] = args.body

    if args.email_host is not None:
        email_config['host'] = args.email_host

    if args.email_port is not None:
        email_config['port'] = args.email_port

    if args.email_user is not None:
        email_config['user'] = args.email_user

    if args.email_password is not None:
        email_config['password'] = args.email_password

    if args.email_secure is not None:
        email_config['secure'] = args.email_secure if args.email_secure not in ('', 'None') else None

    if args.email_protocol is not None:
        email_config['protocol'] = args.email_protocol

    if args.logmails is not None:
        email_config['logmails'] = args.logmails

    if args.wait_file_not_found is not None:
        default_config['wait_file_not_found'] = args.wait_file_not_found

    if args.wait_line_incomplete is not None:
        default_config['wait_line_incomplete'] = args.wait_line_incomplete

    if args.wait_no_entries is not None:
        default_config['wait_no_entries'] = args.wait_no_entries

    if args.wait_before_send is not None:
        default_config['wait_before_send'] = args.wait_before_send

    if args.wait_after_crash is not None:
        default_config['wait_after_crash'] = args.wait_after_crash

    if args.max_entries is not None:
        default_config['max_entries'] = args.max_entries

    if args.max_entry_lines is not None:
        default_config['max_entry_lines'] = args.max_entry_lines

    if args.max_emails_per_minute is not None:
        default_config['max_emails_per_minute'] = args.max_emails_per_minute

    if args.max_emails_per_hour is not None:
        default_config['max_emails_per_hour'] = args.max_emails_per_hour

    if args.seek_end is not None:
        default_config['seek_end'] = args.seek_end

    if args.use_inotify is not None:
        default_config['use_inotify'] = args.use_inotify

    if args.error_pattern is not None:
        default_config['error_pattern'] = args.error_pattern

    if args.ignore_pattern is not None:
        default_config['ignore_pattern'] = args.ignore_pattern

    if args.entry_start_pattern is not None:
        default_config['entry_start_pattern'] = args.entry_start_pattern

    if args.logfiles:
        config_logfiles = config.get('logfiles')
        if isinstance(config_logfiles, dict):
            config['logfiles'] = { logfile: config_logfiles.get(logfile) or {} for logfile in args.logfile }
        else:
            config['logfiles'] = args.logfiles
        context_dir = abspath('.')
    else:
        context_dir = dirname(config_path)

    try:
        app_config = ConfigFile(config=config).config # type: ignore
    except pydantic.ValidationError as exc:
        print(f"{config_path}: Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    logfiles = app_config['logfiles']

    if not logfiles:
        print('No logfiles configured!', file=sys.stderr)
        sys.exit(1)

    if Inotify is None and config.get('use_inotify'):
        _print_no_inotify()
        sys.exit(1)

    # make all paths absolute before daemonize
    abslogfiles: dict[str, LogfileConfig] = {}
    if isinstance(logfiles, dict):
        for logfile, cfg in logfiles.items():
            if Inotify is None and cfg.get('use_inotify'):
                _print_no_inotify()
                sys.exit(1)
            abslogfiles[joinpath(context_dir, logfile)] = cfg
    else:
        for logfile in logfiles:
            abslogfiles[joinpath(context_dir, logfile)] = {}
    app_config['logfiles'] = abslogfiles

    logconfig = app_config.get('log') or {}
    loglevel_name = args.log_level   if args.log_level   is not None else logconfig.get('level', 'INFO')
    app_logfile   = args.log_file    if args.log_file    is not None else logconfig.get('file')
    logformat     = args.log_format  if args.log_format  is not None else logconfig.get('logformat',  DEFAULT_LOG_FORMAT)
    logdatefmt    = args.log_datefmt if args.log_datefmt is not None else logconfig.get('logdatefmt', DEFAULT_LOG_DATEFMT)

    loglevel = logging.getLevelNamesMapping()[loglevel_name]

    logging.basicConfig(
        filename = app_logfile,
        level    = loglevel,
        format   = logformat,
        datefmt  = logdatefmt,
    )

    pidfile: Optional[str] = app_config.get('pidfile')

    if args.pidfile is not None:
        pidfile = args.pidfile

    if args.daemonize:
        if pidfile:
            os.access(pidfile, os.W_OK | os.R_OK)

        daemonize()

    if pidfile:
        pid = os.getpid()
        with open(pidfile, 'w') as pidfilefp:
            pidfilefp.write(f'{pid}\n')

    def on_signal(signum: int, frame) -> None:
        global _running
        _running = False
        signame: str
        try:
            signame = signal.Signals(signum).name
        except:
            signame = f'signal {signum}'
        logger.info(f"Shutting down on {signame}...")

    signal.signal(signal.SIGTERM, on_signal)

    if len(abslogfiles) == 1:
        logfile, cfg = next(iter(abslogfiles.items()))
        cfg = {
            **email_config,
            **default_config,
            **cfg
        }
        _logmon_thread(logfile, cfg) # type: ignore
    else:
        logmon_mt(app_config)

def _print_no_inotify() -> None:
    print('Inotify support requires the `inotify` Python package to be installed!', file=sys.stderr)

if __name__ == '__main__':
    main()
