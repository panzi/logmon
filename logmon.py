#!/usr/bin/env python3
"""\
logmon - Monitor log files and send emails if errors are detected

Copyright (c) 2025  Mathias Panzenböck

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Callable, Generator, TextIO, Pattern, Optional, NotRequired, Literal, Any, Self, get_args, override
from abc import ABC, abstractmethod
from time import sleep, monotonic
from email.message import EmailMessage
from email.policy import SMTP
from math import inf
from os.path import dirname, abspath, join as joinpath, normpath
from http.client import HTTPConnection, HTTPSConnection, NotConnected, HTTPException
from urllib.parse import urlencode, urljoin, urlparse
from select import poll, POLLIN
from base64 import b64encode

import re
import os
import sys
import ssl
import uuid
import json
import errno
import smtplib
import imaplib
import logging
import threading
import pydantic

if sys.version_info < (3, 12):
    # compatibility fudging
    try:
        from typing_extensions import TypedDict
    except ImportError:
        from typing import TypedDict
else:
    from typing import TypedDict

__version__ = '0.2.1'

HTTP_REDIRECT_STATUSES = frozenset((301, 302, 307, 308))

try:
    # inotify has no proper type annotations!
    from inotify.adapters import Inotify, TerminalEventException # type: ignore
    from inotify.constants import IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_MOVE_SELF # type: ignore
    from inotify.calls import InotifyError # type: ignore

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
EmailProtocol = Literal['SMTP', 'IMAP', 'HTTP', 'HTTPS']
Logmails = Literal['always', 'never', 'onerror', 'instead']
ContentType = Literal['JSON', 'URL', 'multipart']

DEFAULT_EMAIL_HOST = 'localhost'
DEFAULT_EMAIL_PROTOCOL: EmailProtocol = 'SMTP'

DEFAULT_SUBJECT = '[ERROR] {brief}'
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
DEFAULT_LOGMAILS: Logmails = 'onerror'

DEFAULT_ENTRY_START_PATTERN = re.compile(r'^\[\d\d\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?: ?(?:[-+]\d\d:?\d\d|Z))?\]')
DEFAULT_WARNING_PATTERN = re.compile(r'WARNING', re.I)
DEFAULT_ERROR_PATTERN = re.compile(r'ERROR|CRITICAL|Exception', re.I)

DEFAULT_HTTP_MAX_REDIRECT = 10
DEFAULT_HTTP_PARAMS = {
    'subject': '{subject}',
    'receivers': '{receivers}',
}

ROOT_CONFIG_PATH = '/etc/logmonrc'

JSON_PATH_PATTERN_STR = r'(?P<key>[\$_a-z][\$_a-z0-9]*)|\[(?:(?P<index>[0-9]+)|(?P<qkey>"(?:[^"\\]|\\.)*"))\]'
JSON_PATH_START_PATTERN = re.compile(JSON_PATH_PATTERN_STR, re.I)
JSON_PATH_TAIL_PATTERN = re.compile(r'\.' + JSON_PATH_PATTERN_STR, re.I)

type JsonPath = list[str|int]
type JsonCmp = Literal["<", ">", "<=", ">=", "=", "!=", "in", "not in"]

class Range(pydantic.BaseModel):
    start: int
    stop: int

    def __contains__(self, other) -> bool:
        if not isinstance(other, int):
            return False

        return other >= self.start and other < self.stop

class RangeValidator(pydantic.BaseModel):
    range: list[str|float|int|None]|Range

type EqExpr = tuple[Literal["=","!="],None|bool|float|int|str]
type OrdExpr = tuple[Literal["<",">","<=",">="],float|int|str]
type RangeExpr = tuple[Literal["in","not in"],list[str|float|int|None]|Range]
type RegExExpr = tuple[Literal["~"], str]
type JsonExpr = EqExpr|OrdExpr|RangeExpr|RegExExpr
type JsonMatch = dict[str|int, JsonExpr|JsonMatch]

def parse_json_match(match_def: str) -> tuple[JsonPath, JsonExpr]:
    m = JSON_PATH_START_PATTERN.match(match_def)
    if m is None:
        raise ValueError(f'Illegal JSON match definition: {match_def!r}')

    match = JSON_PATH_TAIL_PATTERN.match

    path: JsonPath = []
    index = m.end()

    while m is not None:
        if (key := m.group('key')) is not None:
            path.append(key)
        elif (index := m.group('index')) is not None:
            path.append(int(index, 10))
        elif (qkey := m.group('qkey')) is not None:
            path.append(json.loads(qkey))
        else:
            assert False, "No group defined!"

        index = m.end()
        m = match(match_def, index)

    tail = match_def[index:].lstrip()
    try:
        for ord_op in "<=", ">=", "<", ">":
            if tail.startswith(ord_op):
                ord_value = json.loads(tail[len(ord_op):])

                if not isinstance(ord_value, (int, float, str)):
                    raise ValueError(f'{ord_op} is only defined for int, float, and str: {match_def!r}')

                return path, (ord_op, ord_value)

        for eq_op in "!=", "=":
            if tail.startswith(eq_op):
                eq_value = json.loads(tail[len(eq_op):])

                if not isinstance(eq_value, (int, float, str, bool)) and eq_value is not None:
                    raise ValueError(f'{eq_op} is only defined for int, float, str, bool and None: {match_def!r}')

                return path, (eq_op, eq_value)

        if tail.startswith("~"):
            tail = tail[1:].lstrip()
            re_value = json.loads(tail)
            if not isinstance(re_value, str):
                raise ValueError(f'~ is only defined for str: {match_def!r}')

            return path, ('~', re_value)

        in_op: Literal["in", "not in"]
        if tail.startswith("in") and not _is_json_word(tail[2:3]):
            tail = tail[2:]
            in_op = "in"
        elif tail.startswith("not") and not _is_json_word(tail[3:4]):
            tail = tail[3:]
            if tail.startswith("in") and not _is_json_word(tail[2:3]):
                tail = tail[2:]
                in_op = "not in"
            else:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}')
        else:
            raise ValueError(f'Illegal JSON match definition: {match_def!r}')

        if tail[1:2].isnumeric():
            range_parts = tail.split('..', 1)
            if len(range_parts) != 2:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}')

            try:
                start = int(range_parts[0], 10)
                stop = int(range_parts[1], 10)
            except ValueError as exc:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

            return path, (in_op, Range(start=start, stop=stop))

        try:
            in_value = RangeValidator(range = json.loads(tail)).range
        except pydantic.ValidationError as exc:
            raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

        return path, (in_op, in_value)

    except json.JSONDecodeError as exc:
        raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

def _is_json_word(ch: str) -> bool:
    return ch.isalnum() or ch == '_' or ch == '$'

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

class EMailConfigBase(TypedDict):
    subject: NotRequired[str]
    body: NotRequired[str]
    host: NotRequired[str]
    port: NotRequired[int]
    user: NotRequired[str]
    password: NotRequired[str]
    secure: NotRequired[SecureOption]
    protocol: NotRequired[EmailProtocol]
    logmails: NotRequired[Logmails]
    http_method: NotRequired[str]
    http_path: NotRequired[str]
    http_params: NotRequired[dict[str, str]]
    http_content_type: NotRequired[ContentType]
    http_headers: NotRequired[dict[str, str]]
    http_max_redirect: NotRequired[int]
    keep_connected: NotRequired[bool]

class EMailConfig(EMailConfigBase):
    sender: str
    receivers: list[str]

class PartialEMailConfig(EMailConfigBase):
    sender: NotRequired[str]
    receivers: NotRequired[list[str]]

class LimitsConfig(TypedDict):
    max_emails_per_minute: NotRequired[int]
    max_emails_per_hour: NotRequired[int]

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
    use_inotify: NotRequired[bool]
    seek_end: NotRequired[bool] # default: True
    json: NotRequired[bool] # default: False
    json_match: NotRequired[Optional[JsonMatch]]

SystemDPriority = Literal[
    'PANIC', 'WARNING', 'ALERT', 'NONE', 'CRITICAL',
    'DEBUG', 'INFO', 'ERROR', 'NOTICE',
]

class SystemDConfig(TypedDict):
    systemd_priority: NotRequired[SystemDPriority|int]
    systemd_match: NotRequired[dict[str, str|int]] # TODO: more complex expressions?

class Config(EMailConfig, LogfileConfig, SystemDConfig, LimitsConfig):
    pass

class PartialConfig(PartialEMailConfig, LogfileConfig, SystemDConfig, LimitsConfig):
    pass

class DefaultConfig(LogfileConfig, SystemDConfig):
    pass

class MTConfig(TypedDict):
    email: EMailConfig
    default: NotRequired[DefaultConfig]
    logfiles: dict[str, PartialConfig]|list[str]
    limits: NotRequired[LimitsConfig]

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

def make_message(
        sender: str,
        receivers: list[str],
        templ_params: dict[str, str],
        subject_templ: str,
        body_templ: str,
) -> EmailMessage:
    subject = subject_templ.format_map(templ_params)
    body = body_templ.format_map(templ_params)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(receivers)
    msg.set_content(body)

    return msg

class MultipartFile(TypedDict):
    filename: str
    content_type: NotRequired[str]
    content: bytes

FIELD_NAME_PATTERN = re.compile(r'["\x00-\x1F]')

def quote_field_name(name: str) -> str:
    return FIELD_NAME_PATTERN.sub(lambda m: '%%%02X' % ord(m[0]), name)

def encode_multipart(fields: dict[str,str]|dict[str, MultipartFile]|dict[str, str|MultipartFile]) -> tuple[dict[str, str], bytes]:
    buf: list[bytes] = []
    boundary = uuid.uuid4().hex
    bin_boundary = f'--{boundary}\r\n'.encode()
    headers: dict[str, str] = {
        'Content-Type': f'multipart/form-data; boundary={boundary}'
    }

    for key, value in fields.items():
        buf.append(bin_boundary)
        if isinstance(value, str):
            buf.append(f'Content-Disposition: form-data; name="{quote_field_name(key)}"\r\n'.encode())
            buf.append(b'\r\n')
            buf.append(value.encode())
            buf.append(b'\r\n')
        else:
            buf.append(f'Content-Disposition: form-data; name="{quote_field_name(key)}", filename="{quote_field_name(value["filename"])}"\r\n'.encode())
            content_type = value.get('content_type', 'application/octet-stream').replace('\n', ' ').replace('\r', '')
            buf.append(f'Content-Type: {content_type}\r\n'.encode())
            buf.append(b'\r\n')
            buf.append(value['content'])
            buf.append(b'\r\n')

    buf.append(f'--{boundary}--\r\n'.encode())
    body = b''.join(buf)

    return headers, body

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

class LimitsService:
    __slots__ = (
        '_lock', '_hour_timestamps', '_minute_timestamps',
        '_max_emails_per_minute', '_max_emails_per_hour',
        '_last_minute_warning_ts', '_last_hour_warning_ts',
    )

    _lock: threading.Lock
    _hour_timestamps: list[float]
    _minute_timestamps: list[float]
    _max_emails_per_minute: int
    _max_emails_per_hour: int
    _last_minute_warning_ts: float
    _last_hour_warning_ts: float

    def __init__(self, max_emails_per_minute: int, max_emails_per_hour: int) -> None:
        self._lock = threading.Lock()
        self._hour_timestamps   = []
        self._minute_timestamps = []
        self._max_emails_per_minute = max_emails_per_minute
        self._max_emails_per_hour   = max_emails_per_hour
        self._last_minute_warning_ts = -inf
        self._last_hour_warning_ts = -inf

    @staticmethod
    def from_config(config: LimitsConfig) -> 'LimitsService':
        return LimitsService(
            max_emails_per_hour=config.get('max_emails_per_hour', DEFAULT_MAX_EMAILS_PER_HOUR),
            max_emails_per_minute=config.get('max_emails_per_minute', DEFAULT_MAX_EMAILS_PER_MINUTE),
        )

    @property
    def max_emails_per_minute(self) -> int:
        return self._max_emails_per_minute

    @property
    def max_emails_per_hour(self) -> int:
        return self._max_emails_per_hour

    def check(self) -> bool:
        warn_minute = False
        warn_hour = False

        with self._lock:
            now = monotonic()
            hour_cutoff = now - (60 * 60)
            minute_cutoff = now - 60

            remove_smaller(self._minute_timestamps, minute_cutoff)
            remove_smaller(self._hour_timestamps, hour_cutoff)

            minutes_count = len(self._minute_timestamps)
            hours_count   = len(self._hour_timestamps)

            minutes_ok = minutes_count < self._max_emails_per_minute
            hours_ok   = hours_count   < self._max_emails_per_hour

            if not minutes_ok:
                if self._last_minute_warning_ts < minute_cutoff:
                    warn_minute = True
                    self._last_minute_warning_ts = now

            elif not hours_ok:
                if self._last_hour_warning_ts < hour_cutoff:
                    warn_hour = True
                    self._last_hour_warning_ts = now

            else:
                self._hour_timestamps.append(now)
                self._minute_timestamps.append(now)

        if warn_minute:
            logger.warning(f"Maximum emails per minute exceeded! {minutes_count} >= {self._max_emails_per_minute}")

        if warn_hour:
            logger.warning(f"Maximum emails per hour exceeded! {hours_count} >= {self._max_emails_per_hour}")

        return minutes_ok and hours_ok

def logmon(logfile: str, config: Config) -> None:
    logfile = normpath(abspath(logfile))
    limits = LimitsService.from_config(config)
    _logmon(logfile, config, limits)

def _logmon(
        logfile: str,
        config: Config,
        limits: LimitsService,
        stopfd: Optional[int] = None,
) -> None:
    if _is_systemd_path(logfile):
        return _logmon_systemd(logfile, config, limits, stopfd)

    entry_start_pattern_cfg = config.get('entry_start_pattern')
    if entry_start_pattern_cfg is None:
        entry_start_pattern = DEFAULT_ENTRY_START_PATTERN
    else:
        if isinstance(entry_start_pattern_cfg, list):
            entry_start_pattern_cfg = '|'.join(f'(?:{pattern})' for pattern in entry_start_pattern_cfg)
        entry_start_pattern = re.compile(entry_start_pattern_cfg)

    error_pattern_cfg = config.get('error_pattern')
    if error_pattern_cfg is None:
        error_pattern = DEFAULT_ERROR_PATTERN
    else:
        if isinstance(error_pattern_cfg, list):
            error_pattern_cfg = '|'.join(f'(?:{pattern})' for pattern in error_pattern_cfg)
        error_pattern = re.compile(error_pattern_cfg)

    ignore_pattern_cfg = config.get('ignore_pattern')
    ignore_pattern: Optional[Pattern[str]]
    if ignore_pattern_cfg is not None:
        if not ignore_pattern_cfg:
            ignore_pattern = None
        else:
            if isinstance(ignore_pattern_cfg, list):
                ignore_pattern_cfg = '|'.join(f'(?:{pattern})' for pattern in ignore_pattern_cfg)
            ignore_pattern = re.compile(ignore_pattern_cfg)
    else:
        ignore_pattern = None

    wait_line_incomplete = config.get('wait_line_incomplete', DEFAULT_WAIT_LINE_INCOMPLETE)
    wait_no_entries = config.get('wait_no_entries', DEFAULT_WAIT_NO_ENTRIES)
    wait_file_not_found = config.get('wait_file_not_found', DEFAULT_WAIT_FILE_NOT_FOUND)
    wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
    max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
    max_entry_lines = config.get('max_entry_lines', DEFAULT_MAX_ENTRY_LINES)

    with EmailSender.from_config(config) as email_sender:
        seek_end = config.get('seek_end', True)
        use_inotify = config.get('use_inotify', Inotify is not None)

        parentdir = dirname(logfile)
        if use_inotify and Inotify is not None:
            inotify = Inotify()
        else:
            inotify = None

        try:
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
                                try:
                                    if limits.check():
                                        brief = ''

                                        for line in entry_start_pattern.sub('', entries[0]).split('\n'):
                                            brief = line.lstrip().rstrip(' \r\n\t:{')
                                            if brief:
                                                break

                                        if not brief:
                                            brief = entries[0]

                                        email_sender.send_email(
                                            logfile = logfile,
                                            entries = entries,
                                            brief = brief,
                                        )
                                    elif logger.isEnabledFor(logging.DEBUG):
                                        first_entry = entries[0]
                                        first_line = first_entry.split('\n', 1)[0].lstrip().rstrip(' \r\n\t:{')
                                        logger.debug(f'{logfile}: Email with {len(entries)} entries was rate limited: {first_line}')

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

class EmailSender(ABC):
    __slots__ = (
        'subject_templ',
        'body_templ',
        'sender',
        'receivers',
        'logmails',
        'protocol',
    )

    subject_templ: str
    body_templ: str

    sender: str
    receivers: list[str]
    protocol: EmailProtocol

    logmails: Logmails

    @staticmethod
    def from_config(config: Config) -> "EmailSender":
        protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

        match protocol:
            case 'HTTP' | 'HTTPS':
                return HttpEmailSender(config)

            case 'IMAP':
                return ImapEmailSender(config)

            case 'SMTP':
                return SmtpEmailSender(config)

            case _:
                raise ValueError(f'Illegal protocol: {protocol!r}')

    def __init__(self, config: EMailConfig) -> None:
        self.subject_templ = config.get('subject', DEFAULT_SUBJECT)
        self.body_templ = config.get('body', DEFAULT_BODY)

        self.sender = config['sender']
        self.receivers = config['receivers']
        self.protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

        self.logmails = config.get('logmails', DEFAULT_LOGMAILS)

    @abstractmethod
    def send_email(self, logfile: str, entries: list[str], brief: str) -> None:
        ...

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        pass

    def handle_error(self, msg: Optional[EmailMessage], templ_params: dict[str, str], exc: Exception) -> None:
        if self.logmails == 'onerror':
            if msg is None:
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
            logger.error('Error while sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))

    def get_email_params(self, logfile: str, entries: list[str], brief: str) -> Optional[tuple[dict[str, str], Optional[EmailMessage]]]:
        entries_str = '\n\n'.join(entries)
        first_entry = entries[0]
        lines = first_entry.split('\n')
        first_line = lines[0]

        templ_params = {
            'entries': entries_str,
            'entries_json': json.dumps(entries, indent=2),
            'logfile': logfile,
            'brief': brief,
            'line1': first_line,
            'entry1': first_entry,
            'entrynum': str(len(entries)),
            'receivers': ', '.join(self.receivers),
        }

        msg: Optional[EmailMessage]
        match self.logmails:
            case 'always':
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
                logger.info(f'{logfile}: Sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))

            case 'instead':
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
                logger.info(f'{logfile}: Simulate sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))
                return None

            case _:
                msg = None

        return templ_params, msg

def get_default_port(config: EMailConfig) -> int:
    protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

    match protocol:
        case 'HTTP':
            return 80

        case 'HTTPS':
            return 443

        case 'SMTP':
            match config.get('secure'):
                case 'STARTTLS':
                    return 587

                case 'SSL/TLS':
                    return 465

                case None:
                    return 25

        case 'IMAP':
            match config.get('secure'):
                case 'STARTTLS' | None:
                    return 993

                case 'SSL/TLS':
                    return 143

        case _:
            raise ValueError(f'Illegal protocol: {protocol!r}')

class RemoteEmailSender(EmailSender):
    __slots__ = (
        'host',
        'port',
        'username',
        'password',
        'keep_connected',
    )

    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    keep_connected: bool

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        port = config.get('port')
        self.host = config.get('host', DEFAULT_EMAIL_HOST)
        self.port = port if port is not None else get_default_port(config)
        self.username = config.get('user')
        self.password = config.get('password')
        self.keep_connected = config.get('keep_connected', False)

class HttpEmailSender(RemoteEmailSender):
    __slots__ = (
        'http_method',
        'http_path',
        'http_params',
        'http_content_type',
        'http_headers',
        'http_max_redirect',
        'http_connection',
    )
    http_method: str
    http_path: str
    http_params: Optional[dict[str, str]]
    http_content_type: Optional[ContentType]
    http_headers: Optional[dict[str, str]]
    http_max_redirect: int
    http_connection: HTTPConnection

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.http_method = config.get('http_method', 'POST')
        http_path = config.get('http_path', '/')
        if not http_path.startswith('/'):
            http_path = f'/{http_path}'
        self.http_path = http_path
        self.http_params = config.get('http_params')
        self.http_content_type = config.get('http_content_type')
        self.http_headers = config.get('http_headers')
        self.http_max_redirect = config.get('http_max_redirect', DEFAULT_HTTP_MAX_REDIRECT)
        self.http_connection = HTTPConnection(self.host, self.port) if self.protocol == 'HTTP' else \
                               HTTPSConnection(self.host, self.port)

    @override
    def send_email(self, logfile: str, entries: list[str], brief: str) -> None:
        email_params = self.get_email_params(logfile, entries, brief)

        if email_params is None:
            return

        templ_params, msg = email_params

        try:
            if logger.isEnabledFor(logging.DEBUG):
                subject = self.subject_templ.format_map(templ_params)
                debug_url = f'{self.protocol.lower()}://{self.host}:{self.port}{self.http_path}'
                logger.debug(f'{logfile}: {self.http_method}-ing to {debug_url}: {subject}')

            http_params = self.http_params
            if http_params is None:
                http_params = DEFAULT_HTTP_PARAMS

            data = {
                key: templ.format_map(templ_params)
                for key, templ in http_params.items()
            }

            body: Optional[bytes]
            content_type: Optional[str] = None
            http_method = self.http_method
            relative_url = self.http_path

            if http_method == 'GET':
                query = urlencode(data)
                relative_url = f'{relative_url}?{query}'
                body = None
            else:
                http_content_type = self.http_content_type
                if http_content_type is None or http_content_type == 'URL':
                    body = urlencode(data).encode()
                    content_type = 'application/x-www-form-urlencoded'

                elif http_content_type == 'JSON':
                    json_data: dict[str, Any] = data
                    for key, templ in http_params.items():
                        if templ == '{entries_json}':
                            json_data[key] = entries

                    body = json.dumps(json_data).encode()
                    content_type = 'application/json; charset=UTF-8'

                elif http_content_type == 'multipart':
                    headers, body = encode_multipart(data)

                else:
                    raise ValueError(f'illegal http_content_type: {http_content_type}')

            if self.http_headers:
                headers = dict(self.http_headers)
            else:
                headers = {}

            if content_type:
                headers['Content-Type'] = content_type

            if self.keep_connected:
                headers['Connection'] = 'keep-alive'

            if self.username or self.password:
                credentials = f'{self.username or ''}:{self.password or ''}'.encode()
                headers['Authorization'] = f"Basic {b64encode(credentials).decode('ASCII')}"

            if self.http_connection.sock is None:
                self.http_connection.connect()

            try:
                self.http_connection.request(http_method, relative_url, body, headers)
            except NotConnected:
                self.http_connection.connect()
                self.http_connection.request(http_method, relative_url, body, headers)

            res = self.http_connection.getresponse()
            status = res.status

            if status in HTTP_REDIRECT_STATUSES:
                scheme = self.protocol.lower()
                url = f'{scheme}://{relative_url}'

                if http_method != 'GET':
                    raise HTTPException(f'Got {status} {res.reason} for {http_method} request to {url}')

                visited = {url}

                if self.http_headers:
                    new_headers = dict(self.http_headers)
                else:
                    new_headers = {}

                if content_type:
                    new_headers['Content-Type'] = content_type

                redirect_count = 0
                while True:
                    redirect_count += 1
                    if redirect_count > self.http_max_redirect:
                        raise HTTPException(f'Maximum number of redirects ({self.http_max_redirect}) exceeded!')

                    location = res.headers.get('location')

                    if not location:
                        raise HTTPException(f'Redirect {status} {res.reason} is missing a Location header!')

                    new_url = urljoin(url, location)
                    if new_url in visited:
                        raise HTTPException(f'Redirection loop to {new_url} detected!')
                    visited.add(new_url)

                    new_url_obj = urlparse(new_url)
                    new_relative_url = (new_url_obj.path or '/')
                    if new_url_obj.query:
                        new_relative_url = f'{new_relative_url}?{new_url_obj.query}'

                    new_port = new_url_obj.port
                    if new_port is None:
                        if new_url_obj.scheme == 'http':
                            new_port = 80

                        elif new_url_obj.scheme == 'https':
                            new_port = 443

                    if self.keep_connected and new_url_obj.scheme == scheme and new_url_obj.netloc == self.host and new_port == self.port:
                        try:
                            self.http_connection.request('GET', new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })
                        except NotConnected:
                            self.http_connection.connect()
                            self.http_connection.request('GET', new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })

                        res = self.http_connection.getresponse()
                    else:
                        conn = HTTPConnection(new_url_obj.netloc, new_port) if new_url_obj.scheme == 'http' else \
                               HTTPSConnection(new_url_obj.netloc, new_port)
                        try:
                            conn.connect()
                            conn.request('GET', new_relative_url, body, new_headers)
                            res = self.http_connection.getresponse()
                        finally:
                            conn.close()

                    status = res.status
                    url = new_url

                    if status in HTTP_REDIRECT_STATUSES:
                        continue

                    if status < 200 or status >= 300:
                        raise HTTPException(f'HTTP status error: {status} {res.reason}')

            elif status < 200 or status >= 300:
                raise HTTPException(f'HTTP status error: {status} {res.reason}')

        except Exception as exc:
            self.handle_error(msg, templ_params, exc)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.http_connection.close()

class SslEmailSender(RemoteEmailSender):
    __slots__ = (
        'secure',
        'ssl_context',
    )

    secure: SecureOption
    ssl_context: Optional[ssl.SSLContext]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.secure = secure = config.get('secure')
        self.ssl_context = ssl.create_default_context() if secure else None

class SmtpEmailSender(SslEmailSender):
    __slots__ = (
        'smtp',
    )

    smtp: smtplib.SMTP

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        if self.secure == 'SSL/TLS':
            self.smtp = smtplib.SMTP_SSL()
        else:
            self.smtp = smtplib.SMTP()

    @override
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.smtp.sock is not None:
            self.smtp.__exit__(exc_type, exc_value, traceback)

    def connect(self) -> None:
        self.smtp.connect(self.host, self.port)

        if self.secure == 'STARTTLS':
            if self.ssl_context is None:
                self.ssl_context = ssl.create_default_context()
            self.smtp.starttls(context=self.ssl_context)

        if self.username or self.password:
            self.smtp.login(self.username or '', self.password or '')

    @override
    def send_email(self, logfile: str, entries: list[str], brief: str) -> None:
        email_params = self.get_email_params(logfile, entries, brief)

        if email_params is None:
            return

        templ_params, msg = email_params

        try:
            if msg is None:
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)

            try:
                if self.smtp.sock is None:
                    self.connect()

                try:
                    self.smtp.send_message(msg)
                except smtplib.SMTPServerDisconnected:
                    self.connect()
                    self.smtp.send_message(msg)
            finally:
                if not self.keep_connected:
                    self.__exit__(None, None, None)

        except Exception as exc:
            self.handle_error(msg, templ_params, exc)
            raise

class ImapEmailSender(SslEmailSender):
    __slots__ = (
        'imap',
    )

    imap: Optional[imaplib.IMAP4]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.imap = None

    @override
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        imap = self.imap
        if imap is not None:
            imap.__exit__(exc_type, exc_value, traceback)
            self.imap = None

    def connect(self) -> imaplib.IMAP4:
        imap = self.imap

        if imap is not None:
            try:
                imap.shutdown()
            except Exception as exc:
                logger.error(f'Error shutting down existing IMAP connection: {exc}', exc_info=exc)

            self.imap = None

        if self.secure == 'SSL/TLS':
            imap = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=self.ssl_context)
        else:
            imap = imaplib.IMAP4(self.host, self.port)

        self.imap = imap
        imap.open(self.host, self.port)

        if self.secure == 'STARTTLS':
            if self.ssl_context is None:
                self.ssl_context = ssl.create_default_context()
            imap.starttls(ssl_context=self.ssl_context)

        if self.username or self.password:
            imap.login(self.username or '', self.password or '')

        return imap

    @override
    def send_email(self, logfile: str, entries: list[str], brief: str) -> None:
        email_params = self.get_email_params(logfile, entries, brief)

        if email_params is None:
            return

        templ_params, msg = email_params

        try:
            if msg is None:
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)

            msg_bytes = msg.as_bytes()

            try:
                imap = self.imap
                if imap is None:
                    imap = self.connect()

                try:
                    imap.send(msg_bytes)
                except OSError as exc:
                    if exc.errno == errno.ECONNRESET or exc.errno == errno.ENOTCONN:
                        imap = self.connect()
                        imap.send(msg_bytes)
                    else:
                        raise
            finally:
                if not self.keep_connected:
                    self.__exit__(None, None, None)

        except Exception as exc:
            self.handle_error(msg, templ_params, exc)
            raise

try:
    from cysystemd.reader import JournalReader, JournalOpenMode, Rule # type: ignore
    from cysystemd.journal import Priority

    OPEN_MODES: dict[str, JournalOpenMode] = {
        mode.name: mode
        for mode in JournalOpenMode
    }

    def _logmon_systemd(
        logfile: str,
        config: Config,
        limits: LimitsService,
        stopfd: Optional[int] = None,
    ) -> None:
        wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
        max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)
        # TODO: respect max_entry_lines? break the JSON?
        # max_entry_lines = config.get('max_entry_lines', DEFAULT_MAX_ENTRY_LINES)

        with EmailSender.from_config(config) as email_sender:
            seek_end = config.get('seek_end', True)
            raw_priority = config.get('systemd_priority')
            match_dict = config.get('systemd_match')

            priority: Optional[Priority]
            if isinstance(raw_priority, str):
                priority = Priority[raw_priority]
            elif raw_priority is not None:
                priority = Priority(raw_priority)
            else:
                priority = None

            mode, unit = _systemd_parse_path(logfile)

            reader = JournalReader()
            try:
                reader.open(mode)

                if seek_end:
                    reader.seek_tail()

                rule: Optional[Rule] = None

                if unit is not None:
                    rule = Rule('_SYSTEMD_UNIT', unit)

                if match_dict:
                    for rule_key, rule_value in match_dict.items():
                        new_rule = Rule(rule_key, str(rule_value))
                        if rule is None:
                            rule = new_rule
                        else:
                            rule &= new_rule

                if priority is not None:
                    # TODO: is this really the way?
                    int_priority: int = priority.value
                    prule = Rule('PRIORITY', str(int_priority))
                    int_priority -= 1
                    while int_priority > 0:
                        prule |= Rule('PRIORITY', str(int_priority))
                        int_priority -= 1

                    if rule is None:
                        rule = prule
                    else:
                        rule &= prule

                if rule is not None:
                    reader.add_filter(rule)

                poller = poll()
                if stopfd is not None:
                    poller.register(stopfd, POLLIN)
                poller.register(reader.fd, reader.events)

                while _running:
                    events = poller.poll()
                    if not events:
                        continue

                    if any(fd == stopfd for fd, _event in events):
                        break

                    start_ts = monotonic()
                    entries = list(reader)
                    duration = monotonic() - start_ts

                    try:
                        while len(entries) < max_entries and duration < wait_before_send:
                            rem_time = wait_before_send - duration
                            logger.debug(f'{logfile}: Waiting for {rem_time} seconds to gather more messages')
                            reader.wait(rem_time)
                            entries.extend(reader)
                            duration = monotonic() - start_ts

                    except KeyboardInterrupt:
                        _keyboard_interrupt()

                    str_entries: list[str] = [json.dumps(entry.data, indent=4) for entry in entries]

                    if str_entries:
                        try:
                            brief = entries[0].data.get('MESSAGE')

                            if limits.check():
                                email_sender.send_email(
                                    logfile = logfile,
                                    entries = str_entries,
                                    brief = brief,
                                )
                            elif logger.isEnabledFor(logging.DEBUG):
                                if not brief:
                                    first_entry = str_entries[0]
                                    brief = first_entry.split('\n', 1)[0].lstrip().rstrip(' \r\n\t:{')
                                logger.debug(f'{logfile}: Email with {len(str_entries)} entries was rate limited: {brief}')

                        except Exception as exc:
                            logger.error(f'{logfile}: Error sending email: {exc}', exc_info=exc)

            except KeyboardInterrupt:
                _keyboard_interrupt()

            # There seems to be no way to manually close the reader.
            # It happens only in __dealloc__().

    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

    OPEN_MODES = {
        'LOCAL_ONLY': 1, 'RUNTIME_ONLY': 2, 'SYSTEM': 4, 'CURRENT_USER': 8,
    }

    def _logmon_systemd(
        logfile: str,
        config: Config,
        limits: LimitsService,
        stopfd: Optional[int] = None,
    ) -> None:
        raise NotImplementedError(f'{logfile}: Reading SystemD journals requires the `cysystemd` package!')

def _systemd_parse_path(logfile: str) -> tuple["JournalOpenMode", Optional[str]]:
    path = logfile.split(':')
    if len(path) < 2 or len(path) > 3 or path[0] != 'systemd':
        raise ValueError(f'Illegal SystemD path: {logfile!r}')

    mode = OPEN_MODES.get(path[1])
    if mode is None:
        raise ValueError(f'Illegal open mode in SystemD path: {logfile!r}')

    unit = path[2] or None if len(path) > 2 else None

    return mode, unit

def make_abs_logfile(logfile: str, context_dir: str) -> str:
    if _is_systemd_path(logfile):
        return logfile

    if logfile.startswith('file:'):
        logfile = logfile[5:]

    return joinpath(context_dir, logfile)

def _keyboard_interrupt() -> None:
    global _running
    if _running:
        logger.info("Shutting down on SIGINT...")
        _running = False

def _logmon_thread(logfile: str, config: Config, limits: LimitsService, stopfd: Optional[int] = None) -> None:
    logfile = normpath(abspath(logfile)) if not _is_systemd_path(logfile) else logfile
    wait_after_crash = config.get('wait_after_crash', DEFAULT_WAIT_AFTER_CRASH)

    while _running:
        try:
            _logmon(
                logfile = logfile,
                config = config,
                limits = limits,
                stopfd = stopfd,
            )
        except KeyboardInterrupt:
            _keyboard_interrupt()
            break
        except Exception as exc:
            logger.error(f"{logfile}: Restarting after crash: {exc}", exc_info=exc)
            logger.debug(f"{logfile}: Waiting for {wait_after_crash} seconds after crash")
            sleep(wait_after_crash)
        else:
            break

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

    limits = LimitsService.from_config(config.get('limits') or {})

    threads: list[threading.Thread] = []
    read_stopfd:  Optional[int] = None
    write_stopfd: Optional[int] = None

    try:
        items = logfiles.items() if isinstance(logfiles, dict) else [(logfile, {}) for logfile in logfiles]
        for logfile, cfg in items:
            cfg = {
                **base_config,
                **cfg
            }

            if read_stopfd is None and _needs_stopfd(logfile):
                read_stopfd, write_stopfd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

            thread = threading.Thread(
                target = _logmon_thread,
                args = (logfile, cfg, limits, read_stopfd),
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

        if not _running and write_stopfd is not None:
            try:
                os.write(write_stopfd, b'\0')
            except Exception as exc:
                logger.warning(f"Error signaling stop through write_stopfd: {write_stopfd}")

            try:
                os.close(write_stopfd)
            except Exception as exc:
                logger.warning(f"Error closing write_stopfd: {write_stopfd}")

            write_stopfd = None

            if read_stopfd is not None:
                try:
                    os.close(read_stopfd)
                except Exception as exc:
                    logger.warning(f"Error closing read_stopfd: {read_stopfd}")

                read_stopfd = None

    if write_stopfd is not None:
        try:
            os.close(write_stopfd)
        except Exception as exc:
            logger.warning(f"Error closing write_stopfd: {write_stopfd}")

    if read_stopfd is not None:
        try:
            os.close(read_stopfd)
        except Exception as exc:
            logger.warning(f"Error closing read_stopfd: {read_stopfd}")

def _is_systemd_path(logfile: str) -> bool:
    return logfile.startswith('systemd:')

_needs_stopfd = _is_systemd_path

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

def main(argv: Optional[list[str]] = None) -> None:
    from pathlib import Path
    import argparse
    import signal

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

    is_root = os.getpid() == 0
    esc_config_path = '$HOME/.logmonrc'.replace('%', '%%')
    esc_root_config_path = ROOT_CONFIG_PATH.replace('%', '%%')
    esc_default_config_path = esc_config_path if not is_root else esc_root_config_path
    esc_default_subject = DEFAULT_SUBJECT.replace('%', '%%')
    esc_default_body = DEFAULT_BODY.replace('%', '%%')
    esc_default_entry_start_pattern = DEFAULT_ENTRY_START_PATTERN.pattern.replace('%', '%%')
    esc_default_error_pattern = DEFAULT_ERROR_PATTERN.pattern.replace('%', '%%')
    esc_default_log_format = DEFAULT_LOG_FORMAT.replace('%', '%%')
    esc_default_log_datefmt = DEFAULT_LOG_DATEFMT.replace('%', '%%')
    esc_default_logmails = DEFAULT_LOGMAILS.replace('%', '%%')

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
               '      logmails: onerror\n'
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
              f'      use_inotify: true\n'
              f'      seek_end: true\n'
               '    limits:\n'
              f'      max_emails_per_minute: {DEFAULT_MAX_EMAILS_PER_MINUTE}\n'
              f'      max_emails_per_hour: {DEFAULT_MAX_EMAILS_PER_HOUR}\n'
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
               '        subject: "[SERVICE 3] {brief}"\n'
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
               'This program comes with ABSOLUTELY NO WARRANTY.\n'
    )
    try:
        # don't like the default texts
        ap._optionals.title = 'Options'
        ap._positionals.title = 'Positional Arguments'
    except: pass

    ap.add_argument('-v', '--version', default=False, action='store_true',
        help='Print version and exit.')
    ap.add_argument('--license', default=False, action='store_true',
        help='Show license information and exit.')
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
             '  {brief} ...... Like {line1}, but with the entry start pattern removed.\n'
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
    ap.add_argument('--json', action='store_true', default=None)
    ap.add_argument('--no-json', action='store_false', dest='json')
    ap.add_argument('--json-match', action='append', metavar='PATH=VALUE')
    ap.add_argument('--systemd-priority', default=None, choices=get_args(SystemDPriority))
    ap.add_argument('--systemd-match', action='append', metavar='KEY=VALUE')
    ap.add_argument('--email-host', default=None, metavar='HOST')
    ap.add_argument('--email-port', type=positive(int), default=None, metavar='PORT')
    ap.add_argument('--email-user', default=None, metavar='USER')
    ap.add_argument('--email-password', default=None, metavar='PASSWORD')
    ap.add_argument('--email-secure', default=None, choices=[str(arg) for arg in get_args(SecureOption)])
    ap.add_argument('--email-protocol', default=None, choices=list(get_args(EmailProtocol)))
    ap.add_argument('--http-method', default=None)
    ap.add_argument('--http-path', default=None)
    ap.add_argument('--http-content-type', default=None, choices=list(get_args(ContentType)))
    ap.add_argument('-P', '--http-param', action='append', default=[])
    ap.add_argument('-H', '--http-header', action='append', default=[])
    ap.add_argument('--keep-connected', action='store_true', default=None)
    ap.add_argument('--no-keep-connected', action='store_false', dest='keep_connected')
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
    ap.add_argument('--logmails', default=None, choices=list(get_args(Logmails)),
        help='Log emails.\n'
             '\n'
             'never ..... Never log emails\n'
             'always .... Always log emails\n'
             'onerror ... Log emails if sending failed\n'
             'instead ... Log emails instead of sending them. Useful for debugging.\n'
             '\n'
            f'[default: {esc_default_logmails}]')
    ap.add_argument('logfiles', nargs='*', default=[],
        help='Overwrite the logfiles form the settings. If the given logfile is also configured in the '
             'settings it still uses the logfile specific settings for the given logfile.')
    args = ap.parse_args(argv)

    if args.version:
        print(__version__)
        return

    if args.license:
        assert __doc__
        print(__doc__.strip())
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

    limits_config = config.get('limits')
    if limits_config is None:
        limits_config = config['limits'] = {}

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

    if args.http_method is not None:
        email_config['http_method'] = args.http_method

    if args.http_path is not None:
        email_config['http_path'] = args.http_path

    if args.http_content_type is not None:
        email_config['http_content_type'] = args.http_content_type

    if args.http_param:
        http_params: dict[str, str] = {}
        try:
            for param in args.http_param:
                key, value = param.split('=', 1)
                http_params[key] = value
        except ValueError:
            print(f'Illegal value for --http-param: {args.http_param}', file=sys.stderr)
            sys.exit(1)
        email_config['http_params'] = http_params

    if args.http_header:
        http_headers: dict[str, str] = {}
        try:
            for header in args.http_header:
                key, value = header.split(':', 1)
                http_headers[key] = value.strip()
        except ValueError:
            print(f'Illegal value for --http-header: {args.http_param}', file=sys.stderr)
            sys.exit(1)
        email_config['http_headers'] = http_headers

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
        limits_config['max_emails_per_minute'] = args.max_emails_per_minute

    if args.max_emails_per_hour is not None:
        limits_config['max_emails_per_hour'] = args.max_emails_per_hour

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

    if args.keep_connected is not None:
        default_config['keep_connected'] = args.keep_connected

    if args.json is not None:
        default_config['json'] = args.json

    if args.json_match is not None:
        json_match: JsonMatch = {}
        json_match_item: str
        for json_match_item in args.json_match:
            json_path, json_value = parse_json_match(json_match_item)

            json_ctx = json_match
            for key in json_path[:-1]:
                if key not in json_ctx:
                    next_ctx = {}
                    json_ctx[key] = next_ctx
                else:
                    next_ctx = json_ctx[key]
                    if not isinstance(next_ctx, dict):
                        raise ValueError(f'--json-match="{json_match_item}" conflict: item already exists and is of type {type(next_ctx).__name__} (expected dict)')
                json_ctx = next_ctx

            key = json_path[-1]
            if key in json_ctx:
                raise ValueError(f'--json-match="{json_match_item}" conflict: item already exists')
            json_ctx[key] = json_value
        default_config['json_match'] = json_match

    if args.systemd_priority is not None:
        default_config['systemd_priority'] = args.systemd_priority

    if args.systemd_match is not None:
        systemd_match: dict[str, str] = {}
        systemd_match_item: str
        for systemd_match_item in args.systemd_match:
            try:
                key, value = systemd_match_item.split('=', 1)
            except ValueError:
                print(f'Illegal argument for --systemd-match option: {systemd_match_item}', file=sys.stderr)
                sys.exit(1)
        default_config['systemd_match'] = systemd_match

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
    abslogfiles: dict[str, PartialConfig] = {}
    if isinstance(logfiles, dict):
        for logfile, cfg in logfiles.items():
            if Inotify is None and cfg.get('use_inotify'):
                _print_no_inotify()
                sys.exit(1)
            abslogfiles[make_abs_logfile(logfile, context_dir)] = cfg
    else:
        for logfile in logfiles:
            abslogfiles[make_abs_logfile(logfile, context_dir)] = {}
    app_config['logfiles'] = abslogfiles

    has_systemd = False
    for logfile in abslogfiles:
        if _is_systemd_path(logfile):
            _systemd_parse_path(logfile)
            has_systemd = True

    if has_systemd and not HAS_SYSTEMD:
        _print_no_systemd()
        sys.exit(1)

    log_config = app_config.get('log') or {}
    loglevel_name = args.log_level   if args.log_level   is not None else log_config.get('level', 'INFO')
    app_logfile   = args.log_file    if args.log_file    is not None else log_config.get('file')
    logformat     = args.log_format  if args.log_format  is not None else log_config.get('format',  DEFAULT_LOG_FORMAT)
    logdatefmt    = args.log_datefmt if args.log_datefmt is not None else log_config.get('datefmt', DEFAULT_LOG_DATEFMT)

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
    #signal.signal(signal.SIGINT, on_signal)

    SIGBREAK: Optional[int] = getattr(signal, 'SIGBREAK', None)
    if SIGBREAK is not None:
        signal.signal(SIGBREAK, on_signal)

    if len(abslogfiles) == 1:
        logfile, cfg = next(iter(abslogfiles.items()))
        cfg = {
            **email_config,
            **default_config,
            **cfg
        }
        limits = LimitsService.from_config(app_config.get('limits') or {})

        _logmon_thread(logfile, cfg, limits) # type: ignore
    else:
        logmon_mt(app_config)

def _print_no_inotify() -> None:
    print('Inotify support requires the `inotify` Python package to be installed!', file=sys.stderr)

def _print_no_systemd() -> None:
    print('SystemD support requires the `cysystemd` Python package to be installed!', file=sys.stderr)

if __name__ == '__main__':
    main()
