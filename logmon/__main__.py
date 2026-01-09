#!/usr/bin/env python3

"""\
logmon - Monitor log files and send emails or run actions if errors are detected

Copyright (c) 2025-2026  Mathias Panzenböck

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

from typing import Any, Callable, Optional, TypeVar, Literal, get_args

import re
import os
import sys
import json
import shlex
import signal
import logging
import pydantic

from os.path import abspath, join as joinpath, dirname
from urllib.parse import unquote_plus
from datetime import timedelta

from .schema import Config, ConfigFile, LogmonConfig, FILE_MODE_PATTERN
from .yaml import HAS_YAML, yaml_load, yaml_dump
from .inotify import HAS_INOTIFY
from .json_match import parse_json_path
from .types import *
from .constants import *
from .systemd import HAS_SYSTEMD, is_systemd_path, parse_systemd_path
from .global_state import handle_stop_signal
from .json_match import JsonMatch, parse_json_match
from .limits_service import LimitsService
from .logmon import logmon_mt, _logmon_thread

ACTIONS: set[ActionType] = set(get_args(ActionType.__value__))

type Num = int|float

parse_timedelta = pydantic.TypeAdapter(timedelta).validate_python

def parse_optional_timedelta(value: Any) -> Optional[timedelta]:
    if not value:
        return None

    return parse_timedelta(value)

def in_range(parse: Callable[[str], Num], min: Optional[Num] = None, max: Optional[Num] = None) -> Callable[[str], Num]:
    def parse_in_range(value: str) -> Num:
        num = parse(value)
        if min is not None and num < min:
            raise ValueError(f'value may not be less than {min} but was {num}')
        if max is not None and num > max:
            raise ValueError(f'value may not be greater than {max} but was {num}')
        return num
    parse_in_range.__name__ = f'in_range({parse.__name__}, {min!r}, {max!r})'
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
    parse_positive.__name__ = f'positive({parse.__name__})'
    return parse_positive

T = TypeVar('T')

def optional(parse: Callable[[str], T], *none_values: str) -> Callable[[str], Optional[T]]:
    def parse_optional(value: str) -> Optional[T]:
        if not value.strip() or value in none_values:
            return None
        return parse(value)
    fmt_args = ''.join(f", {val!r}" for val in none_values)
    parse_optional.__name__ = f'optional({parse.__name__}{fmt_args})'
    return parse_optional

T1 = TypeVar('T1')
T2 = TypeVar('T2')

def either(parse1: Callable[[str], T1], parse2: Callable[[str], T2]) -> Callable[[str], T1|T2]:
    def parse_either(value: str) -> T1|T2:
        try:
            return parse1(value)
        except:
            return parse2(value)
    parse_either.__name__ = f'either({parse1.__name__}, {parse2.__name__})'
    return parse_either

S = TypeVar('S', bound=str)

def literal(expected: S) -> Callable[[str], S]:
    def parse_literal(actual: str) -> S:
        if actual != expected:
            raise ValueError(f'expected: {expected!r}, actual: {actual!r}')
        return expected
    parse_literal.__name__ = f'literal({expected!r})'
    return parse_literal

def _parse_comma_list(value: str) -> list[str]:
    result: list[str] = []
    for item in value.split(','):
        item = item.strip()
        if item:
            result.append(item)
    return result

def make_abs_logfile(logfile: str, context_dir: str) -> str:
    if is_systemd_path(logfile):
        return logfile

    if logfile.startswith('file:'):
        logfile = logfile[5:]

    return joinpath(context_dir, logfile)

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

URL_PATTERN = re.compile(r'^(:?(?P<iscommand>command|cmd)(?::(?P<command>.*))?|(?P<file_prot>file|fifo)(?::(?P<file>.*))?|(?P<prot>[-_a-z0-9]+)(?::(?://)?(?:(?P<user>[^:/\\@?#\[\]&\s]*)(?::(?P<password>[^:/\\@?#\[\]&\s]*))?@)?(?P<host>[-_.a-z0-9]+|\[(?P<ipv6>[:0-9a-f]+)\])(?::(?P<port>[0-9]+))?(?P<path>/[^\s#?&]*)?(?:\?(?P<query>[^\s#]*))?)?)$', re.I)

def parse_action(cfg: dict[str, Any]) -> None:
    action = cfg.get('action')
    if action is None:
        return

    if not isinstance(action, str):
        raise TypeError(f'illegal action type: {action!r} ({type(action).__name__})')

    m = URL_PATTERN.match(action)
    if m is None:
        raise ValueError(f'illegal action: {action!r}')

    if m.group('iscommand'):
        cfg['action'] = 'COMMAND'

        command: Optional[str] = m.group('command')
        if command:
            cfg['command'] = shlex.split(command)

        return

    file_prot = m.group('file_prot')
    if file_prot:
        cfg['action'] = 'FILE'

        if file_prot.lower() == 'fifo':
            cfg['file_type'] = 'fifo'

        file_path = m.group('file')
        if file_path:
            cfg['file'] = file_path

        return

    prot: str = m.group('prot').upper()
    user: Optional[str] = m.group('user')
    password: Optional[str] = m.group('password')
    host: Optional[str] = m.group('host') # TODO: do we need to use this?: m.group('ipv6') or m.group('host')
    port_str: Optional[str] = m.group('port')
    port: Optional[int] = int(port_str, 10) if port_str is not None else None
    path: Optional[str] = m.group('path')
    query: Optional[str] = m.group('query')

    if prot not in ACTIONS:
        raise ValueError(f'illegal action: {action!r}')

    cfg['action'] = prot # type: ignore

    if user is not None:
        cfg['user'] = unquote_plus(user)

    if password is not None:
        cfg['password'] = unquote_plus(password)

    if host is not None:
        cfg['host'] = host

    if port is not None:
        cfg['port'] = port

    if prot in ('HTTP', 'HTTPS'):
        if path is not None:
            cfg['http_path'] = path

        if query is not None:
            cfg['http_params'] = parse_query(query)
    else:
        if path:
            logging.warning(f'Non-HTTP(S) URLs may not have a path component: {action!r}')

        if query:
            if prot in ('SMTP', 'IMAP'):
                params = parse_query(query)

                sender = params.pop('sender', None)
                receivers_str = params.pop('receivers', None)
                secure = params.pop('secure', None)

                if params:
                    raise ValueError(f'Unsupported parameters ({", ".join(params.keys())}) in action: {action!r}')

                if sender:
                    cfg['sender'] = sender

                if receivers_str:
                    cfg['receivers'] = [receiver.strip() for receiver in receivers_str.split(',')]

                if secure:
                    match secure.upper():
                        case 'STARTTLS':
                            cfg['email_secure'] = 'STARTTLS'

                        case 'SSL/TLS':
                            cfg['email_secure'] = 'SSL/TLS'

                        case 'NONE' | '':
                            cfg['email_secure'] = None

                        case _:
                            raise ValueError(f'Illegal value for secure parameter in action: {action!r}')

            else:
                logging.warning(f'Non-HTTP(S) URLs may not have a query component: {action!r}')

def parse_query(query: str) -> dict[str, str]:
    parsed: dict[str, str] = {}

    if query:
        for item in query.split('&'):
            pair = item.split('=', 1)
            key = unquote_plus(pair[0])
            value = unquote_plus(pair[1]) if len(pair) == 2 else ''
            parsed[key] = value

    return parsed

def main(argv: Optional[list[str]] = None) -> None:
    from pathlib import Path
    import argparse

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
               '    do:\n'
               '      action: SMTP # same syntax as --action\n'
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
               "      # json: true means the log file contains a JSON document per line.\n"
               "      json: false\n"
               "      json_match:\n"
               "        # operators: =, !=, <, >, <=, >=, in, not in\n"
               "        # in and not in can either have an array of values as the argument\n"
               '        # or an object in the form of: {"start": 0, "stop": 10} (int only)\n'
               "        level: ['in', ['ERROR', 'CRITICAL']]\n"
               "        some:\n"
               "          nested:\n"
               "            field: ['=', 12]\n"
               "        a_list:\n"
               "          15: ['>=', 123]\n"
               "      json_ignore:\n"
               "        message: ['~', '(?i)test']\n"
               "      json_brief: ['message']\n"
               "      output_indent: 4\n"
               "      output_format: YAML # or JSON\n"
               "      systemd_priority: ERROR\n"
               "      systemd_match:\n"
               "        _SYSTEMD_USER_UNIT: plasma-kwin_x11.service\n"
               '      command: ["/usr/local/bin/my_command", "{sender}", "{receivers}", "{...entries}"]\n'
               '      command_user: myuser\n'
               '      command_group: mygroup\n'
               '      command_stdin: "null:" # or file:..., inherit:, pipe:FORMAT\n'
               '      command_stdout: "null:" # or file:..., append:..., inherit:\n'
               '      command_stderr: "null:" # or file:..., append:..., inherit:, stdout:\n'
               '      command_interactive: True\n'
               '      command_timeout: 3.5 # or None\n'
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
               'Copyright (c) 2025-2026 Mathias Panzenböck\n'
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
    non_command_actions = set(action.lower() for action in ACTIONS)
    non_command_actions.remove('command')
    ap.add_argument('-A', '--action', default=None,
        metavar=f"{{{{{','.join(sorted(non_command_actions))}}}[:[//][<user>[:<password>]@]<host>[:<port>][/<path>[?<query>]]],command[:<command> [<option>...]],file:<path>}}",
        help='Parameters defined here overwrite values passed via other options.\n'
             '\n'
             'For SMTP and IMAP these query parameters are supported:\n'
             '  sender ...... same as --sender\n'
             '  receivers ... same as --receivers\n'
             '  secure ...... same as --email-secure\n'
             '\n'
             f'[default: {DEFAULT_ACTION}]')
    ap.add_argument('--sender', default=None, metavar='EMAIL',
        help=f'[default: {DEFAULT_EMAIL_SENDER}@<host>]')
    ap.add_argument('--receivers', default=None, metavar='EMAIL,...',
        help='Comma separated list of email addresses.\n'
             '[default: <sender>]')
    ap.add_argument('--subject', default=None, metavar='TEMPLATE',
        help=f'Subject template for the emails. See --body for the template variables. [default: {esc_default_subject!r}]')
    ap.add_argument('--body', default=None, metavar='TEMPLATE',
        help='Body template for the emails.\n'
             '\n'
             'Template variables:\n'
             '  {entries} ......... All entries formatted with the --output-format and --output-indent options.\n'
             '  {entries_str} ..... All entries for the message concatenated into a string with two newlines between each.\n'
             '  {entries_raw} ..... Raw entries (list[str] for normal log files or list[dict] for SystemD or JSON log files).\n'
             '  {logfile} ......... The path of the logfile.\n'
             '  {entry1} .......... The first log entry of the message.\n'
             '  {line1} ........... The first line of the first log entry.\n'
             '  {brief} ........... Like {line1}, but with the entry start pattern removed.\n'
             '  {entrynum} ........ The number of entries in this message.\n'
             '  {sender} .......... The sender email address.\n'
             '  {receivers} ....... Comma separated list of receiver email addresses.\n'
             '  {receiver_list} ... List of receiver email addresses (list[str]).\n'
             "  {nl} .............. A newline character ('\\n')\n"
             '  {{ ................ A literal {\n'
             '  }} ................ A literal }\n'
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
        help=f'This is the default if the `inotify` Python package is installed. [default: {HAS_INOTIFY}]')
    inotify_grp.add_argument('--no-use-inotify', default=None, action='store_false', dest='use_inotify',
        help='Opposite of --use-inotify')
    ap.add_argument('--encoding', default=None)
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

    ap.add_argument('--json', action='store_true', default=None,
        help='Every line in the log file is parsed as a JSON document. [default: False]')
    ap.add_argument('--no-json', action='store_false', dest='json',
        help='Opposite of --json')
    ap.add_argument('--json-match', action='append', metavar='PATH=VALUE',
        help='Nested properties of the JSON document to match against.\n'
             '\n'
             'Operators:\n'
             '  = ........ equals\n'
             '  != ....... not equals\n'
             '  < ........ less than\n'
             '  > ........ greater than\n'
             '  <= ....... less than or equal\n'
             '  >= ....... greater than or equal\n'
             '  ~ ........ match regular expression\n'
             '  in ....... value in a list or range of given values\n'
             '  not in ... value not in a list or range of given values\n'
             '\n'
             'The argument to in and not in can be a list like ["foo", "bar"] '
             'or a range definition like {"start": 0, "stop": 10}. Start is '
             'inclusive, stop is exclusive.\n'
             '\n'
             'When multiple --json-match are defined all have to match.\n'
             'Per no filter is defined.')
    ap.add_argument('--json-ignore', action='append', metavar='PATH=VALUE',
        help='Same match syntax as --json-match, but if this matches the log entry is ignored.')
    ap.add_argument('--json-brief', default=None, metavar='PATH',
        help='Path to the JSON field')

    ap.add_argument('--output-indent', type=either(literal('unset'), optional(non_negative(int),'NONE')), default='unset', metavar='WIDTH|NONE',
        help=f'When JSON or YAML data is included in the email indent by this number of spaces. [default: {DEFAULT_OUTPUT_INDENT}]')
    ap.add_argument('--output-format', type=str.upper, choices=get_args(OutputFormat.__value__), default=None,
        help=f'Format structured data in emails using this format. [default: {DEFAULT_OUTPUT_FORMAT}]')

    ap.add_argument('--systemd-priority', default=None, choices=get_args(SystemDPriority.__value__),
        help='Only report log entries of this or higher priority.')
    ap.add_argument('--systemd-match', action='append', metavar='KEY=VALUE')

    ap.add_argument('--host', default=None, metavar='HOST',
        help=f'[default: {DEFAULT_EMAIL_HOST}]')
    ap.add_argument('--port', type=positive(int), default=None, metavar='PORT',
        help='[default: depends on --action and --email-secure]')
    ap.add_argument('--user', default=None, metavar='USER')
    ap.add_argument('--password', default=None, metavar='PASSWORD')
    ap.add_argument('--email-secure', default=None, choices=[str(arg) for arg in get_args(SecureOption.__value__)])

    ap.add_argument('--http-method', default=None, help='[default: GET]')
    ap.add_argument('--http-path', default=None, help='[default: /]')
    ap.add_argument('--http-content-type', default=None, choices=list(get_args(ContentType.__value__)),
        help=f'[default: {DEFAULT_HTTP_CONTENT_TYPE}]')
    ap.add_argument('--http-timeout', type=either(literal('unset'), optional(non_negative(float), 'NONE')), default='unset', metavar='SECONDS|NONE',
        help="[default: no timeout]")
    ap.add_argument('-P', '--http-param', action='append', default=[], metavar='KEY=VALUE',
        help=f'[default: {' '.join(f"{key}={value}" for key, value in DEFAULT_HTTP_PARAMS)}]')
    ap.add_argument('-H', '--http-header', action='append', default=[], metavar='Header:Value')

    ap.add_argument('--oauth2-grant-type', choices=list(get_args(OAuth2GrantType.__value__)),
        help=f'[default: {DEFAULT_OAUTH2_GRANT_TYPE}]')
    ap.add_argument('--oauth2-token-url', default=None)
    ap.add_argument('--oauth2-client-id', default=None)
    ap.add_argument('--oauth2-client-secret', default=None)
    ap.add_argument('--oauth2-scope', default=None)
    ap.add_argument('--oauth2-refresh-margin', type=parse_optional_timedelta, default=None, metavar='#:##:##',
        help='Subtract this time-span from the access token expiration date. [default: 0]')

    ap.add_argument('--command', metavar='''"/path/to/command --sender {sender} --receivers {receivers} -- {...entries}"''',
        help='When --action=COMMAND then run this command. The command is interpolated with the same '
             'format as --body plus an additional special parameter {...entries} wich will repeat that '
             'argument for each entry. E.g. if you have the command "mycommand --entry={...entries}" and '
             'the entries are just "foo" and "bar" the command that will be executed is:\n'
             '\n'
             '    mycommand --entry=foo --entry=bar\n'
             '\n'
             "The command string is parsed as a list of strings with Python's `shlex.split()` before "
             'interpolation takes place and is executed as that list with `Popen(args=command)` and not '
             'with a shell in order pro prevent command injections.')
    ap.add_argument('--command-cwd', metavar='PATH',
        help='Run command in PATH. All other paths are thus relative to this.\n'
             '[default is the current working directory of logmon]')
    ap.add_argument('--command-user', metavar='USER',
        help='Run command as USER.\n'
             '[default is the user of the logmon process]')
    ap.add_argument('--command-group', metavar='GROUP',
        help='Run command as GROUP.\n'
             '[default is the group of the logmon process]')
    ap.add_argument('-E', '--command-env', action='append', default=[], metavar='NAME[=VALUE]',
        help='Replace the environment of the command. Pass this option multiple times for multiple '
             'environment variables. Only pass a NAME in order to copy the value from the environment '
             'of the logmon process.\n'
             '[default is the environment of the logmon process]')
    ap.add_argument('--command-stdin', metavar='{file:/file/path,null:,inherit:,pipe:FORMAT,/absolute/file/path}',
        help='When using "pipe:" the FORMAT is interpolated and written to stdin of the spawned process. '
             'It has the same parameters as the format of --body plus an additional special parameter '
             '{...entries} which will repeat the whole format for each log entry. Meaning if FORMAT is '
             '"before {...entries} after{nl}" and the entries are just "foo" and "bar" then this is '
             'written to stdin:\n'
             '\n'
             '    before foo after\n'
             '    before bar after\n'
             '\n'
             '[default: null:]')
    ap.add_argument('--command-stdout', metavar='{file:/file/path,append:/file/path,null:,inherit:,/absolute/file/path}')
    ap.add_argument('--command-stderr', metavar='{file:/file/path,append:/file/path,null:,stdout:,inherit:,/absolute/file/path}')
    ap.add_argument('--command-interactive', action='store_true', default=None,
        help='Use this when the spawned process is ')
    ap.add_argument('--command-no-interactive', action='store_false', default=None, dest='command_interactive',
        help='Opposite of --command-interactive')
    ap.add_argument('--command-timeout', metavar='SECONDS|NONE', default='unset',
        type=either(literal('unset'), optional(non_negative(float),'NONE')),
        help='Wait SECONDS for process to finish. If the procress is still running on shutdown and '
             'the timeout is exceeded the process will be killed.\n'
             '[default: NONE]')

    ap.add_argument('--file', default=None)
    ap.add_argument('--file-encoding', default=None, metavar='ENCODING',
        help='[default: "UTF-8"]')
    ap.add_argument('--file-append', action='store_true', default=None)
    ap.add_argument('--no-file-append', action='store_false', dest='file_append')
    ap.add_argument('--file-user', metavar='USER', default=None)
    ap.add_argument('--file-group', metavar='GROUP', default=None)
    ap.add_argument('--file-type', choices=list(get_args(FileType.__value__)), default=None)

    def parse_file_mode(value: str|None) -> str|None:
        if not value:
            return None

        if not FILE_MODE_PATTERN.match(value):
            raise ValueError(f'illegal file mode: {value!r}')

        return value

    ap.add_argument('--file-mode', type=parse_file_mode, metavar='MODE',
        help='File mode, e.g.: `rwxr-x---`, `u=rwx,g=rx,o=`, or `0750`.')

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
    ap.add_argument('--logmails', default=None, choices=list(get_args(Logmails.__value__)),
        help='Log emails to the Python logger.\n'
             '\n'
             'never ..... Never log emails\n'
             'always .... Always log emails\n'
             'onerror ... Log emails if sending failed\n'
             'instead ... Log emails instead of sending them. Useful for debugging.\n'
             '\n'
            f'[default: {esc_default_logmails}]')
    ap.add_argument('--config-schema', default=False, action='store_true',
        help="Dump config file schema and exit. Uses --output-format and --output-indent.")
    ap.add_argument('logfiles', nargs='*', default=[],
        help='Overwrite the logfiles form the settings. If the given logfile is also configured in the '
             'settings it still uses the logfile specific settings for the given logfile.\n'
             '\n'
             'You can read from a SystemD journal instead of a file by specifying a path in the form of:\n'
             '\n'
             '    systemd:{LOCAL_ONLY,RUNTIME_ONLY,SYSTEM,CURRENT_USER}[:{UNIT,SYSLOG}:<identifier>]'
    )
    args = ap.parse_args(argv)

    if args.version:
        print(__version__)
        return

    if args.license:
        assert __doc__
        print(__doc__.strip())
        return

    if args.config_schema:
        output_fromat: OutputFormat = args.output_format or DEFAULT_OUTPUT_FORMAT
        output_indent: Optional[int]|Literal['unset'] = args.output_indent
        if output_indent == 'unset':
            output_indent = DEFAULT_OUTPUT_INDENT

        schema = pydantic.TypeAdapter(LogmonConfig).json_schema()

        match output_fromat:
            case 'JSON':
                json.dump(schema, sys.stdout, indent=output_indent)

            case 'YAML':
                print(yaml_dump(schema, indent=output_indent))

            case _:
                raise ValueError(f'illegal output format: {output_fromat}')
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
        if config_path_lower.endswith(('.yml', '.yaml')) or HAS_YAML:
            with open(config_path, 'r') as configfp:
                config = yaml_load(configfp)
        else:
            with open(config_path, 'r') as configfp:
                config = json.load(configfp)

        if config is None:
            config = {}
        elif not isinstance(config, dict):
            print(f"{config_path}: Config file format error", file=sys.stderr)
            sys.exit(1)

    except FileNotFoundError:
        if args.config:
            print(f"{args.config}: File not found", file=sys.stderr)
            sys.exit(1)
        config = { 'logfiles': [] }

    except Exception as exc:
        print(f"{config_path}: Config file format error: {exc}", file=sys.stderr)
        sys.exit(1)

    default_config = config.get('default')
    if default_config is None:
        default_config = config['default'] = {}

    limits_config = config.get('limits')
    if limits_config is None:
        limits_config = config['limits'] = {}

    action_config = config.get('do')
    if action_config is None:
        action_config = config['do'] = {}
    elif not isinstance(action_config, dict):
        print(f"{config_path}: Key 'do' must be a dict", file=sys.stderr)
        sys.exit(1)

    if args.sender is not None:
        action_config['sender'] = args.sender

    if args.receivers is not None:
        action_config['receivers'] = _parse_comma_list(args.receivers)
    else:
        receivers_str = action_config.get('receivers')
        if isinstance(receivers_str, str):
            action_config['receivers'] = _parse_comma_list(receivers_str)
        receiver = action_config.get('receiver')

        if receiver is not None:
            if receivers_str is not None:
                print(f"{config_path}: Only either do.receivers or do.receiver may be set!")
                sys.exit(1)
            action_config['receivers'] = [receiver]

    if args.body is not None:
        action_config['body'] = args.body

    action: Optional[str] = args.action
    if action is not None:
        action_config['action'] = action

    if args.host is not None:
        action_config['host'] = args.host

    if args.port is not None:
        action_config['port'] = args.port

    if args.user is not None:
        action_config['user'] = args.user

    if args.password is not None:
        action_config['password'] = args.password

    if args.email_secure is not None:
        action_config['secure'] = args.email_secure if args.email_secure not in ('', 'None') else None

    if args.http_method is not None:
        action_config['http_method'] = args.http_method

    if args.http_path is not None:
        action_config['http_path'] = args.http_path

    if args.http_content_type is not None:
        action_config['http_content_type'] = args.http_content_type

    if args.http_timeout != 'unset':
        action_config['http_timeout'] = args.http_timeout

    if args.http_param:
        http_params: list[tuple[str, str]] = []
        try:
            for param in args.http_param:
                key, value = param.split('=', 1)
                http_params.append((key, value))
        except ValueError:
            print(f'Illegal value for --http-param: {args.http_param}', file=sys.stderr)
            sys.exit(1)
        action_config['http_params'] = http_params

    if args.http_header:
        http_headers: dict[str, str] = {}
        try:
            for header in args.http_header:
                key, value = header.split(':', 1)
                http_headers[key] = value.strip()
        except ValueError:
            print(f'Illegal value for --http-header: {args.http_param}', file=sys.stderr)
            sys.exit(1)
        action_config['http_headers'] = http_headers

    if args.oauth2_grant_type is not None:
        action_config['oauth2_grant_type'] = args.oauth2_grant_type

    if args.oauth2_token_url is not None:
        action_config['oauth2_token_url'] = args.oauth2_token_url

    if args.oauth2_client_id is not None:
        action_config['oauth2_client_id'] = args.oauth2_client_id

    if args.oauth2_client_secret is not None:
        action_config['oauth2_client_secret'] = args.oauth2_client_secret

    if args.oauth2_scope is not None:
        action_config['oauth2_scope'] = args.oauth2_scope.split()

    if args.oauth2_refresh_margin is not None:
        action_config['oauth2_refresh_margin'] = args.oauth2_refresh_margin

    if args.command is not None:
        action_config['command'] = shlex.split(args.command)

    if args.command_cwd is not None:
        action_config['command_cwd'] = args.command_cwd

    if args.command_user is not None:
        action_config['command_user'] = args.command_user

    if args.command_group is not None:
        action_config['command_group'] = args.command_group

    if args.command_stdin is not None:
        action_config['command_stdin'] = args.command_stdin

    if args.command_stdout is not None:
        action_config['command_stdout'] = args.command_stdout

    if args.command_stderr is not None:
        action_config['command_stderr'] = args.command_stderr

    if args.command_interactive is not None:
        action_config['command_interactive'] = args.command_interactive

    if args.command_env:
        env: dict[str, str] = {}
        var: str
        for var in args.command_env:
            parts = var.split('=', 1)
            env_name = parts[0]
            if len(parts) == 1:
                env_value = os.getenv(env_name)
                if env_value is not None:
                    env[env_name] = env_value
            else:
                env[env_name] = parts[0]
        action_config['command_env'] = env

    if args.command_timeout != 'unset':
        action_config['command_timeout'] = args.command_timeout

    if args.file is not None:
        action_config['file'] = args.file

    if args.file_encoding is not None:
        action_config['file_encoding'] = args.file_encoding

    if args.file_append is not None:
        action_config['file_append'] = args.file_append

    if args.file_user is not None:
        action_config['file_user'] = args.file_user

    if args.file_group is not None:
        action_config['file_group'] = args.file_group

    if args.file_type is not None:
        action_config['file_type'] = args.file_type

    if args.file_mode is not None:
        action_config['file_mode'] = args.file_mode

    if args.logmails is not None:
        action_config['logmails'] = args.logmails

    parse_action(action_config)

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

    if args.encoding is not None:
        default_config['encoding'] = args.encoding

    if args.entry_start_pattern is not None:
        default_config['entry_start_pattern'] = args.entry_start_pattern

    if args.keep_connected is not None:
        default_config['keep_connected'] = args.keep_connected

    if args.json is not None:
        default_config['json'] = args.json

    if args.json_match is not None:
        default_config['json_match'] = _parse_json_match_arg(args.json_match)

    if args.json_ignore is not None:
        default_config['json_ignore'] = _parse_json_match_arg(args.json_ignore)

    if args.json_brief is not None:
        default_config['json_brief'] = parse_json_path(args.json_brief)

    if args.output_indent != 'unset':
        default_config['output_indent'] = args.output_indent

    if args.output_format is not None:
        default_config['output_format'] = args.output_format

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
            for raw_cfg in config_logfiles.values():
                parse_action(raw_cfg)

            config['logfiles'] = { logfile: config_logfiles.get(logfile) or {} for logfile in args.logfiles }
        else:
            config['logfiles'] = args.logfiles
        context_dir = abspath('.')
    else:
        context_dir = dirname(config_path)

    try:
        app_config = ConfigFile(
            config=config # type: ignore
        ).config
    except pydantic.ValidationError as exc:
        print(f"{config_path}: Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    logfiles = app_config['logfiles']

    if not logfiles:
        print('No logfiles configured!', file=sys.stderr)
        sys.exit(1)

    if not HAS_INOTIFY and config.get('use_inotify'):
        _print_no_inotify()
        sys.exit(1)

    # make all paths absolute before daemonize
    abslogfiles: dict[str, Config] = {}
    if isinstance(logfiles, dict):
        for logfile, cfg in logfiles.items():
            if not HAS_INOTIFY and cfg.get('use_inotify'):
                _print_no_inotify()
                sys.exit(1)
            abslogfiles[make_abs_logfile(logfile, context_dir)] = cfg
    else:
        for logfile in logfiles:
            abslogfiles[make_abs_logfile(logfile, context_dir)] = {}
    app_config['logfiles'] = abslogfiles

    if not HAS_YAML:
        if ((app_default := app_config.get('default')) and app_default.get('output_format') == 'YAML') or \
            any(cfg.get('output_format') == 'YAML' for cfg in abslogfiles.values()):
            raise NotImplementedError('Writing YAML files requires the `PyYAML` package.')

    has_systemd = False
    for logfile in abslogfiles:
        if is_systemd_path(logfile):
            parse_systemd_path(logfile)
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

    signal.signal(signal.SIGTERM, handle_stop_signal)
    #signal.signal(signal.SIGINT, handle_stop_signal)

    SIGBREAK: Optional[int] = getattr(signal, 'SIGBREAK', None)
    if SIGBREAK is not None:
        signal.signal(SIGBREAK, handle_stop_signal)

    if len(abslogfiles) == 1:
        logfile, cfg = next(iter(abslogfiles.items()))
        cfg = {
            **action_config,
            **default_config,
            **cfg
        }
        limits = LimitsService.from_config(app_config.get('limits') or {})

        _logmon_thread(
            logfile,
            cfg, # type: ignore
            limits,
        )
    else:
        logmon_mt(app_config)

def _print_no_inotify() -> None:
    print('Inotify support requires the `inotify` Python package to be installed!', file=sys.stderr)

def _print_no_systemd() -> None:
    print('SystemD support requires the `cysystemd` Python package to be installed!', file=sys.stderr)

def _parse_json_match_arg(args: list[str]) -> JsonMatch:
    json_match: JsonMatch = {}
    json_match_item: str
    for json_match_item in args:
        json_path, json_value = parse_json_match(json_match_item)

        json_ctx = json_match
        for key in json_path[:-1]:
            if key not in json_ctx:
                new_ctx: JsonMatch = {}
                json_ctx[key] = new_ctx
                json_ctx = new_ctx
            else:
                next_ctx = json_ctx[key]
                if not isinstance(next_ctx, dict):
                    raise ValueError(f'--json-match="{json_match_item}" conflict: item already exists and is of type {type(next_ctx).__name__} (expected dict)')
                json_ctx = next_ctx

        key = json_path[-1]
        if key in json_ctx:
            raise ValueError(f'--json-match="{json_match_item}" conflict: item already exists')
        json_ctx[key] = json_value

    return json_match

if __name__ == '__main__':
    main()
