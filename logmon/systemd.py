from typing import Optional, Mapping

import re
import logging

from select import poll, POLLIN
from time import monotonic
from .constants import *
from .global_state import is_running, get_read_stopfd
from .cleanup_brief import cleanup_brief
from .schema import Config
from .limiter import Limiter
from .actions import Action
from .global_state import handle_keyboard_interrupt
from .entry_readers import LogEntry
from .types import SystemDSelector

__all__ = (
    'logmon_systemd',
    'parse_systemd_path',
    'is_systemd_path',
    'HAS_SYSTEMD',
)

logger = logging.getLogger(__name__)

try:
    from cysystemd.reader import JournalReader, JournalOpenMode, Rule # type: ignore
    from cysystemd.journal import Priority

    # HACK: The `JournalOpenMode._missing_()` method is wrong!
    #       It wrongly disallows any ORed values in an attempt to add backward
    #       compatibility for the SD_JOURNAL_SYSTEM_ONLY value, which is defined
    #       to be the same as SD_JOURNAL_SYSTEM anyway. So it does nothing
    #       except breaking valid usage.
    try:
        del JournalOpenMode._missing_
    except AttributeError as exc:
        pass

    def logmon_systemd(
        logfile: str,
        config: Config,
        limiter: Limiter,
    ) -> None:
        wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
        max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)

        output_indent = config.get('output_indent', DEFAULT_OUTPUT_INDENT) or None
        output_format = config.get('output_format', DEFAULT_OUTPUT_FORMAT)

        # TODO: respect max_entry_lines? break the JSON?
        # max_entry_lines = config.get('max_entry_lines', DEFAULT_MAX_ENTRY_LINES)

        with Action.open_actions(config) as actions:
            seek_end = config.get('seek_end', True)
            raw_priority = config.get('systemd_priority')
            match_dict = config.get('systemd_match')
            ignore_raw = config.get('systemd_ignore')
            ignore_dict = {
                rule_key: str(rule_value)
                for rule_key, rule_value in ignore_raw.items()
            } if ignore_raw else None

            priority: Optional[Priority]
            if isinstance(raw_priority, str):
                priority = Priority[raw_priority]
            elif raw_priority is not None:
                priority = Priority(raw_priority)
            else:
                priority = None

            mode, selector = parse_systemd_path(logfile)

            reader = JournalReader()
            try:
                reader.open(mode)

                if seek_end:
                    reader.seek_tail()

                rule: Optional[Rule] = None

                match selector:
                    case ('UNIT', ident):
                        rule = Rule('_SYSTEMD_UNIT', ident)

                    case ('SYSLOG', ident):
                        rule = Rule('SYSLOG_IDENTIFIER', ident)

                if match_dict:
                    for rule_key, rule_value in match_dict.items():
                        new_rule = Rule(rule_key, str(rule_value))
                        if rule is None:
                            rule = new_rule
                        else:
                            rule &= new_rule

                if priority is not None:
                    int_priority: int = priority.value
                    prule = Rule('PRIORITY', str(int_priority))
                    int_priority -= 1
                    while int_priority > 0:
                        prule |= Rule('PRIORITY', str(int_priority))
                        int_priority -= 1

                    reader.add_filter(prule)

                if rule is not None:
                    reader.add_filter(rule)

                poller = poll()
                stopfd = get_read_stopfd()
                if stopfd is not None:
                    poller.register(stopfd, POLLIN)
                poller.register(reader.fd, reader.events)

                while is_running():
                    events = poller.poll()
                    if not events:
                        continue

                    if any(fd == stopfd for fd, _event in events):
                        break

                    start_ts = monotonic()
                    systemd_entries = [
                        systemd_entry
                        for systemd_entry in reader
                        if not systemd_match(ignore_dict, systemd_entry.data)
                    ] if ignore_dict else list(reader)
                    duration = monotonic() - start_ts

                    try:
                        while len(systemd_entries) < max_entries and duration < wait_before_send:
                            rem_time = wait_before_send - duration
                            logger.debug(f'{logfile}: Waiting for {rem_time} seconds to gather more messages')
                            reader.wait(rem_time)
                            systemd_entries.extend(reader)
                            duration = monotonic() - start_ts

                    except KeyboardInterrupt:
                        handle_keyboard_interrupt()

                    entries: list[LogEntry] = []

                    for systemd_entry in systemd_entries:
                        brief = systemd_entry.data.get('MESSAGE') or systemd_entry.data.get('SYSLOG_RAW') or ''
                        brief = cleanup_brief(brief)

                        entries.append(LogEntry(
                            data = systemd_entry.data,
                            brief = brief,
                        ))

                    if entries:
                        for offset in range(0, len(entries), max_entries):
                            try:
                                chunk = entries[offset:offset + max_entries]
                                brief = chunk[0].brief

                                for action in actions:
                                    if limiter.check():
                                        action.perform_action(
                                            logfile = logfile,
                                            entries = chunk,
                                            brief = brief,
                                        )
                                    elif logger.isEnabledFor(logging.DEBUG):
                                        logger.debug(f'{logfile}: Action with {len(chunk)} entries was rate limited: {brief}')

                            except Exception as exc:
                                logger.error(f'{logfile}: Error performing action: {exc}', exc_info=exc)

            except KeyboardInterrupt:
                handle_keyboard_interrupt()

            # There seems to be no way to manually close the reader.
            # It happens only in __dealloc__().

    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

    from enum import IntFlag

    class JournalOpenMode(IntFlag): # type: ignore
        LOCAL_ONLY   = 1 << 0
        RUNTIME_ONLY = 1 << 1
        SYSTEM       = 1 << 2
        CURRENT_USER = 1 << 3

    def logmon_systemd(
        logfile: str,
        config: Config,
        limiter: Limiter,
    ) -> None:
        raise NotImplementedError(f'{logfile}: Reading SystemD journals requires the `cysystemd` package!')

OPEN_MODES: dict[str, JournalOpenMode] = { # type: ignore
    mode.name: mode
    for mode in JournalOpenMode
}

SYSTEMD_PATH_PREFIX = re.compile(r'^systemd:', re.I)
SYSTEMD_PATH_PREFIX_match = SYSTEMD_PATH_PREFIX.match

def is_systemd_path(logfile: str) -> bool:
    return SYSTEMD_PATH_PREFIX_match(logfile) is not None

def parse_systemd_path(logfile: str) -> tuple["JournalOpenMode", Optional[tuple[SystemDSelector, str]]]:
    path = logfile.split(':')
    if path[0].lower() != 'systemd' or len(path) not in (2, 4):
        raise ValueError(f'Illegal SystemD path: {logfile!r}')

    flags_str = path[1]
    flags = 0
    if flags_str:
        for flag_str in flags_str.split('+'):
            mode = OPEN_MODES.get(flag_str.upper())
            if mode is None:
                raise ValueError(f'Illegal open mode {flag_str!r} in SystemD path: {logfile!r}')
            flags |= mode.value

    mode = JournalOpenMode(flags)

    if len(path) == 4:
        what_raw = path[2].upper()
        if what_raw not in ('UNIT', 'SYSLOG'):
            raise ValueError(f'Illegal selector in SystemD path: {logfile!r}')

        what: SystemDSelector = what_raw # type: ignore
        ident = path[3]

        return mode, (what, ident)

    return mode, None

def systemd_match(match_dict: Mapping[str, str], data: Mapping[str, str]) -> bool:
    for match_key, match_value in match_dict.items():
        if data.get(match_key) != match_value:
            return False
    return True

if __name__ == '__main__':
    import sys

    for arg in sys.argv[1:]:
        try:
            print(arg, is_systemd_path(arg), parse_systemd_path(arg))
        except Exception as exc:
            print(arg, exc, file=sys.stderr)
