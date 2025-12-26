from typing import Optional

import json
import logging

from select import poll, POLLIN
from time import monotonic
from .constants import *
from .yaml import yaml_dump
from .global_state import is_running, get_read_stopfd
from .cleanup_brief import cleanup_brief
from .schema import Config
from .limits_service import LimitsService
from .email_senders import EmailSender
from .global_state import handle_keyboard_interrupt
from .entry_readers import LogEntry

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

    OPEN_MODES: dict[str, JournalOpenMode] = {
        mode.name: mode
        for mode in JournalOpenMode
    }

    def logmon_systemd(
        logfile: str,
        config: Config,
        limits: LimitsService,
    ) -> None:
        wait_before_send = config.get('wait_before_send', DEFAULT_WAIT_BEFORE_SEND)
        max_entries = config.get('max_entries', DEFAULT_MAX_ENTRIES)

        output_indent = config.get('output_indent', DEFAULT_OUTPUT_INDENT)
        output_format = config.get('output_format', DEFAULT_OUTPUT_FORMAT)

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

            mode, unit = parse_systemd_path(logfile)

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
                    systemd_entries = list(reader)
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
                        match output_format:
                            case 'JSON':
                                formatted = json.dumps(systemd_entry.data, indent=output_indent)

                            case 'YAML':
                                formatted = yaml_dump(systemd_entry.data, indent=output_indent)

                            case _:
                                logger.error(f'{logfile}: Illegal output format: {output_format}')
                                formatted = json.dumps(systemd_entry.data, indent=output_indent)

                        brief = systemd_entry.data.get('MESSAGE')

                        if not brief:
                            brief = formatted.split('\n', 1)[0].lstrip().rstrip(' \r\n\t:{')

                        brief = cleanup_brief(brief)

                        entries.append(LogEntry(
                            data = systemd_entry.data,
                            brief = brief,
                            formatted = formatted,
                        ))

                    if systemd_entries:
                        try:
                            brief = entries[0].brief

                            if limits.check():
                                email_sender.send_email(
                                    logfile = logfile,
                                    entries = entries,
                                    brief = brief,
                                )
                            elif logger.isEnabledFor(logging.DEBUG):
                                logger.debug(f'{logfile}: Email with {len(entries)} entries was rate limited: {brief}')

                        except Exception as exc:
                            logger.error(f'{logfile}: Error sending email: {exc}', exc_info=exc)

            except KeyboardInterrupt:
                handle_keyboard_interrupt()

            # There seems to be no way to manually close the reader.
            # It happens only in __dealloc__().

    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

    OPEN_MODES = {
        'LOCAL_ONLY': 1, 'RUNTIME_ONLY': 2, 'SYSTEM': 4, 'CURRENT_USER': 8,
    }

    def logmon_systemd(
        logfile: str,
        config: Config,
        limits: LimitsService,
    ) -> None:
        raise NotImplementedError(f'{logfile}: Reading SystemD journals requires the `cysystemd` package!')

def is_systemd_path(logfile: str) -> bool:
    return logfile.startswith('systemd:')

def parse_systemd_path(logfile: str) -> tuple["JournalOpenMode", Optional[str]]:
    path = logfile.split(':')
    if len(path) < 2 or len(path) > 3 or path[0] != 'systemd':
        raise ValueError(f'Illegal SystemD path: {logfile!r}')

    mode = OPEN_MODES.get(path[1])
    if mode is None:
        raise ValueError(f'Illegal open mode in SystemD path: {logfile!r}')

    unit = path[2] or None if len(path) > 2 else None

    return mode, unit
