from typing import Pattern, Optional, TextIO, Generator, override

import re
import logging

from time import sleep
from ..constants import *
from ..schema import Config
from ..global_state import is_running
from .entry_reader_factory import EntryReaderFactory, LogEntry

logger = logging.getLogger(__name__)

class TextEntryReaderFactory(EntryReaderFactory):
    __slots__ = (
        'entry_start_pattern',
        'error_pattern',
        'ignore_pattern',
        'wait_line_incomplete',
        'max_entry_lines',
    )
    entry_start_pattern: Pattern[str]
    error_pattern: Pattern[str]
    ignore_pattern: Optional[Pattern[str]]
    wait_line_incomplete: int|float
    max_entry_lines: int

    def __init__(self, config: Config) -> None:
        super().__init__()

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
        max_entry_lines = config.get('max_entry_lines', DEFAULT_MAX_ENTRY_LINES)

        self.entry_start_pattern = entry_start_pattern
        self.error_pattern = error_pattern
        self.ignore_pattern = ignore_pattern
        self.wait_line_incomplete = wait_line_incomplete
        self.max_entry_lines = max_entry_lines

    @override
    def create_reader(self, logfile: TextIO) -> Generator[Optional[LogEntry], None, None]:
        buf: list[str] = []
        next_line: Optional[str] = None

        while is_running():
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
                sleep(self.wait_line_incomplete)
                buf.append(logfile.readline())

            line_count = 1
            entry_start_pattern = self.entry_start_pattern
            while line_count < self.max_entry_lines:
                line = logfile.readline()

                if not line:
                    break

                if not line.endswith('\n'):
                    sleep(self.wait_line_incomplete)
                    line += logfile.readline()

                if entry_start_pattern.match(line):
                    next_line = line
                    break

                buf.append(line)
                line_count += 1

            entry = ''.join(buf)
            buf.clear()

            if error_match := self.error_pattern.search(entry):
                ignore_pattern = self.ignore_pattern
                if ignore_pattern is not None and (ignore_match := ignore_pattern.search(entry)):
                    if logger.isEnabledFor(logging.DEBUG):
                        error_reason  = error_match.group(0)
                        ignore_reason = ignore_match.group(0)
                        logger.debug(f'{logfile.name}: IGNORED: {error_reason} for {ignore_reason}')
                else:
                    brief = ''

                    for line in entry_start_pattern.sub('', entry).split('\n'):
                        brief = line.lstrip().rstrip(' \r\n\t:{')
                        if brief:
                            break

                    if not brief:
                        brief = entry

                    yield LogEntry(
                        data = entry,
                        brief = brief,
                        formatted = entry,
                    )
