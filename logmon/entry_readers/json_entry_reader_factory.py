from typing import Optional, TextIO, Generator, override

import json
import logging

from time import sleep
from ..constants import *
from ..global_state import is_running
from ..schema import Config
from ..json_match import CompiledJsonMatch, JsonPath, compile_json_match, check_json_match, get_json_path
from ..cleanup_brief import cleanup_brief
from .entry_reader_factory import LogEntry, EntryReaderFactory

__all__ = (
    'JsonEntryReaderFactory',
)

logger = logging.getLogger(__name__)

class JsonEntryReaderFactory(EntryReaderFactory):
    __slots__ = (
        'match',
        'ignore',
        'brief_path',
        'wait_line_incomplete',
    )
    match: CompiledJsonMatch
    ignore: Optional[CompiledJsonMatch]
    brief_path: Optional[JsonPath]
    wait_line_incomplete: int|float

    def __init__(self, config: Config) -> None:
        super().__init__()

        json_match = config.get('json_match') or {}
        json_ignore = config.get('json_ignore')

        self.match = compile_json_match(json_match)
        self.ignore = compile_json_match(json_ignore) if json_ignore is not None else None
        self.brief_path = config.get('json_brief', DEFAULT_JSON_BRIEF)
        self.wait_line_incomplete = config.get('wait_line_incomplete', DEFAULT_WAIT_LINE_INCOMPLETE)

    @override
    def create_reader(self, logfile: TextIO) -> Generator[LogEntry | None, None, None]:
        while is_running():
            try:
                line = logfile.readline()
            except EOFError:
                line = ''

            if not line:
                yield None
                continue

            if not line.endswith('\n'):
                sleep(self.wait_line_incomplete)
                try:
                    line += logfile.readline()
                except EOFError:
                    pass

            line = line.strip()

            if not line or line.startswith('//'):
                # ignore empty lines and support single line JavaScript style comments
                continue

            entry = json.loads(line)

            if not check_json_match(entry, self.match):
                continue

            ignore = self.ignore
            if ignore is not None and check_json_match(entry, ignore):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f'{logfile.name}: IGNORED: {line}')
                continue

            brief_path = self.brief_path

            if brief_path is not None:
                brief = get_json_path(entry, brief_path)
                if brief is None:
                    brief = line.strip()
                elif isinstance(brief, (list, dict)):
                    brief = json.dumps(brief)
                else:
                    brief = str(brief)

                brief = cleanup_brief(brief)
            else:
                brief = line.strip()

            yield LogEntry(
                data = entry,
                brief = brief,
            )
