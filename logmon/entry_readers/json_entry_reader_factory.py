from typing import Optional, TextIO, Generator, override

import json
import logging

from time import sleep
from ..constants import *
from ..global_state import is_running
from ..types import OutputFormat
from ..schema import Config
from ..yaml import yaml_dump
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
        'output_indent',
        'output_format',
    )
    match: CompiledJsonMatch
    ignore: Optional[CompiledJsonMatch]
    brief_path: Optional[JsonPath]
    wait_line_incomplete: int|float
    output_indent: int
    output_format: OutputFormat

    def __init__(self, config: Config) -> None:
        super().__init__()

        json_match = config.get('json_match') or {}
        json_ignore = config.get('json_ignore')

        self.match = compile_json_match(json_match)
        self.ignore = compile_json_match(json_ignore) if json_ignore is not None else None
        self.brief_path = config.get('json_brief', DEFAULT_JSON_BRIEF)
        self.wait_line_incomplete = config.get('wait_line_incomplete', DEFAULT_WAIT_LINE_INCOMPLETE)
        self.output_indent = config.get('output_indent', DEFAULT_OUTPUT_INDENT)
        self.output_format = config.get('output_format', DEFAULT_OUTPUT_FORMAT)

    @override
    def create_reader(self, logfile: TextIO) -> Generator[LogEntry | None, None, None]:
        while is_running():
            line = logfile.readline()

            if not line:
                yield None
                continue

            if not line.endswith('\n'):
                sleep(self.wait_line_incomplete)
                line += logfile.readline()

            line = line.strip()

            if not line or line.startswith('//'):
                # ignore empty lines and support single line JavaScript style comments
                continue

            entry = json.loads(line)

            if not check_json_match(entry, self.match):
                continue

            ignore = self.ignore
            if ignore is not None and check_json_match(entry, ignore):
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

            match self.output_format:
                case 'JSON':
                    formatted = json.dumps(entry, indent=self.output_indent)

                case 'YAML':
                    formatted = yaml_dump(entry, indent=self.output_indent)

                case _:
                    logger.error(f'{logfile.name}: Illegal output format: {self.output_format}')
                    formatted = json.dumps(entry, indent=self.output_indent)

            yield LogEntry(
                data = entry,
                brief = brief,
                formatted = formatted
            )
