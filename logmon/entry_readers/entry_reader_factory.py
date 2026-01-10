from typing import NamedTuple, TextIO, Optional, Generator, Any
from abc import ABC, abstractmethod

import json
import logging

from ..schema import Config
from ..types import OutputFormat
from ..yaml import yaml_dump

__all__ = (
    'LogEntry',
    'TextLogEntry',
    'EntryReaderFactory',
)

logger = logging.getLogger(__name__)

class LogEntry(NamedTuple):
    data: Any
    brief: str # how to not calculate that for all entries?

    def format(self, output_format: OutputFormat, output_indent: Optional[int] = None) -> str:
        match output_format:
            case 'JSON':
                return json.dumps(self.data, indent=output_indent)

            case 'YAML':
                return yaml_dump(self.data, indent=output_indent)

            case _:
                logger.error(f'Illegal output format: {output_format}')
                return json.dumps(self.data, indent=output_indent)

class TextLogEntry(LogEntry):
    def format(self, output_format: OutputFormat, output_indent: Optional[int] = None) -> str:
        return self.data

class EntryReaderFactory(ABC):
    __slots__ = ()

    @abstractmethod
    def create_reader(self, logfile: TextIO) -> Generator[Optional[LogEntry], None, None]: ...

    @staticmethod
    def from_config(config: Config) -> "EntryReaderFactory":
        if config.get('json'):
            from .json_entry_reader_factory import JsonEntryReaderFactory
            return JsonEntryReaderFactory(config)
        else:
            from .text_entry_reader_factory import TextEntryReaderFactory
            return TextEntryReaderFactory(config)
