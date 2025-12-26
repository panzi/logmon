from typing import NamedTuple, TextIO, Optional, Generator, Any
from abc import ABC, abstractmethod

from ..schema import Config

__all__ = (
    'LogEntry',
    'EntryReaderFactory',
)

class LogEntry(NamedTuple):
    data: Any
    brief: str # how to not calculate that for all entries?
    formatted: str

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
