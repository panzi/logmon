from typing import NotRequired, TypedDict, Optional

import pydantic

from .types import *
from .json_match import JsonMatch

__all__ = (
    'EMailConfig',
    'PartialEMailConfig',
    'LimitsConfig',
    'LogfileConfig',
    'SystemDConfig',
    'Config',
    'PartialConfig',
    'DefaultConfig',
    'MTConfig',
    'AppLogConfig',
    'AppConfig',
    'ConfigFile',
)

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
    json_ignore: NotRequired[Optional[JsonMatch]]
    json_brief: NotRequired[Optional[JsonPath]]
    output_indent: NotRequired[int]
    output_format: NotRequired[OutputFormat]

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
