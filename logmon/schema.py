from typing import NotRequired, TypedDict, Optional

import pydantic

from datetime import timedelta

from .types import *
from .json_match import JsonMatch

__all__ = (
    'ActionConfig',
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

class ActionConfigBase(TypedDict):
    action: NotRequired[ActionType]
    subject: NotRequired[str]
    body: NotRequired[str]
    host: NotRequired[str]
    port: NotRequired[int]
    user: NotRequired[str]
    password: NotRequired[str]
    secure: NotRequired[SecureOption]
    logmails: NotRequired[Logmails]
    keep_connected: NotRequired[bool]

    http_method: NotRequired[str]
    http_path: NotRequired[str]
    http_params: NotRequired[dict[str, str]|list[tuple[str, str]]]
    http_content_type: NotRequired[ContentType]
    http_headers: NotRequired[dict[str, str]]
    http_max_redirect: NotRequired[int]
    http_timeout: NotRequired[float]

    oauth2_grant_type: NotRequired[OAuth2GrantType]
    oauth2_token_url: NotRequired[Optional[str]] # explicit None for explicit no-oauth2
    oauth2_client_id: NotRequired[str]
    oauth2_client_secret: NotRequired[str]
    oauth2_scope: NotRequired[list[str]]
    oauth2_refresh_margin: NotRequired[timedelta]

    command: NotRequired[list[str]]
    command_cwd: NotRequired[str]
    command_user: NotRequired[str|int]
    command_group: NotRequired[str|int]
    command_env: NotRequired[dict[str, str]]
    command_stdin: NotRequired[str]
    command_stdout: NotRequired[str]
    command_stderr: NotRequired[str]
    command_interactive: NotRequired[bool]
    command_timeout: NotRequired[Optional[float]]

class ActionConfig(ActionConfigBase):
    sender: NotRequired[str]
    receivers: NotRequired[list[str]]

class PartialEMailConfig(ActionConfigBase):
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

class Config(ActionConfig, LogfileConfig, SystemDConfig, LimitsConfig):
    pass

class PartialConfig(PartialEMailConfig, LogfileConfig, SystemDConfig, LimitsConfig):
    pass

class DefaultConfig(LogfileConfig, SystemDConfig):
    pass

class MTConfig(TypedDict):
    do: ActionConfig
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
