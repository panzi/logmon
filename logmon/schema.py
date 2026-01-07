from typing import NotRequired, TypedDict, Optional, Annotated

import pydantic

from pydantic import Field
from datetime import timedelta

from .types import *
from .json_match import JsonMatch

__all__ = (
    'ActionConfig',
    'LimitsConfig',
    'LogfileConfig',
    'SystemDConfig',
    'Config',
    'DefaultConfig',
    'MTConfig',
    'AppLogConfig',
    'LogmonConfig',
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
    logmails: Annotated[NotRequired[Logmails], Field(description="Write messages to logmon's log instead of/in addition to performing the action.")]
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

class LimitsConfig(TypedDict):
    max_emails_per_minute: NotRequired[int]
    max_emails_per_hour: NotRequired[int]

class LogfileConfig(TypedDict):
    entry_start_pattern: NotRequired[str | list[str]]
    error_pattern: NotRequired[str | list[str]]
    #warning_pattern: NotRequired[str|list[str]]
    ignore_pattern: Annotated[NotRequired[str | list[str] | None], Field(description="Even if the `error_pattern` matches, if this pattern also matches the log entry is ignored.")]
    wait_line_incomplete: NotRequired[int | float]
    wait_file_not_found: NotRequired[int | float]
    wait_no_entries: NotRequired[int | float]
    wait_before_send: NotRequired[int | float]
    wait_after_crash: NotRequired[int | float]
    max_entries: NotRequired[int]
    max_entry_lines: NotRequired[int]
    use_inotify: Annotated[NotRequired[bool], Field(description="If the `inotify` package is available this defaults to `True`.")]
    seek_end: Annotated[NotRequired[bool], Field(default=True)]
    json: Annotated[NotRequired[bool], Field(default=False, description="If `True` parses each line of the log file as a JSON document.")]
    json_match: Annotated[NotRequired[Optional[JsonMatch]], Field(description="JSON property paths and values to compare them to. A log entry will only be processed if all properties match. Per default all log entries are processed.")]
    json_ignore: Annotated[NotRequired[Optional[JsonMatch]], Field(description="Even if `json_match` matches, if this matches then the log entry is ignored.")]
    json_brief: Annotated[NotRequired[Optional[JsonPath]], Field(description="Use property at this path as the `{brief}` template variable. Per default the whole JSON document is used.")]
    output_indent: Annotated[NotRequired[int], Field(description="Indent JSON log entries in output.")]
    output_format: Annotated[NotRequired[OutputFormat], Field(description="Use this format when writing JSON log entries to the output.")]

class SystemDConfig(TypedDict):
    systemd_priority: NotRequired[SystemDPriority|int]
    systemd_match: NotRequired[dict[str, str|int]] # TODO: more complex expressions?

class Config(ActionConfig, LogfileConfig, SystemDConfig, LimitsConfig):
    pass

class DefaultConfig(LogfileConfig, SystemDConfig):
    pass

class MTConfig(TypedDict):
    do: ActionConfig
    default: NotRequired[DefaultConfig]
    logfiles: dict[str, Config]|list[str]
    limits: NotRequired[LimitsConfig]

class AppLogConfig(TypedDict):
    """
    Configuration of this apps own logging.
    """
    file: NotRequired[str]
    level: NotRequired[str]
    format: NotRequired[str]
    datefmt: NotRequired[str]

class LogmonConfig(MTConfig):
    log: NotRequired[AppLogConfig]
    pidfile: Annotated[NotRequired[str], Field(title="PID File", description="Write the process Id of the logmon process to this file.")]

class ConfigFile(pydantic.BaseModel):
    config: Annotated[LogmonConfig, Field(description="Contents of the config file.")]
