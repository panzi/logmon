from typing import NotRequired, TypedDict, Optional, Annotated

import re
import pydantic

from pydantic import Field
from datetime import timedelta

from .types import *
from .constants import *
from .json_match import JsonMatch

__all__ = (
    'ActionConfig',
    'LimitsConfig',
    'LogfileConfig',
    'SystemDConfig',
    'Config',
    'InputConfig',
    'MTConfig',
    'AppLogConfig',
    'LogmonConfig',
    'ConfigFile',
)

FILE_MODE_PATTERN = re.compile(r'^(?:(?P<ls>(?:[-r][-w][-x]){3})|(?P<eq>([ugo]=r?w?x?(,[ugo]=r?w?x?)*)?)|(?P<oct>(?:0o?)?[0-7]{3}))$')

class ActionConfigBase(TypedDict):
    action: Annotated[NotRequired[ActionType], Field(
        description="Action to perform.\n"
                    "This can also be a string in the form of:\n"
                    "```\n"
                    "    {smtp,imap,http,https}[:[//][<user>[:<password>]@]<host>[:<port>][/<path>[?<query>]]]\n"
                    "```\n"
                    "\n"
                    "or:\n"
                    "```\n"
                    "    command[:<command> [<option>...]]}\n"
                    "```\n"
                    "\n"
                    'Parameters defined here overwrite values passed via other options.\n'
                    '\n'
                    'For SMTP and IMAP these query parameters are supported:\n'
                    '\n'
                    '* `sender`\n'
                    '* `receivers`\n'
                    '* `secure`\n'
                    '\n'
                   f'**Default:** `{DEFAULT_ACTION!r}`',
    )]
    subject: Annotated[NotRequired[str], Field(description=f"Email subject template.\n**Default:** `{DEFAULT_SUBJECT!r}`")]
    body: Annotated[NotRequired[str], Field(description=f"Email body template.\n**Default:** `{DEFAULT_BODY!r}`")]
    host: Annotated[NotRequired[str], Field(description="Host to connect to for SMTP/IMAP/HTTP(S).\n**Default:** `'localhost'`")]
    port: Annotated[NotRequired[int], Field(description="Port to connect to for SMTP/IMAP/HTTP(S) if not the standard port.", ge=0)]
    user: Annotated[NotRequired[str], Field(description="Credentials for SMTP/IMAP, HTTP basic auth, or OAuth 2.0 password grant type.")]
    password: Annotated[NotRequired[str], Field(description="Credentials for SMTP/IMAP, HTTP basic auth, or OAuth 2.0 password grant type.")]
    secure: Annotated[NotRequired[SecureOption], Field(description="`secure` option for SMTP/IMAP.\n**Default:** `None`")]
    logmails: Annotated[NotRequired[Logmails], Field(description=f"Write messages to logmon's log instead of/in addition to performing the action.\n**Default:** `{DEFAULT_LOGMAILS!r}`")]
    keep_connected: Annotated[NotRequired[bool], Field(description="Keep connection to server alive (SMTP, IMAP, HTTP(S)).\n**Default:** `False`")]

    http_method: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_HTTP_METHOD!r}`")]
    http_path: Annotated[NotRequired[str], Field(description="**Default:** `'/'`")]
    http_params: Annotated[NotRequired[dict[str, str]|list[tuple[str, str]]], Field(description=f"**Default:** `{DEFAULT_HTTP_PARAMS!r}`")]
    http_content_type: Annotated[NotRequired[ContentType], Field(description=f"**Default:** `{DEFAULT_HTTP_CONTENT_TYPE!r}`")]
    http_headers: Annotated[NotRequired[dict[str, str]], Field(description="Additional HTTP headers. The `Authorization` header will be overwritten if OAuth 2.0 is used or if `username` and `password` are set.")]
    http_max_redirect: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_HTTP_MAX_REDIRECT!r}`", ge=0)]
    http_timeout: Annotated[NotRequired[Optional[float]], Field(description="`None` means no timeout.\n**Default:** `None`", ge=0.0)]

    oauth2_grant_type: Annotated[NotRequired[OAuth2GrantType], Field(description=f"**Default:** `{DEFAULT_OAUTH2_GRANT_TYPE!r}`")]
    oauth2_token_url: Annotated[NotRequired[Optional[str]], Field(description="`None` means don't use OAuth 2.0.\n**Default:** `None`")]
    oauth2_client_id: NotRequired[str]
    oauth2_client_secret: NotRequired[str]
    oauth2_scope: NotRequired[list[str]]
    oauth2_refresh_margin: Annotated[NotRequired[timedelta], Field(description="Seconds to substract from the expiration date-time when checking for access token expiration.\n**Default:** `0.0`")]

    command: NotRequired[list[str]]
    command_cwd: Annotated[NotRequired[str], Field(description="Working directory of spawned process.")]
    command_user: Annotated[NotRequired[str|int], Field(description="Run the process as user/UID.")]
    command_group: Annotated[NotRequired[str|int], Field(description="Run the process as group/GID.")]
    command_env: Annotated[NotRequired[dict[str, str|None]], Field(description="Set the environment of the spawned process to this. Passing `None` as the value means to inherit that environment variable from the current environment.")]
    command_stdin: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'inherit:'`, `'null:'`, `'pipe:TEMPLATE'`\n**Default:** `'null:'`")]
    command_stdout: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'append:/path/to/file'`, `'inherit:'`, `'null:'`\n**Default:** `'null:'`")]
    command_stderr: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'append:/path/to/file'`, `'inherit:'`, `'null:'`, `'stdout:'`\n**Default:** `'null:'`")]
    command_interactive: Annotated[NotRequired[bool], Field(description="If `True` the process is long-running and log entries are passed by writing them to the stdin of the process instead of command line arguments.\n**Default:** `False`")]
    command_timeout: Annotated[NotRequired[Optional[float]], Field(description="Timeout in seconds. If the timeout expires the process is killed.\n**Default:** `None`", ge=0.0)]

    file: NotRequired[str]
    file_encoding: Annotated[NotRequired[str], Field(description="**Default:** `'UTF-8'`")]
    file_append: Annotated[NotRequired[bool], Field(description="**Default:** `True`")]
    file_user: NotRequired[str|int]
    file_group: NotRequired[str|int]
    file_type: Annotated[NotRequired[FileType], Field(description="**Default:** `'regular'`")]
    file_mode: Annotated[NotRequired[str|int], Field(description='File mode, e.g.: `rwxr-x---`, `u=rwx,g=rx,o=`, or `0750`.', pattern=FILE_MODE_PATTERN)]

    output_indent: Annotated[NotRequired[Optional[int]], Field(description=f"Indent JSON/YAML log entries in output. If `None` the JSON documents will be in a single line.\n**Default:** `{DEFAULT_OUTPUT_INDENT!r}`", ge=0)]
    output_format: Annotated[NotRequired[OutputFormat], Field(description=f"Use this format when writing JSON log entries to the output.\n**Default:** `{DEFAULT_OUTPUT_FORMAT!r}`")]

class ActionConfig(ActionConfigBase):
    sender: Annotated[NotRequired[str], Field(description='**Default:** `logmon@<host>`')]
    receivers: Annotated[NotRequired[list[str]], Field(description='**Default:** `<sender>`')]

class LimitsConfig(TypedDict):
    max_emails_per_minute: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_EMAILS_PER_MINUTE!r}`", gt=0)]
    max_emails_per_hour: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_EMAILS_PER_HOUR!r}`", gt=0)]

class LogfileConfig(TypedDict):
    entry_start_pattern: Annotated[NotRequired[str | list[str]], Field(description=f"**Default:** `{DEFAULT_ENTRY_START_PATTERN.pattern!r}`")]
    error_pattern: Annotated[NotRequired[str | list[str]], Field(description=f"**Default:** `{DEFAULT_ERROR_PATTERN.pattern!r}`")]
    #warning_pattern: Annotated[NotRequired[str|list[str]], Field(description=f"**Default:** `{DEFAULT_WARNING_PATTERN.pattern!r}`")]
    ignore_pattern: Annotated[NotRequired[str | list[str] | None], Field(description="Even if the `error_pattern` matches, if this pattern also matches the log entry is ignored.")]
    wait_line_incomplete: Annotated[NotRequired[int | float], Field(description=f"**Default:** `{DEFAULT_WAIT_LINE_INCOMPLETE!r}`", ge=0)]
    wait_file_not_found: Annotated[NotRequired[int | float], Field(description=f"**Default:** `{DEFAULT_WAIT_FILE_NOT_FOUND!r}`", ge=0)]
    wait_no_entries: Annotated[NotRequired[int | float], Field(description=f"**Default:** `{DEFAULT_WAIT_NO_ENTRIES!r}`", ge=0)]
    wait_before_send: Annotated[NotRequired[int | float], Field(description=f"**Default:** `{DEFAULT_WAIT_BEFORE_SEND!r}`", ge=0)]
    wait_after_crash: Annotated[NotRequired[int | float], Field(description=f"**Default:** `{DEFAULT_WAIT_AFTER_CRASH!r}`", ge=0)]
    max_entries: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_ENTRIES!r}`", ge=0)]
    max_entry_lines: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_ENTRY_LINES!r}`", ge=0)]
    use_inotify: Annotated[NotRequired[bool], Field(description="If the `inotify` package is available this defaults to `True`.")]
    seek_end: Annotated[NotRequired[bool], Field(description="Seek to end of log file on open.\n**Default:** `True`")]
    json: Annotated[NotRequired[bool], Field(description="If `True` parses each line of the log file as a JSON document. Empty lines and lines starting with `//` are skipped.\n**Default:** `False`")]
    json_match: Annotated[NotRequired[Optional[JsonMatch]], Field(description="JSON property paths and values to compare them to. A log entry will only be processed if all properties match. Per default all log entries are processed.")]
    json_ignore: Annotated[NotRequired[Optional[JsonMatch]], Field(description="Even if `json_match` matches, if this matches then the log entry is ignored.")]
    json_brief: Annotated[NotRequired[Optional[JsonPath]], Field(description=f"Use property at this path as the `{{brief}}` template variable.\n**Default:** `{DEFAULT_JSON_BRIEF!r}`")]
    encoding: Annotated[NotRequired[str], Field(description="**Default:** `'UTF-8'`")]

class SystemDConfig(TypedDict):
    systemd_priority: NotRequired[SystemDPriority|int]
    systemd_match: NotRequired[dict[str, str|int]] # TODO: more complex expressions?

class Config(LogfileConfig, SystemDConfig, LimitsConfig):
    do: list[ActionConfig]

class InputConfig(LogfileConfig, SystemDConfig):
    pass

class MTConfig(TypedDict):
    do: NotRequired[ActionConfig]
    default: NotRequired[InputConfig]
    logfiles: Annotated[dict[str, Config]|list[str], Field(
        description='The mapping keys or entries in the array of strings is the path of the log file.\n'
                    'You can read from a SystemD journal instead of a file by specifying a path in the form of:\n'
                    '\n'
                    '    systemd:{LOCAL_ONLY,RUNTIME_ONLY,SYSTEM,CURRENT_USER}[:{UNIT,SYSLOG}:IDENTIFIER]'
    )]
    limits: NotRequired[LimitsConfig]

class AppLogConfig(TypedDict):
    """
    Configuration of this apps own logging.
    """
    file: NotRequired[str]
    level: NotRequired[str]
    format: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_LOG_FORMAT!r}`")]
    datefmt: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_LOG_DATEFMT!r}`")]

class LogmonConfig(MTConfig):
    log: NotRequired[AppLogConfig]
    pidfile: Annotated[NotRequired[str], Field(title="PID File", description="Write the process Id of the logmon process to this file.")]

class ConfigFile(pydantic.BaseModel):
    config: Annotated[LogmonConfig, Field(description="Contents of the config file.")]

def resolve_config(input_config: InputConfig, action_config: ActionConfig, logfile_config: Config) -> Config:
    cfg_do_raw = logfile_config.get('do')
    cfg_do: list[ActionConfig] = []
    if cfg_do_raw is not None:
        for do_item in cfg_do_raw:
            cfg_do.append({ **action_config, **do_item })
    else:
        cfg_do = [action_config]

    resolved_cfg: Config = {
        **input_config,
        **logfile_config,
        'do': cfg_do,
    }

    return resolved_cfg
