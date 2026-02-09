from typing import NotRequired, TypedDict, Annotated, Literal

import re
import json
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

_default_limits = {
    "default": {
        "max_actions_per_minute": DEFAULT_MAX_ACTIONS_PER_MINUTE,
        "max_actions_per_hour": DEFAULT_MAX_ACTIONS_PER_HOUR,
    }
}

_action_array_title = 'Action Array'
_unlimited = 'Unlimited'
_limits_title = 'Rate limit actions'
_limits_description = f'''\
Map of action limiters that can be assigned to actions. You can set a limiter to `null` to make it unlimited.

**Default:** `{json.dumps(_default_limits)}`'''
_action_string_tilte = 'Action String'
_see_action = 'See root &rarr; do &rarr; anyOf &rarr; LogActionConfig &rarr; action for more details.'
_action_description = '''\
Action to perform.
This can also be a string in the form of one of these:
```
    {smtp,imap,http,https}[:[//][<user>[:<password>]@]<host>[:<port>][/<path>[?<query>]]]
    command[:<command> [<option>...]]
    {file,fifo}[:<path>]
```

Parameters defined here overwrite values passed via other options.

For SMTP and IMAP these query parameters are supported:

* `sender`
* `receivers`
* `secure`

''' f'**Default:** `{DEFAULT_ACTION!r}`'

Null = Annotated[None, Field(title="Null")]

class ActionConfigBase(TypedDict):
    limiter: NotRequired[
        Annotated[str, Field(title='Limiter Name')]|
        Annotated[None, Field(title=_unlimited)]
    ]
    subject: Annotated[NotRequired[str], Field(description=f"Email subject template.\n**Default:** `{DEFAULT_SUBJECT!r}`")]
    body: Annotated[NotRequired[str], Field(description=f"Email body template.\n**Default:** `{DEFAULT_BODY!r}`")]
    host: Annotated[NotRequired[str], Field(description="Host to connect to for SMTP/IMAP/HTTP(S).\n**Default:** `'localhost'`")]
    port: Annotated[NotRequired[int], Field(description="Port to connect to for SMTP/IMAP/HTTP(S) if not the standard port.", ge=0)]
    user: Annotated[NotRequired[str], Field(description="Credentials for SMTP/IMAP, HTTP basic auth, or OAuth 2.0 password grant type.")]
    password: Annotated[NotRequired[str], Field(description="Credentials for SMTP/IMAP, HTTP basic auth, or OAuth 2.0 password grant type.")]
    secure: Annotated[NotRequired[SecureOption], Field(description="`secure` option for SMTP/IMAP.\n**Default:** `null`")]
    logmails: Annotated[NotRequired[Logmails], Field(description=f"Write messages to logmon's log instead of/in addition to performing the action.\n**Default:** `{DEFAULT_LOGMAILS!r}`")]
    keep_connected: Annotated[NotRequired[bool], Field(description="Keep connection to server alive (SMTP, IMAP, HTTP(S)).\n**Default:** `false`")]

    http_method: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_HTTP_METHOD!r}`")]
    http_path: Annotated[NotRequired[str], Field(description="**Default:** `'/'`")]
    http_params: Annotated[
        NotRequired[
            Annotated[dict[str, str], Field(title='Header Mapping')]|
            Annotated[list[tuple[str, str]], Field(title='List of Tuples')]
        ], Field(description=f"**Default:** `{DEFAULT_HTTP_PARAMS!r}`")]
    http_content_type: Annotated[NotRequired[ContentType], Field(description=f"**Default:** `{DEFAULT_HTTP_CONTENT_TYPE!r}`")]
    http_headers: Annotated[NotRequired[dict[str, str]], Field(description="Additional HTTP headers. The `Authorization` header will be overwritten if OAuth 2.0 is used or if `username` and `password` are set.")]
    http_max_redirect: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_HTTP_MAX_REDIRECT!r}`", ge=0)]
    http_timeout: Annotated[NotRequired[
        Annotated[float, Field(title="Seconds")]|
        Annotated[None,  Field(title=_unlimited)]
    ], Field(description="`null` means no timeout.\n**Default:** `null`", ge=0.0)]

    oauth2_grant_type: Annotated[NotRequired[OAuth2GrantType], Field(description=f"**Default:** `{DEFAULT_OAUTH2_GRANT_TYPE!r}`")]
    oauth2_token_url: Annotated[NotRequired[
        Annotated[str,  Field(title="URL")]|
        Null
    ], Field(description="`null` means don't use OAuth 2.0.\n**Default:** `null`")]
    oauth2_client_id: NotRequired[str]
    oauth2_client_secret: NotRequired[str]
    oauth2_scope: NotRequired[list[str]]
    oauth2_refresh_margin: Annotated[NotRequired[timedelta], Field(description="Seconds to substract from the expiration date-time when checking for access token expiration.\n\n**Default:** `0.0`")]

    command: Annotated[
        NotRequired[
            Annotated[list[str], Field(title='Argument Array')]|
            Annotated[str, Field(title='Command String', description='This string is split into the argument array using `shlex.split()`.')]]
        ,
        Field(description=
              "Command to run if `action` is `'COMMAND'`.\n\n"
              "The template parameters are the same as with `body` plus the special syntax `{...entries}`, which makes "
              "the argument repeat as a separate argument for each entry. E.g. if there are the entries `'foo'` and `'bar'` "
              "the argument list `['command', '--entry={...entries}']` will expand to `['command', '--entry=foo', '--entry=bar']`.\n"
              "\n"
              "Additional parameters:\n"
              "\n"
              "- `{python}` - Path of the Python binary used to execute logmon itself. (`sys.executable`)\n"
              "- `{python_version}` - Full vesrsion string of the Python binary. (`sys.version`)\n"
              "- `{python_version_major}` - `sys.version_info.major`.\n"
              "- `{python_version_minor}` - `sys.version_info.minor`.\n"
              "- `{python_version_micro}` - `sys.version_info.micro`.\n",
              examples=[['/path/to/command', '--sender', '{sender}', '--receivers', '{receivers}', '--', '{...entries}']])
    ]
    command_cwd: Annotated[NotRequired[str], Field(description="Working directory of spawned process.")]
    command_user: Annotated[
        NotRequired[
            Annotated[str, Field(title="User Name")]|
            Annotated[int, Field(title="User Id")]],
        Field(description="Run the process as user/UID.")
    ]
    command_group: Annotated[
        NotRequired[
            Annotated[str, Field(title='Group Name')]|
            Annotated[int, Field(title='Group Id')]],
        Field(description="Run the process as group/GID.")
    ]
    command_process_group: Annotated[NotRequired[int], Field(description="`setpgid()` to apply for the sub-process.")]
    command_new_session: Annotated[NotRequired[bool], Field(description="If `True` use `setsid()` in the sub-process.\n\n**Default:** `False`")]
    command_extra_groups: Annotated[
        NotRequired[
            list[
                Annotated[str, Field(title="Group Name")]|
                Annotated[int, Field(title="Group Id")]
            ]
        ],
        Field(description="`setgroups()` to apply for the sub-process.")
    ]
    command_env: Annotated[NotRequired[
        dict[str,
             Annotated[str, Field(title="String")]|
             Null]
    ], Field(description="Set the environment of the spawned process to this. Passing `null` as the value means to inherit that environment variable from the current environment. If this is unset the environment of the logmon process is inherited.")]
    command_stdin: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'inherit:'`, `'null:'`, `'pipe:TEMPLATE'`\n\nThe parameters to the `TEMPLATE` are the same as for `body` plus the special syntax `{...entries}` which causes the whole template to repeat for each entry.\n\n**Default:** `'null:'`")]
    command_stdout: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'append:/path/to/file'`, `'inherit:'`, `'null:'`\n\n**Default:** `'null:'`")]
    command_stderr: Annotated[NotRequired[str], Field(description="`'file:/path/to/file'`, `'append:/path/to/file'`, `'inherit:'`, `'null:'`, `'stdout:'`\n\n**Default:** `'null:'`")]
    command_interactive: Annotated[NotRequired[bool], Field(description="If `true` the process is long-running and log entries are passed by writing them to the stdin of the process instead of command line arguments.\n\n**Default:** `false`")]
    command_timeout: Annotated[NotRequired[
        Annotated[float, Field(title="Seconds")]|
        Annotated[None,  Field(title=_unlimited)]
    ], Field(description="Timeout in seconds. If the timeout expires the process is killed.\n\n**Default:** `null`", ge=0.0)]
    command_chroot: Annotated[NotRequired[
        Annotated[str, Field(title="Path")]|
        Null
    ], Field(description="`chroot()` into the given path before the sub-process is executed.\n\n**Default:** `null`")]
    command_umask: Annotated[NotRequired[
        Annotated[int, Field(title="Integer", ge=0)]|
        Null
    ], Field(description="`umask()` to apply for the sub-process.")]
    command_nice: Annotated[NotRequired[
        Annotated[int, Field(title="Integer", ge=0)]|
        Null
    ], Field(description="`nice()` to apply for the sub-process.")]
    command_encoding: Annotated[NotRequired[str], Field(description="Encoding used to communicate with sub-process.")]
    command_encoding_errors: Annotated[NotRequired[EncodingErrors], Field(description=f"See: (Python's encoding error handling)[https://docs.python.org/3/library/codecs.html#error-handlers]\n\n**Default:** `{DEFAULT_ENCODING_ERRORS!r}`")]

    file: Annotated[NotRequired[str], Field(description="Path of logmon logfile.")]
    file_encoding: Annotated[NotRequired[str], Field(description="**Default:** `'UTF-8'`")]
    file_encoding_errors: Annotated[NotRequired[EncodingErrors], Field(description=f"See: (Python's encoding error handling)[https://docs.python.org/3/library/codecs.html#error-handlers]\n\n**Default:** `{DEFAULT_ENCODING_ERRORS!r}`")]
    file_append: Annotated[NotRequired[bool], Field(description="Open file in append mode.\n\n**Default:** `true`")]
    file_user: Annotated[
        NotRequired[
            Annotated[str, Field(title="User Name")]|
            Annotated[int, Field(title="User Id")]],
        Field(description="Set owner of the file as user/UID.")
    ]
    file_group: Annotated[
        NotRequired[
            Annotated[str, Field(title='Group Name')]|
            Annotated[int, Field(title='Group Id')]],
        Field(description="Set owner of the file as group/GID.")
    ]
    file_type: Annotated[NotRequired[FileType], Field(description="**Default:** `'regular'`")]
    file_mode: Annotated[
        NotRequired[
            Annotated[str, Field(title='String')]|
            Annotated[int, Field(title='Integer')]],
        Field(description='Create the file with these permissions. E.g.: `rwxr-x---`, `u=rwx,g=rx,o=`, or `0750`.', pattern=FILE_MODE_PATTERN)
    ]
    file_compression: Annotated[NotRequired[
        Compression|
        Annotated[None, Field(title="Uncompressed")]
    ], Field(description="Compress output file.\n\n**Default:** `null`")]
    file_compression_level: Annotated[NotRequired[
        Annotated[int, Field(title="Integer")]|
        Annotated[None, Field(title="Python Default")]
    ], Field(description="**Default:** `null`")]

    output_indent: Annotated[NotRequired[
        Annotated[int, Field(title="Integer", ge=0)]|
        Annotated[None, Field(title="Null", description="Whole JSON document on a single line.")]
    ], Field(description=f"Indent JSON/YAML log entries in output. If `null` the JSON documents will be in a single line.\n\n**Default:** `{DEFAULT_OUTPUT_INDENT!r}`", ge=0)]
    output_format: Annotated[NotRequired[OutputFormat], Field(description=f"Use this format when writing JSON log entries to the output.\n\n**Default:** `{DEFAULT_OUTPUT_FORMAT!r}`")]
    entries_delimiter: Annotated[NotRequired[str], Field(description="String used to delimite entries in {entries_str}.\n\n**Default:** `'\\n\\n'`")]

    sender: Annotated[NotRequired[str], Field(description='Email sender address.\n\n**Default:** `logmon@<host>`')]
    receivers: Annotated[NotRequired[list[str]], Field(description='List of email receiver addresses.\n\n**Default:** `<sender>`')]

class ActionConfig(ActionConfigBase):
    action: Annotated[NotRequired[ActionType], Field(description=_action_description)]

class LimitsConfig(TypedDict):
    max_actions_per_minute: Annotated[
        NotRequired[
            Annotated[int, Field(title='Integer', gt=0)]|
            Annotated[None, Field(title=_unlimited)]
        ],
        Field(description=f"**Default:** `{DEFAULT_MAX_ACTIONS_PER_MINUTE!r}`")
    ]
    max_actions_per_hour: Annotated[
        NotRequired[
            Annotated[int, Field(title='Integer', gt=0)]|
            Annotated[None, Field(title=_unlimited)]
        ],
        Field(description=f"**Default:** `{DEFAULT_MAX_ACTIONS_PER_HOUR!r}`")
    ]

type ErrorPattern = (
    Annotated[str, Field(title="Pattern", description="Python regular expression.")]|
    Annotated[list[str], Field(title="List of Patterns", description="List of Python regular expressions that will be joined with `|` into a single expression.")]
)

class LogfileConfig(TypedDict):
    entry_start_pattern: Annotated[NotRequired[ErrorPattern], Field(description=f"**Default:** `{DEFAULT_ENTRY_START_PATTERN.pattern!r}`")]
    error_pattern: Annotated[NotRequired[ErrorPattern], Field(description=f"**Default:** `{DEFAULT_ERROR_PATTERN.pattern!r}`")]
    #warning_pattern: Annotated[NotRequired[ErrorPattern], Field(description=f"**Default:** `{DEFAULT_WARNING_PATTERN.pattern!r}`")]
    ignore_pattern: Annotated[NotRequired[ErrorPattern | Null], Field(description="Even if the `error_pattern` matches, if this pattern also matches the log entry is ignored.")]
    wait_line_incomplete: Annotated[NotRequired[float], Field(description=f"Seconds to wait for more data if the line wasn't ended with a newline character.\n\n**Default:** `{DEFAULT_WAIT_LINE_INCOMPLETE!r}`", ge=0)]
    wait_file_not_found: Annotated[NotRequired[float], Field(description=f"Seconds to wait before trying to re-open the file if it was not found and if inotify isn't used.\n\n**Default:** `{DEFAULT_WAIT_FILE_NOT_FOUND!r}`", ge=0)]
    wait_no_entries: Annotated[NotRequired[float], Field(description=f"Seconds to wait when there are no entries if inotify is not used.\n\n**Default:** `{DEFAULT_WAIT_NO_ENTRIES!r}`", ge=0)]
    wait_for_more: Annotated[NotRequired[float], Field(description=f"Seconds to wait for more messages before the action is performed.\n\n**Default:** `{DEFAULT_WAIT_FOR_MORE!r}`", ge=0)]
    wait_after_crash: Annotated[NotRequired[float], Field(description=f"Seconds to wait after a logfile handler has crashed before it is restarted.\n\n**Default:** `{DEFAULT_WAIT_AFTER_CRASH!r}`", ge=0)]
    max_entries: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_ENTRIES!r}`", ge=0)]
    max_entry_lines: Annotated[NotRequired[int], Field(description=f"**Default:** `{DEFAULT_MAX_ENTRY_LINES!r}`", ge=0)]
    use_inotify: Annotated[NotRequired[bool], Field(description="If the `inotify` package is available this defaults to `true`.")]
    seek_end: Annotated[NotRequired[bool], Field(description="Seek to end of log file on open.\n**Default:** `true`")]
    json: Annotated[NotRequired[bool], Field(description="If `true` parses each line of the log file as a JSON document. Empty lines and lines starting with `//` are skipped.\n**Default:** `false`")]
    json_match: Annotated[NotRequired[
        Annotated[JsonMatch, Field(title="Object")]|Null
    ], Field(description="JSON property paths and values to compare them to. A log entry will only be processed if all properties match. Per default all log entries are processed.")]
    json_ignore: Annotated[NotRequired[
        Annotated[JsonMatch, Field(title="Object")]|Null
    ], Field(description="Even if `json_match` matches, if this matches then the log entry is ignored.")]
    json_brief: Annotated[NotRequired[
        Annotated[list[
            Annotated[str, Field(title="Object Key")]|
            Annotated[int, Field(title="Array Index")]
        ], Field(title="JSON Path")]|Null
    ], Field(description=f"Use property at this path as the `{{brief}}` template variable.\n**Default:** `{DEFAULT_JSON_BRIEF!r}`")]
    encoding: Annotated[NotRequired[str], Field(description="**Default:** `'UTF-8'`")]
    encoding_errors: Annotated[NotRequired[EncodingErrors], Field(description=f"See: (Python's encoding error handling)[https://docs.python.org/3/library/codecs.html#error-handlers]\n\n**Default:** `{DEFAULT_ENCODING_ERRORS!r}`")]
    glob: Annotated[NotRequired[bool], Field(description="If `true` the last segment of a logfile path is a glob pattern. The rest of the path is just a normal path still. This way multiple logfiles can be processed at once and the directory is monitored for changes for when other matching files appear.\n\n**Default:** `false`")]
    compression: Annotated[NotRequired[Compression|Null], Field(description="Read compressed logfiles.\n\n**Default:** `null`")]

type SystemDMatch = dict[
    str,
    Annotated[str, Field(title="String")]|
    Annotated[int, Field(title="Integer")]
]

class SystemDConfig(TypedDict):
    systemd_priority: Annotated[
        NotRequired[
            Annotated[SystemDPriority, Field(title="String")]|
            Annotated[int, Field(title="Integer")]
        ],
        Field(description="Match log entries of this or higher priority.")
    ]
    systemd_match: NotRequired[SystemDMatch] # TODO: more complex expressions?
    systemd_ignore: Annotated[NotRequired[SystemDMatch|Null], Field(description="Even if a log entry is matched via `systemd_match`, if it also matches via `systemd_ignore` it is ignored.\n\n**Default:** `null`")]

class Config(LogfileConfig, SystemDConfig):
    limiter: NotRequired[
        Annotated[str, Field(title='Limiter Name')]|
        Annotated[None, Field(title=_unlimited)]
    ]
    do: list[ActionConfig]

class InputConfig(LogfileConfig, SystemDConfig):
    pass

_do_description = '''\
Default action configuration.
All actions inherit these settings if they don't overwrite them.'''
_default_description = '''\
Default logfile configuration.
All logfiles inherit these settings if they don't overwrite them.'''
_logfiles_description = '''\
The mapping keys or entries in the array of strings is the path of the log file.
You can read from a SystemD journal instead of a file by specifying a path in the form of:

    systemd:[<open_flag>(+<open_flag>)*][:{UNIT,SYSLOG}:<identifier>]

Where `open_flag` can be one of:

- `LOCAL_ONLY`
- `RUNTIME_ONLY`
- `SYSTEM`
- `CURRENT_USER`

Examples:

    systemd:
    systemd:SYSTEM+LOCAL_ONLY:SYSLOG:sshd
    systemd::UNIT:sshd.service'''

class MTConfig(TypedDict):
    do: Annotated[NotRequired[ActionConfig], Field(description=_do_description)]
    default: Annotated[NotRequired[InputConfig], Field(description=_default_description)]
    logfiles: Annotated[dict[str, Config]|list[str], Field(description=_logfiles_description)]
    limits: Annotated[
        NotRequired[
            dict[
                str,
                LimitsConfig|Annotated[None, Field(title=_unlimited)]
            ]
        ],
        Field(
            title=_limits_title,
            description=_limits_description
        )
    ]

class AppLogConfig(TypedDict):
    """
    Configuration of this apps own logging.
    """
    file: NotRequired[str]
    level: NotRequired[Literal[
        'CRITICAL',
        'FATAL',
        'ERROR',
        'WARN',
        'WARNING',
        'INFO',
        'DEBUG',
        'NOTSET',
    ]]
    format: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_LOG_FORMAT!r}`")]
    datefmt: Annotated[NotRequired[str], Field(description=f"**Default:** `{DEFAULT_LOG_DATEFMT!r}`")]

_pidfile_title = "PID File"
_pidfile_description = "Write the process Id of the logmon process to this file."

_log_description = "Log configuration of logmon itself."

class LogmonConfig(MTConfig):
    log: Annotated[NotRequired[AppLogConfig], Field(description=_log_description)]
    pidfile: Annotated[NotRequired[str], Field(title=_pidfile_title, description=_pidfile_description)]

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

# The config is transformed before validation to match the schema above,
# but for documentation reasons this is how it can be written in the config file:
class LogActionConfig(ActionConfigBase):
    action: Annotated[
        NotRequired[ActionType|Annotated[str, Field(title=_action_string_tilte, description=_see_action)]],
        Field(description=_action_description)
    ]

class LogConfig(LogfileConfig, SystemDConfig):
    limiter: NotRequired[
        Annotated[str, Field(title='Limiter Name')]|
        Annotated[None, Field(title=_unlimited)]
    ]
    do: NotRequired[
        Annotated[list[
            LogActionConfig|
            Annotated[str, Field(title=_action_string_tilte, description=_see_action)]
        ], Field(title=_action_array_title)]|
        LogActionConfig|Annotated[str, Field(title=_action_string_tilte, description=_see_action)]
    ]

class Logmonrc(TypedDict):
    """\
    logmon configuration file schema.

    ### Examples

    ```YAML
    ---
    do:
      # Default action configuration inherited by all logfiles.
      action: smtp:alice:password123@example.com
      sender: alice@example.com
      receivers:
      - bob@example.com

    logfiles:
    # a simple list if no other configuration is needed
    - "/var/log/service1.log"
    - "/var/log/service2.log"
    ```

    ```YAML
    default:
      # Default logfile configuration inherited by all logfiles.
      default_error_pattern: '(?i)ERR(OR)?|CIRT(ICAL)?|EXCEPT(ION)?'

    logfiles:
      "/var/log/service3.log":
        # It's one JSON document per line, not a plain text log.
        json: true

        # Handle JSON documents where the property `level` has
        # the value `'ERROR'` or `'CRITICAL'`.
        json_match:
          level: [in, [ERROR, CRITICAL]]

        # Path for the value of the {brief} template variable:
        json_brief: [message]

        do:
        # Run multiple action, HTTP request and write matched entries to a file.
        - action: https://api.example.com/v1/logs
          http_method: POST
          http_params:
            subject: "{brief}"
            entries: "{entries}"
          http_content_type: JSON
          oauth2_token_url: https://api.example.com/v1/oauth/token
          oauth2_client_id: "23ca1cd3-a234-4719-883f-a6e509fc57f4"
          oauth2_client_secret: "uBti6UENQnU0M1ZxM2IF0meGfovarZ5RRdzfdQe9pga/Vu5KK2vRFtlfcxP0ooMQftfUJeMOkl4Juoo+dXnwiA=="
          oauth2_scope: [write_log]

        - action: file:/var/logs/service3_errors.log

      "systemd:SYSTEM:UNIT:cron.service":
        do: "file:/var/log/cron_errors.log"
        output_indent: null
        output_format: JSON

      "/var/log/service4.log":
        do:
          # The command line string is parsed into a `list[str]` before the template
          # parameters are interpolated and run via `Popen(args=arg_list)`, it is not
          # a shell string.
          action: "command:my_command --brief={breif} --entry={...entries}"
          command_env:
            PATH: null # inherit $PATH
            HOME: "/"
            LOGMON_LOGFILE: "{logfile}" # same template variables
    ```
    """
    do: Annotated[
        NotRequired[LogActionConfig|Annotated[str, Field(title=_action_string_tilte, description=_see_action)]],
        Field(description=_do_description)
    ]
    default: Annotated[NotRequired[InputConfig], Field(description=_default_description)]
    logfiles: Annotated[
        Annotated[dict[
            str,
            LogConfig|
            Annotated[str, Field(title=_action_string_tilte, description=_see_action)]|
            Annotated[
                list[
                    LogActionConfig|
                    Annotated[str, Field(title=_action_string_tilte, description=_see_action)]],
                Field(title=_action_array_title)
            ]
        ], Field(title='Mapping of logfile settings', description='Mapping from logfiles to their configurations.')]|
        Annotated[list[str], Field(title='List of logfiles', description='All the configuration is taken from the global settings.')],
        Field(description=_logfiles_description)
    ]
    limits: Annotated[
        NotRequired[
            dict[
                str,
                LimitsConfig|Annotated[None, Field(title=_unlimited)]
            ]
        ],
        Field(
            title=_limits_title,
            description=_limits_description
        )
    ]

    log: Annotated[NotRequired[AppLogConfig], Field(description=_log_description)]
    pidfile: Annotated[NotRequired[str], Field(title=_pidfile_title, description=_pidfile_description)]
