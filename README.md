logmon
======

A very simple log file monitoring script that sends emails when it finds
configured error patterns.

Dependencies
------------

### Required

* [Pydantic](https://github.com/pydantic/pydantic) - validating the configuration
  file

### Optional

* `inotify`: [PyInotify](https://github.com/dsoprea/PyInotify) - more efficient
  way to wait for log file changes
* `systemd`: [cysystemd](https://github.com/mosquito/cysystemd) - ingest SystemD
  journals
* `yaml`: [PyYAML](https://pyyaml.org/) - support configuration to be YAML
  (instead of JSON) and emit YAML (instead of JSON) in emails
* `ruamel_yaml`: [ruamel.yaml](https://sourceforge.net/projects/ruamel-yaml/) -
  Same as above, but nicer formatted YAML in emails. If `PyYAML` and `ruamel.yaml`
  are both installed then `ruamel.yaml` is used.

Usage
-----

The settings are read from `$HOME/.logmonrc`, or if run as root from
`/etc/logmonrc`. But don't run it as root, use a dedicated user that can only
read the log files. The command line options overwrite the default settings,
but not the per-logfile settings. See below for the settings file format.

```
Usage: logmon.py [-h] [-v] [--license] [--config PATH]
                 [-A {{http,https,imap,smtp}[:[//][<user>[:<password>]@]<host>[/<path>[?<query>]]],command[:<command> [<option>...]]}]
                 [--sender EMAIL] [--receivers EMAIL,...] [--subject TEMPLATE]
                 [--body TEMPLATE] [--wait-file-not-found SECONDS]
                 [--wait-line-incomplete SECONDS] [--wait-no-entries SECONDS]
                 [--wait-before-send SECONDS] [--wait-after-crash SECONDS]
                 [--max-entries COUNT] [--max-entry-lines COUNT]
                 [--max-emails-per-minute COUNT] [--max-emails-per-hour COUNT]
                 [--use-inotify | --no-use-inotify]
                 [--entry-start-pattern REGEXP] [--error-pattern REGEXP]
                 [--ignore-pattern REGEXP] [--seek-end | --no-seek-end]
                 [--json] [--no-json] [--json-match PATH=VALUE]
                 [--json-ignore PATH=VALUE] [--json-brief PATH]
                 [--output-indent OUTPUT_INDENT] [--output-format {JSON,YAML}]
                 [--systemd-priority {PANIC,WARNING,ALERT,NONE,CRITICAL,DEBUG,INFO,ERROR,NOTICE}]
                 [--systemd-match KEY=VALUE] [--host HOST] [--port PORT]
                 [--user USER] [--password PASSWORD]
                 [--email-secure {None,STARTTLS,SSL/TLS}]
                 [--http-method HTTP_METHOD] [--http-path HTTP_PATH]
                 [--http-content-type {JSON,YAML,URL,multipart}]
                 [--http-timeout SECONDS|NONE] [-P KEY=VALUE]
                 [-H Header:Value]
                 [--oauth2-grant-type {client_credentials,password}]
                 [--oauth2-token-url OAUTH2_TOKEN_URL]
                 [--oauth2-client-id OAUTH2_CLIENT_ID]
                 [--oauth2-client-secret OAUTH2_CLIENT_SECRET]
                 [--oauth2-scope OAUTH2_SCOPE]
                 [--oauth2-refresh-margin #:##:##]
                 [--command "/path/to/command --sender {sender} --receivers {receivers} -- {...entries}"]
                 [--command-cwd PATH] [--command-user USER]
                 [--command-group GROUP] [-E NAME[=VALUE]]
                 [--command-stdin {file:/file/path,null:,inherit:,pipe:FORMAT,/absolute/file/path}]
                 [--command-stdout {file:/file/path,append:/file/path,null:,inherit:,/absolute/file/path}]
                 [--command-stderr {file:/file/path,append:/file/path,null:,stdout:,inherit:,/absolute/file/path}]
                 [--command-interactive] [--command-no-interactive]
                 [--command-timeout SECONDS|NONE] [--keep-connected]
                 [--no-keep-connected] [-d] [--pidfile PATH] [--log-file PATH]
                 [--log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
                 [--log-format FORMAT] [--log-datefmt DATEFMT]
                 [--logmails {always,never,onerror,instead}]
                 [logfiles ...]
```

### Positional Arguments
```
  logfiles              Overwrite the logfiles form the settings. If the given
                        logfile is also configured in the settings it still
                        uses the logfile specific settings for the given
                        logfile.
                        
                        You can read from a SystemD journal instead of a file by
                        specifying a path in the form of:
                        
                            systemd:{LOCAL_ONLY,RUNTIME_ONLY,SYSTEM,CURRENT_USER}[:{UNIT,SYSLOG}:IDENTIFIER]
```

### Options
```
  -h, --help            show this help message and exit
  -v, --version         Print version and exit.
  --license             Show license information and exit.
  --config PATH         Read settings from PATH. [default: $HOME/.logmonrc]
  -A, --action {{http,https,imap,smtp}[:[//][<user>[:<password>]@]<host>[/<path>[?<query>]]],command[:<command> [<option>...]]}
                        Parameters defined here overwrite values passed via
                        other options.
                        
                        For SMTP and IMAP these query parameters are
                        supported:
                          sender ...... same as --sender
                          receivers ... same as --receivers
                          secure ...... same as --email-secure
                        
                        [default: SMTP]
  --sender EMAIL        [default: logmon@<host>]
  --receivers EMAIL,...
                        Comma separated list of email addresses.
                        [default: <sender>]
  --subject TEMPLATE    Subject template for the emails. See --body for the
                        template variables. [default: '{brief}']
  --body TEMPLATE       Body template for the emails.
                        
                        Template variables:
                          {entries} ......... All entries formatted with the
                                              --output-format and
                                              --output-indent options.
                          {entries_str} ..... All entries for the message
                                              concatenated into a string with
                                              two newlines between each.
                          {entries_raw} ..... Raw entries (list[str] for
                                              normal log files or list[dict]
                                              for SystemD or JSON log files).
                          {logfile} ......... The path of the logfile.
                          {entry1} .......... The first log entry of the
                                              message.
                          {line1} ........... The first line of the first log
                                              entry.
                          {brief} ........... Like {line1}, but with the entry
                                              start pattern removed.
                          {entrynum} ........ The number of entries in this
                                              message.
                          {sender} .......... The sender email address.
                          {receivers} ....... Comma separated list of receiver
                                              email addresses.
                          {receiver_list} ... List of receiver email addresses
                                              (list[str]).
                          {nl} .............. A newline character ('\n')
                          {{ ................ A literal {
                          }} ................ A literal }
                        
                        [default: '{logfile}\n\n{entries_str}']
  --wait-file-not-found SECONDS
                        Wait SECONDS before retry if file was not found. Not
                        used if inotify is used. [default: 30]
  --wait-line-incomplete SECONDS
                        Wait SECOONDS for a 2nd read if the read line was not
                        terminated with a newline. Only one wait is performed.
                        [default: 0.1]
  --wait-no-entries SECONDS
                        Wait SECONDS before retry if no new entries where
                        found. Not used if inotify is used. [default: 5]
  --wait-before-send SECONDS
                        Wait SECONDS for more entries before sending email.
                        [default: 1]
  --wait-after-crash SECONDS
                        Wait SECONDS after a monitoring thread crashed.
                        [default: 10]
  --max-entries COUNT   Only gather up to COUNT entries before sending an
                        email. [default: 20]
  --max-entry-lines COUNT
                        Limit the length of a log entry to COUNT lines.
                        [default: 2048]
  --max-emails-per-minute COUNT
                        Limit emails sent per minute to COUNT. Once the limit
                        is reached an error will be logged and no more emails
                        are sent until the message count in the last 60
                        seconds dropped below COUNT. [default: 6]
  --max-emails-per-hour COUNT
                        Same as --max-emails-per-minute but for a span of 60
                        minutes. Both options are evaluated one after another.
                        [default: 60]
  --use-inotify         This is the default if the `inotify` Python package is
                        installed. [default: True]
  --no-use-inotify      Opposite of --use-inotify
  --entry-start-pattern REGEXP
                        This pattern defines the start of a log entry. A
                        multiline log entry is parsed up until the next start
                        pattern is matched or the end of the file is reached.
                        [default: ^\[\d\d\d\d-\d\d-\d\d[T
                        ]\d\d:\d\d:\d\d(?:\.\d+)?(?:
                        ?(?:[-+]\d\d:?\d\d|Z))?\]]
  --error-pattern REGEXP
                        If this pattern is found within a log entry the whole
                        entry will be sent to the configured receivers.
                        [default: ERROR|CRITICAL|Exception]
  --ignore-pattern REGEXP
                        Even if the error pattern matches, if this pattern
                        also matches ignore the message anyway. Pass an empty
                        string to clear the pattern form the settings file.
                        Per default this is not set.
  --seek-end            Seek to the end of existing files. [default: True]
  --no-seek-end         Opposite of --seek-end
  --json                Every line in the log file is parsed as a JSON
                        document. [default: False]
  --no-json             Opposite of --json
  --json-match PATH=VALUE
                        Nested properties of the JSON document to match
                        against.
                        
                        Operators:
                          = ........ equals
                          != ....... not equals
                          < ........ less than
                          > ........ greater than
                          <= ....... less than or equal
                          >= ....... greater than or equal
                          ~ ........ match regular expression
                          in ....... value in a list or range of given values
                          not in ... value not in a list or range of given
                                     values
                        
                        The argument to in and not in can be a list like
                        ["foo", "bar"] or a range definition like {"start": 0,
                        "stop": 10}. Start is inclusive, stop is exclusive.
                        
                        When multiple --json-match are defined all have to
                        match.
                        Per no filter is defined.
  --json-ignore PATH=VALUE
                        Same match syntax as --json-match, but if this matches
                        the log entry is ignored.
  --json-brief PATH     Path to the JSON field
  --output-indent OUTPUT_INDENT
                        When JSON or YAML data is included in the email indent
                        by this number of spaces. [default: 4]
  --output-format {JSON,YAML}
                        Format structured data in emails using this format.
                        [default: YAML]
  --systemd-priority {PANIC,WARNING,ALERT,NONE,CRITICAL,DEBUG,INFO,ERROR,NOTICE}
                        Only report log entries of this or higher priority.
  --systemd-match KEY=VALUE
  --host HOST           [default: localhost]
  --port PORT           [default: depends on --action and --email-secure]
  --user USER
  --password PASSWORD
  --email-secure {None,STARTTLS,SSL/TLS}
  --http-method HTTP_METHOD
                        [default: GET]
  --http-path HTTP_PATH
                        [default: /]
  --http-content-type {JSON,YAML,URL,multipart}
                        [default: URL]
  --http-timeout SECONDS|NONE
                        [default: no timeout]
  -P, --http-param KEY=VALUE
                        [default: subject={subject} receivers={receivers}]
  -H, --http-header Header:Value
  --oauth2-grant-type {client_credentials,password}
                        [default: client_credentials]
  --oauth2-token-url OAUTH2_TOKEN_URL
  --oauth2-client-id OAUTH2_CLIENT_ID
  --oauth2-client-secret OAUTH2_CLIENT_SECRET
  --oauth2-scope OAUTH2_SCOPE
  --oauth2-refresh-margin #:##:##
                        Subtract this time-span from the access token
                        expiration date. [default: 0]
  --command "/path/to/command --sender {sender} --receivers {receivers} -- {...entries}"
                        When --action=COMMAND then run this command. The
                        command is interpolated with the same format as --body
                        plus an additional special parameter {...entries} wich
                        will repeat that argument for each entry. E.g. if you
                        have the command "mycommand --entry={...entries}" and
                        the entries are just "foo" and "bar" the command that
                        will be executed is:
                        
                            mycommand --entry=foo --entry=bar
                        
                        The command string is parsed as a list of strings with
                        Python's `shlex.split()` before interpolation takes
                        place and is executed as that list with
                        `Popen(args=command)` and not with a shell in order
                        pro prevent command injections.
  --command-cwd PATH    Run command in PATH. All other paths are thus relative
                        to this.
                        [default is the current working directory of logmon]
  --command-user USER   Run command as USER.
                        [default is the user of the logmon process]
  --command-group GROUP
                        Run command as GROUP.
                        [default is the group of the logmon process]
  -E, --command-env NAME[=VALUE]
                        Replace the environment of the command. Pass this
                        option multiple times for multiple environment
                        variables. Only pass a NAME in order to copy the value
                        from the environment of the logmon process.
                        [default is the environment of the logmon process]
  --command-stdin {file:/file/path,null:,inherit:,pipe:FORMAT,/absolute/file/path}
                        When using "pipe:" the FORMAT is interpolated and
                        written to stdin of the spawned process. It has the
                        same parameters as the format of --body plus an
                        additional special parameter {...entries} which will
                        repeat the whole format for each log entry. Meaning if
                        FORMAT is "before {...entries} after{nl}" and the
                        entries are just "foo" and "bar" then this is written
                        to stdin:
                        
                            before foo after
                            before bar after
                        
                        [default: null:]
  --command-stdout {file:/file/path,append:/file/path,null:,inherit:,/absolute/file/path}
  --command-stderr {file:/file/path,append:/file/path,null:,stdout:,inherit:,/absolute/file/path}
  --command-interactive
                        Use this when the spawned process is
  --command-no-interactive
                        Opposite of --command-interactive
  --command-timeout SECONDS|NONE
                        Wait SECONDS for process to finish. If the procress is
                        still running on shutdown and the timeout is exceeded
                        the process will be killed.
                        [default: NONE]
  --keep-connected
  --no-keep-connected
  -d, --daemonize       Fork process to the background. Send SIGTERM to the
                        logmon process for shutdown.
  --pidfile PATH        Write logmons PID to given file. Useful in combination
                        with --background.
  --log-file PATH       Logfile of logmon itself. If not given writes to
                        standard out.
  --log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Log level of logmon itself.
  --log-format FORMAT   Format of log entries of logmon itself. [default:
                        [%(asctime)s] [%(process)d] %(levelname)s:
                        %(message)s]
  --log-datefmt DATEFMT
                        Format of the timestamp of log entries of logmon
                        itself. [default: %Y-%m-%dT%H:%M:%S%z]
  --logmails {always,never,onerror,instead}
                        Log emails to the Python logger.
                        
                        never ..... Never log emails
                        always .... Always log emails
                        onerror ... Log emails if sending failed
                        instead ... Log emails instead of sending them. Useful
                                    for debugging.
                        
                        [default: onerror]
```

Settings
--------

The settings file uses YAML, although if neitehr `ruamel.yaml` nor `PyYAML` is
installed it falls back to just JSON.

Example:

```YAML
---
do:
  action: SMTP # same syntax as --action
  host: mail.example.com
  port: 25
  secure: STARTTLS # or SSL/TLS or None
  sender: "Alice <alice@example.com>"
  receivers:
  - bob@example.com
  - charly@example.com
  user: alice@example.com
  password: password1234
  logmails: onerror

default:
  # Default configuration for every log
  # entry that doesn't overwrite this.
  # This secion and everything in it is
  # optional.
  entry_start_pattern: >-
    ^\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\]
  error_pattern: "(?i)ERROR|CRIT"
  ignore_pattern: "SSL: error:0A00006C:"
  wait_line_incomplete: 0.1
  wait_file_not_found: 30
  wait_no_entries: 5
  wait_before_send: 1
  wait_after_crash: 10
  max_entries: 20
  max_entry_lines: 2048
  use_inotify: true
  seek_end: true
  # json: true means the log file contains a JSON document per line.
  json: false
  json_match:
    # operators: =, !=, <, >, <=, >=, in, not in
    # in and not in can either have an array of values as the argument
    # or an object in the form of: {"start": 0, "stop": 10} (int only)
    level: ['in', ['ERROR', 'CRITICAL']]
    some:
      nested:
        field: ['=', 12]
    a_list:
      15: ['>=', 123]
  json_ignore:
    message: ['~', '(?i)test']
  json_brief: ['message']
  output_indent: 4
  output_format: YAML # or JSON
  systemd_priority: ERROR
  systemd_match:
    _SYSTEMD_USER_UNIT: plasma-kwin_x11.service
  command: ["/usr/local/bin/my_command", "{sender}", "{receivers}",
  "{...entries}"]
  command_user: myuser
  command_group: mygroup
  command_stdin: "null:" # or file:..., inherit:, pipe:FORMAT
  command_stdout: "null:" # or file:..., append:..., inherit:
  command_stderr: "null:" # or file:..., append:..., inherit:, stdout:
  command_interactive: True
  command_timeout: 3.5 # or None
limits:
  max_emails_per_minute: 6
  max_emails_per_hour: 60

logfiles:
  # This can be a simple list of strings,
  # which will then use the default settings
  # for every file, or a mapping with
  # overloaded settings for each file.
  /var/log/service1.log:
    entry_start_pattern: >-
      ^\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d:
  /var/log/service2.log: {}
  /var/log/service3.log:
    subject: "[SERVICE 3] {brief}"
    receivers:
    - daniel@example.com
log:
  # These are the logging settings for logmon
  # itself. This section and everthing in it is
  # optional.

  # Per default logs are written to standard
  # output.
  file: /var/log/logmon.log
  level: INFO
  format: "[%(asctime)s] [%(process)d] %(levelname)s: %(message)s"
  datefmt: "%Y-%m-%dT%H:%M:%S%z"

# Per default no pidfile is written. Optional.
pidfile: /var/run/logmon.pid
```

License
-------

Copyright &copy; 2025-2026  Mathias Panzenböck

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
