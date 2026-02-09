logmon
======
[![Test Status](https://img.shields.io/github/actions/workflow/status/panzi/logmon/tests.yml)](https://github.com/panzi/logmon/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/tag/panzi/logmon)](https://github.com/panzi/logmon/tags)
[![GNU General Public License Version 3](https://img.shields.io/github/license/panzi/logmon)](https://github.com/panzi/logmon/blob/main/LICENSE.txt)
[![Config Schema](https://img.shields.io/badge/Config_Schema-informational)](https://panzi.github.io/logmon/)

A log file monitoring script that runs actions like sending emails when it finds
configured error patterns.

Setup
-----

```bash
git clone git@github.com:panzi/logmon.git
cd logmon
uv pip install -r pyproject.toml --extra ruamel_yaml --extra systemd
```

For SystemD support you nead the SystemD library development files because
`cysystemd` compiles bindings at install.

Debian:

```bash
sudo apt install libsystemd-dev
```

Fedora:

```bash
sudo dnf install systemd-devel
```

Dependencies
------------

### Required

* [Pydantic](https://github.com/pydantic/pydantic) - validating the configuration
  file

### Optional

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

Configuration schema:
[![HTML](https://img.shields.io/badge/HTML-red)](https://panzi.github.io/logmon/)
[![YAML](https://img.shields.io/badge/YAML-blue)](https://panzi.github.io/logmon/schema.yaml)

When running via uv:

```bash
uv run logmon.py
```

```
Usage: logmon.py [-h] [-v] [--license] [--config PATH]
                 [-A {{file,http,https,imap,smtp}[:[//][<user>[:<password>]@]<host>[:<port>][/<path>[?<query>]]],command[:<command> [<option>...]],{file,fifo}[:<path>]}]
                 [--sender EMAIL] [--receivers EMAIL,...] [--subject TEMPLATE]
                 [--body TEMPLATE] [--wait-file-not-found SECONDS]
                 [--wait-line-incomplete SECONDS] [--wait-no-entries SECONDS]
                 [--wait-for-more SECONDS] [--wait-after-crash SECONDS]
                 [--max-entries COUNT] [--max-entry-lines COUNT]
                 [--max-actions-per-minute COUNT]
                 [--max-actions-per-hour COUNT] [--use-inotify |
                 --no-use-inotify] [--encoding ENCODING]
                 [--encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}]
                 [--entry-start-pattern REGEXP] [--error-pattern REGEXP]
                 [--ignore-pattern REGEXP] [--seek-end | --no-seek-end]
                 [--json] [--no-json] [--json-match PATH=VALUE]
                 [--json-ignore PATH=VALUE] [--json-brief PATH]
                 [--compression {gzip,bz2,zstd,none}] [--glob] [--no-glob]
                 [--output-indent WIDTH|NONE] [--output-format {JSON,YAML}]
                 [--entries-delimiter STRING] [--null-entries-delimiter]
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
                 [--command-cwd PATH] [--command-user USERID|USERNAME]
                 [--command-group GROUPID|GROUPNAME]
                 [--command-process-group GROUPID] [--command-new-session]
                 [--command-extra-groups GROUPID|GROUPNAME,...]
                 [-E NAME[=VALUE]]
                 [--command-stdin {file:/file/path,null:,inherit:,pipe:FORMAT,/absolute/file/path}]
                 [--command-stdout {file:/file/path,append:/file/path,null:,inherit:,/absolute/file/path}]
                 [--command-stderr {file:/file/path,append:/file/path,null:,stdout:,inherit:,/absolute/file/path}]
                 [--command-interactive] [--command-no-interactive]
                 [--command-timeout SECONDS|NONE] [--command-chroot PATH]
                 [--command-umask UMASK] [--command-nice NICE]
                 [--command-encoding ENCODING]
                 [--command-encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}]
                 [--file FILE] [--file-encoding ENCODING]
                 [--file-encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}]
                 [--file-append] [--no-file-append] [--file-user USER]
                 [--file-group GROUP] [--file-type {regular,fifo}]
                 [--file-compression COMPRESSION]
                 [--file-compression-level LEVEL] [--file-mode MODE]
                 [--keep-connected] [--no-keep-connected] [-d]
                 [--pidfile PATH] [--log-file PATH]
                 [--log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
                 [--log-format FORMAT] [--log-datefmt DATEFMT]
                 [--logmails {always,never,onerror,instead}] [--config-schema]
                 [logfiles ...]
```

### Positional Arguments
```
  logfiles              Overwrite the logfiles form the settings. If the given
                        logfile is also configured in the settings it still
                        uses the logfile specific settings for the given
                        logfile.
                        
                        You can read from a SystemD journal instead of a file
                        by specifying a path in the form of:
                        
                            systemd:[<open_flag>(+<open_flag>)*][:{UNIT,SYSLOG}:<identifier>]
                        
                        Where open_flag can be one of:
                        
                        - LOCAL_ONLY
                        - RUNTIME_ONLY
                        - SYSTEM
                        - CURRENT_USER
                        
                        Examples:
                        
                            systemd:
                            systemd:SYSTEM+LOCAL_ONLY:SYSLOG:sshd
                            systemd::UNIT:sshd.service
```

### Options
```
  -h, --help            show this help message and exit
  -v, --version         Print version and exit.
  --license             Show license information and exit.
  --config PATH         Read settings from PATH. Explicitly passing an empty
                        string to not read any config file. [default:
                        $HOME/.logmonrc]
  -A, --action {{file,http,https,imap,smtp}[:[//][<user>[:<password>]@]<host>[:<port>][/<path>[?<query>]]],command[:<command> [<option>...]],{file,fifo}[:<path>]}
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
                                              --entries-delemeter between each
                                              (default is two newlines).
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
                        [default: 0.04]
  --wait-no-entries SECONDS
                        Wait SECONDS when there are no entries and inotify
                        isn't used. [default: 5]
  --wait-for-more SECONDS
                        Wait SECONDS for more entries before sending email.
                        [default: 0.08]
  --wait-after-crash SECONDS
                        Wait SECONDS after a monitoring thread crashed.
                        [default: 10]
  --max-entries COUNT   Only gather up to COUNT entries before sending an
                        email. [default: 20]
  --max-entry-lines COUNT
                        Limit the length of a log entry to COUNT lines.
                        [default: 2048]
  --max-actions-per-minute COUNT
                        Limit actions performed per minute to COUNT. Once the
                        limit is reached an error will be logged and no more
                        actions are performed until the message count in the
                        last 60 seconds dropped below COUNT. [default: 6]
  --max-actions-per-hour COUNT
                        Same as --max-actions-per-minute but for a span of 60
                        minutes. Both options are evaluated one after another.
                        [default: 60]
  --use-inotify         This is the default if your libc exports the inofify
                        functions. [default: True]
  --no-use-inotify      Opposite of --use-inotify
  --encoding ENCODING
  --encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}
                        [default: replace]
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
  --compression {gzip,bz2,zstd,none}
                        Read a compressed logfile. [default: none]
  --glob                Interpret last segment of a logfile path is a glob
                        pattern. The rest of the path is just a normal path
                        still. This way multiple logfiles can be processed at
                        once and the directory is monitored for changes for
                        when other matching files appear. [default: False]
  --no-glob             Opposite of --glob
  --output-indent WIDTH|NONE
                        When JSON or YAML data is included in the email indent
                        by this number of spaces. [default: 4]
  --output-format {JSON,YAML}
                        Format structured data in emails using this format.
                        [default: YAML]
  --entries-delimiter STRING
                        String used to delimite entries in {entries_str}.
                        [default is two newlines]
  --null-entries-delimiter
                        Use a NULL-byte as the entries delimiter.
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
                        [default: subject={subject} receivers={receivers}
                        entries={entries_raw}]
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
                        
                        Additional parameters:
                        
                        - `{python}` - Path of the Python binary used to
                        execute logmon itself. (`sys.executable`)
                        - `{python_version}` - Full vesrsion string of the
                        Python binary. (`sys.version`)
                        - `{python_version_major}` - `sys.version_info.major`.
                        - `{python_version_minor}` - `sys.version_info.minor`.
                        - `{python_version_micro}` - `sys.version_info.micro`.
                        
  --command-cwd PATH    Run command in PATH. All other paths are thus relative
                        to this.
                        [default is the current working directory of logmon]
  --command-user USERID|USERNAME
                        Run command as USER.
                        [default is the user of the logmon process]
  --command-group GROUPID|GROUPNAME
                        Run command as GROUP.
                        [default is the group of the logmon process]
  --command-process-group GROUPID
                        `setpgid()` to apply for the sub-process.
  --command-new-session
                        If `True` use `setsid()` in the sub-process.
  --command-extra-groups GROUPID|GROUPNAME,...
                        `setgroups()` to apply for the sub-process.
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
  --command-chroot PATH
                        `chroot()` into the given path before the sub-process
                        is executed.
  --command-umask UMASK
                        `umask()` to apply for the sub-process.
  --command-nice NICE   `nice()` to apply for the sub-process.
  --command-encoding ENCODING
                        Encoding used to communicate with sub-process.
  --command-encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}
                        [default: replace]
  --file FILE
  --file-encoding ENCODING
                        [default: "UTF-8"]
  --file-encoding-errors {strict,ignore,replace,surrogateescape,xmlcharrefreplace,backslashreplace,namereplace}
                        [default: replace]
  --file-append
  --no-file-append
  --file-user USER
  --file-group GROUP
  --file-type {regular,fifo}
  --file-compression COMPRESSION
                        Compress the output file. [default: none]
  --file-compression-level LEVEL
                        [default: Python's default for given method]
  --file-mode MODE      File mode, e.g.: `rwxr-x---`, `u=rwx,g=rx,o=`, or
                        `0750`.
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
  --config-schema       Dump config file schema and exit. Uses --output-format
                        and --output-indent.
```

Settings
--------

The settings file uses YAML, although if neitehr `ruamel.yaml` nor `PyYAML` is
installed it falls back to just JSON.

For the configuration file schema and a few simple examples see
<https://panzi.github.io/logmon/> or run `logmon.py --config-schema > schema.yaml`.

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
