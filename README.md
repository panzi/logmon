logmon
======

A very simple log file monitoring script that sends emails when it finds
configured error patterns.

Usage
-----

The settings are read from `$HOME/.logmonrc`, or if run as root from
`/etc/logmonrc`. But don't run it as root, use a dedicated user that can only
read the log files. The command line options overwrite the default settings,
but not the per-logfile settings. See below for the settings file format.

```
Usage: logmon.py [-h] [--config PATH] [--sender EMAIL] [--receivers EMAIL,...]
                 [--subject TEMPLATE] [--body TEMPLATE]
                 [--wait-file-not-found SECONDS]
                 [--wait-line-incomplete SECONDS] [--wait-no-entries SECONDS]
                 [--wait-before-send SECONDS] [--wait-after-crash SECONDS]
                 [--max-entries COUNT] [--max-entry-lines COUNT]
                 [--max-emails-per-minute COUNT] [--max-emails-per-hour COUNT]
                 [--use-inotify | --no-use-inotify]
                 [--entry-start-pattern REGEXP] [--error-pattern REGEXP]
                 [--ignore-pattern REGEXP] [--seek-end | --no-seek-end]
                 [--email-host HOST] [--email-port PORT] [--email-user USER]
                 [--email-password PASSWORD]
                 [--email-secure {None,STARTTLS,SSL/TLS}]
                 [--email-protocol {SMTP,IMAP}] [-d] [--pidfile PATH]
                 [--log-file PATH]
                 [--log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
                 [--log-format FORMAT] [--log-datefmt DATEFMT] [--logmails]
                 [logfiles ...]
```

### Positional Arguments
```
  logfiles              Overwrite the logfiles form the settings. If the given
                        logfile is also configured in the settings it still
                        uses the logfile specific settings for the given
                        logfile.
```

### Options
```
  -h, --help            show this help message and exit
  -v, --version         Print version and exit.
  --config PATH         Read settings from PATH. [default: $HOME/.logmonrc]
  --sender EMAIL
  --receivers EMAIL,...
  --subject TEMPLATE    Subject template for the emails. See --body for the
                        template variables. [default: '[ERROR] {line1}']
  --body TEMPLATE       Body template for the emails.
                        
                        Template variables:
                          {entries} .... All entries for the message
                                         concatenated into a string with two
                                         newlines between each.
                          {logfile} .... The path of the logfile.
                          {entry1} ..... The first log entry of the message.
                          {line1} ...... The first line of the first log
                                         entry.
                          {brief} ...... Like {line1}, but with the entry
                                         start pattern removed.
                          {entrynum} ... The number of entries in this
                                         message.
                          {{ ........... A literal {
                          }} ........... A literal }
                        
                        [default: '{logfile}\n\n{entries}']
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
  --email-host HOST
  --email-port PORT
  --email-user USER
  --email-password PASSWORD
  --email-secure {None,STARTTLS,SSL/TLS}
  --email-protocol {SMTP,IMAP}
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
                        Log emails.
                        
                        never ..... Never log emails
                        always .... Always log emails
                        onerror ... Log emails if sending failed
                        instead ... Log emails instead of sending them.
                                    Useful for debugging.
                        
                        [default: onerror]
```

Settings
--------

The settings file uses YAML, although if `PyYAML` is not installed it falls 
back to just JSON.

Example:

```YAML
---
email:
  protocol: SMTP # or IMAP
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

Copyright &copy; 2025  Mathias Panzenböck

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
