import os

from tests.testutils import *

def test_logmails(logmonrc_path: str, logfiles: list[str]) -> None:
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    logmonrc = f'''\
---
do:
  action: SMTP
  port: 587
  host: localhost
  sender: "{sender}"
  receivers:
  - "{receivers[0]}"
  - "{receivers[1]}"
default:
  use_inotify: true
  seek_end: true
log:
  format: "%(message)s"
logfiles:
  "{logfiles[0]}": {{}}
  "{logfiles[1]}": {{}}
  "{logfiles[2]}":
    entry_start_pattern: >-
      "^{{"
'''
    write_file(logmonrc_path, logmonrc)

    logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, '--logmails=instead')

    expected1 = f'''\
{logfiles[0]}: Simulate sending email
> Subject: {logs[0][0]['header']}
> From: {sender}
> To: {', '.join(receivers)}
> 
> {logfiles[0]}
> 
> {logs[0][0]['message']}
> 
> 
> {logs[0][1]['message']}
> 
'''

    expected2 = f'''\
{logfiles[1]}: Simulate sending email
> Subject: {logs[1][0]['header']}
> From: {sender}
> To: {', '.join(receivers)}
> 
> {logfiles[1]}
> 
> {logs[1][0]['message'].replace('\n', '\n> ')}
> 
'''

    assert expected1 in stderr, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(stderr)}'
    assert expected2 in stderr, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(stderr)}'

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')
