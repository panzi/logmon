import os

from os.path import join as join_path

from tests.testutils import *

def test_fifo(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
default:
  use_inotify: true
  seek_end: false
log:
  format: "%(message)s"
  file: /tmp/test.log
logfiles:
  "{logfiles[0]}": "file:{logfiles[0]}.out"
  "{logfiles[1]}": "file:{logfiles[1]}.out"
  "{logfiles[2]}":
    do: "file:{logfiles[2]}.out"
    entry_start_pattern: >-
      "^{{"
'''
    write_file(logmonrc_path, logmonrc)

    for logfile in logfiles:
        os.mkfifo(logfile)

    logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path)

    expected1 = f'''\
{logs[0][0]['message']}
{logs[0][1]['message']}
'''

    expected2 = f'''\
{logs[1][0]['message']}
'''

    output1 = read_file(f'{logfiles[0]}.out')
    output2 = read_file(f'{logfiles[1]}.out')

    assert expected1 in output1, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(output1)}'
    assert expected2 in output2, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(output2)}'

    for filepath in *logfiles, logmonrc_path, file_path:
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')
