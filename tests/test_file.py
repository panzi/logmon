import os

from os.path import join as join_path

from tests.testutils import *

def test_file(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
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

    proc, logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path)

    expected1 = f'''\
{logs[0][0]['message']}
{logs[0][1]['message']}
'''

    expected2 = f'''\
{logs[1][0]['message']}
'''

    with open(file_path) as fp:
        output = fp.read()

    assert expected1 in output, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(output)}'
    assert expected2 in output, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(output)}'

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore
