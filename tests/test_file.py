from typing import Optional

import os
import sys

from os.path import join as join_path
from time import sleep
from subprocess import Popen, PIPE

from tests.testutils import *

def test_file(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "append:{file_path}"
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

    proc = Popen(
        [sys.executable, '-m', 'logmon', '--config', logmonrc_path],
        cwd=SRC_PATH,
        stdout=PIPE,
        stderr=PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    sleep(0.5)

    status: Optional[int] = proc.returncode

    logs: list[list[ExampleLog]] = []

    try:
        for l in write_logs(logfiles):
            logs.append(l)

            status: Optional[int] = proc.returncode
            if status is not None and status != 0:
                assert status == 0

        sleep(0.25)

        proc.terminate()

        status = proc.wait(5)
    finally:
        pipe_io(proc.stdout, proc.stderr)

    assert proc.returncode == 0

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

    proc.stderr.close()
    proc.stdout.close()

# TODO: test all features
