import os

from os.path import join as join_path

from tests.testutils import *

def test_multi(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix

    file_path1 = join_path(tempdir, f'{prefix}.output.1.log')
    file_path2 = join_path(tempdir, f'{prefix}.output.2.log')
    file_path3 = join_path(tempdir, f'{prefix}.output.3.log')
    file_path4 = join_path(tempdir, f'{prefix}.output.4.log')

    logmonrc = f'''\
---
default:
  use_inotify: true
  seek_end: true
log:
  format: "%(message)s"
logfiles:
  "{logfiles[0]}":
  - "file:{file_path1}"
  - action: FILE
    file: "{file_path2}"
    file_append: true
  "{logfiles[1]}":
    do:
    - "file:{file_path2}"
    - action: "file:{file_path3}"
  "{logfiles[2]}":
    do:
      action: "file:{file_path4}"
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

    output1 = read_file(file_path1)
    output2 = read_file(file_path2)
    output3 = read_file(file_path3)
    output4 = read_file_if_exists(file_path4, '')

    assert_message_exists(expected1, output1)
    assert_message_exists(expected1, output2)
    assert_message_not_exists(expected1, output3)

    assert_message_exists(expected2, output2)
    assert_message_exists(expected2, output3)
    assert_message_not_exists(expected2, output1)

    assert output4 == ''
  
    for filepath in *logfiles, logmonrc_path, file_path1, file_path2, file_path3, file_path4:
        try:
            if os.path.exists(filepath):
              os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore

def assert_message_exists(message: str, output: str) -> None:
    assert message in output, (
        f'Message not found in output!\n'
        f'\n'
        f'Message:\n'
        f'\n'
        f'{indent(message)}\n'
        f'\n'
        f'Output:\n'
        f'\n'
        f'{indent(output)}\n'
    )

def assert_message_not_exists(message: str, output: str) -> None:
    assert message not in output, (
        f'Message found in output!\n'
        f'\n'
        f'Message:\n'
        f'\n'
        f'{indent(message)}\n'
        f'\n'
        f'Output:\n'
        f'\n'
        f'{indent(output)}\n'
    )
