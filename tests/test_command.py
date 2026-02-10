import os

from tests.testutils import *

def test_command(logmonrc_path: str, logfiles: list[str]) -> None:
    logmonrc = f'''\
---
do:
  command_stdin: "pipe:{{entries_str}}"
  command_stdout: "inherit:"
  command_stderr: "inherit:"
  entries_delimiter: ""
log:
  format: "%(message)s"
logfiles:
  "{logfiles[0]}": "command:{{python}} tests/tee.py {logfiles[0]}.out"
  "{logfiles[1]}":
    do:
      action: command
      command:
      - "{{python}}"
      - "tests/print_entries.py"
      - "--entry={{...entries}}"
      - "{logfiles[1]}.out"
  "{logfiles[2]}":
    do:
      action: command
      command:
      - "{{python}}"
      - "-c"
      - |
        import sys

        with open({(logfiles[2] + '.out')!r}, "wt") as fp:
            for line in sys.stdin:
                fp.write(line)
                sys.stdout.write(line)
'''
    write_file(logmonrc_path, logmonrc)

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
    #output3 = read_file(f'{logfiles[2]}.out')

    assert expected1 in output1, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(output1)}'
    assert expected2 in output2, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(output2)}'
    #assert output3.strip() == ""

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')
