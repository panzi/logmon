import os
import sys

from os.path import join as join_path
from time import sleep
from shutil import rmtree

from tests.testutils import *

def test_glob(logmonrc_path: str, temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    logdir = join_path(tempdir, f'{prefix}.logs')
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
  "{join_path(logdir, 'foo*.log')}":
    glob: true
'''
    write_file(logmonrc_path, logmonrc)

    def write_logs(logfiles: list[str]):
        sleep(0.25)
        os.mkdir(logdir)
        print(f"{logdir}: created directory", file=sys.stderr)

        write_file(join_path(logdir, 'bar.log'), "[2025-12-14T20:15:00+0100] INFO: BAR message.")

        with open(logfiles[0], 'w') as fp1:
            print("[2025-12-14T20:15:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        #sleep(0.5)

        os.unlink(logfiles[0])
        print(f"{logfiles[0]}: deleted", file=sys.stderr)

        with open(logfiles[0], 'w') as fp1:
            print("[2025-12-14T20:16:00+0100] INFO: Info message.", file=fp1); fp1.flush()
            errmsg1hdr = "ERROR: Something failed!"
            errmsg1 = f"[2025-12-14T20:17:00+0100] {errmsg1hdr}"
            print(errmsg1, file=fp1); fp1.flush()
        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        sleep(0.5)

        os.unlink(logfiles[0])
        print(f"{logfiles[0]}: deleted", file=sys.stderr)

        #sleep(2) # XXX: shorter sleep breaks this. it shouldn't!

        with open(logfiles[0], 'w') as fp1:
            errmsg2hdr = "CRITICAL: Something else failed!"
            errmsg2 = f"[2025-12-14T20:18:00+0100] {errmsg2hdr}"
            print(errmsg2, file=fp1); fp1.flush()
            print("[2025-12-14T20:19:00+0100] INFO: Ok again.", file=fp1); fp1.flush()
        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        yield [
            { "header": errmsg1hdr, "message": errmsg1 },
            { "header": errmsg2hdr, "message": errmsg2 },
        ]

        bar2 = join_path(logdir, 'bar2.log')
        with open(bar2, 'w') as fp2:
            errmsg3hdr = "ERROR: Starts with an error!"
            errmsg3_1 = f"[2025-12-14T20:16:00+0100] {errmsg3hdr}"
            errmsg3_2 = "Which is actually multi line!"
            print(errmsg3_1, file=fp2); fp2.flush()
            print(errmsg3_2, file=fp2); fp2.flush()
            print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp2); fp2.flush()
        print(f"{bar2}: written logs", file=sys.stderr)

        #sleep(0.25)

        os.rename(bar2, logfiles[1])
        print(f"{bar2} -> {logfiles[1]}: renamed", file=sys.stderr)

        yield [
            { "header": errmsg3hdr, "message": f"{errmsg3_1}\n{errmsg3_2}" },
        ]

        with open(logfiles[2], 'w') as fp3:
            pass

        print(f"{logfiles[2]}: written empty file", file=sys.stderr)

        yield []

#        sleep(0.25)
#
#        os.unlink(logfiles[0])
#        print(f"{logfiles[0]}: deleted", file=sys.stderr)
#
#        sleep(0.1)

    logfiles = [
        join_path(logdir, 'foo.log'),
        join_path(logdir, 'foo2.log'),
        join_path(logdir, 'foo03.log'),
    ]

    proc, logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, write_logs=write_logs)

    expected1 = f'''\
{logs[0][0]['message']}
{logs[0][1]['message']}
'''

    expected2 = f'''\
{logs[1][0]['message']}
'''

    output = read_file(file_path)

    assert expected1 in output, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(output)}'
    assert expected2 in output, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(output)}'

    for filepath in *logfiles, logmonrc_path, file_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    try:
        rmtree(logdir)
    except Exception as exc:
        print(f'Error deleting {logdir}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore
