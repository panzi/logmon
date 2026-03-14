import os
import sys

from typing import Callable, TextIO
from os.path import join as join_path
from time import sleep
from shutil import rmtree
from threading import Thread

from tests.testutils import *

def _write_regular(path: str, writefn: Callable[[TextIO], None], compression: Compression|None=None) -> None:
    with open_compressed_file(path, compression) as fp:
        writefn(fp)

def _write_fifo(path: str, writefn: Callable[[TextIO], None], compression: Compression|None=None) -> None:
    def target():
        with open_compressed_file(path, compression) as fp:
            writefn(fp)
    os.mkfifo(path)
    thread = Thread(target=target, daemon=True)
    thread.start()

def _test_glob(is_fifo: bool, logmonrc_path: str, temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    logdir = join_path(tempdir, f'{prefix}.logs')
    file_path = join_path(tempdir, f'{prefix}.output.log')

    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
default:
  use_inotify: true
  #use_inotify: false
  wait_no_entries: 0.01
  wait_file_not_found: 0.01
  seek_end: {not is_fifo}
log:
  format: "%(message)s"
logfiles:
  "{join_path(logdir, 'foo*.log')}":
    glob: true
'''
    write_file(logmonrc_path, logmonrc)

    _write = _write_fifo if is_fifo else _write_regular

    def write(path: str, compression: Compression|None=None):
        def _wrapper(fn: Callable[[TextIO], None]):
            _write(path, fn, compression)
            return fn
        return _wrapper

    def write_logs(logfiles: list[str], compression: Compression|None):
        sleep(0.25)
        os.mkdir(logdir)
        print(f"{logdir}: created directory", file=sys.stderr)

        bar = join_path(logdir, 'bar.log')

        @write(bar, compression)
        def _write_bar(fp: TextIO) -> None:
            print("[2025-12-14T20:15:00+0100] INFO: BAR message.", file=fp); fp.flush()

        @write(logfiles[0], compression)
        def _write0_1(fp: TextIO) -> None:
            print("[2025-12-14T20:15:00+0100] INFO: Info message.", file=fp); fp.flush()

        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        sleep(0.25)

        os.unlink(logfiles[0])
        print(f"{logfiles[0]}: deleted", file=sys.stderr)

        errmsg1hdr = "ERROR: Something failed!"
        errmsg1 = f"[2025-12-14T20:17:00+0100] {errmsg1hdr}"

        @write(logfiles[0])
        def _write0_2(fp: TextIO) -> None:
            print("[2025-12-14T20:16:00+0100] INFO: Info message.", file=fp); fp.flush()
            print(errmsg1, file=fp); fp.flush()

        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        sleep(0.5)

        os.unlink(logfiles[0])
        print(f"{logfiles[0]}: deleted", file=sys.stderr)

        #sleep(2) # XXX: shorter sleep breaks this. it shouldn't!

        errmsg2hdr = "CRITICAL: Something else failed!"
        errmsg2 = f"[2025-12-14T20:18:00+0100] {errmsg2hdr}"

        @write(logfiles[0])
        def _write0_3(fp: TextIO) -> None:
            print(errmsg2, file=fp); fp.flush()
            print("[2025-12-14T20:19:00+0100] INFO: Ok again.", file=fp); fp.flush()

        print(f"{logfiles[0]}: written logs", file=sys.stderr)

        yield [
            { "header": errmsg1hdr, "message": errmsg1 },
            { "header": errmsg2hdr, "message": errmsg2 },
        ]

        errmsg3hdr = "ERROR: Starts with an error!"
        errmsg3_1 = f"[2025-12-14T20:16:00+0100] {errmsg3hdr}"
        errmsg3_2 = "Which is actually multi line!"

        bar2 = join_path(logdir, 'bar2.log')
        @write(bar2, compression)
        def _write_bar2(fp: TextIO) -> None:
            print(errmsg3_1, file=fp); fp.flush()
            print(errmsg3_2, file=fp); fp.flush()
            print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp); fp.flush()

        print(f"{bar2}: written logs", file=sys.stderr)

        #sleep(0.25)

        os.rename(bar2, logfiles[1])
        print(f"{bar2} -> {logfiles[1]}: renamed", file=sys.stderr)

        yield [
            { "header": errmsg3hdr, "message": f"{errmsg3_1}\n{errmsg3_2}" },
        ]

        @write(logfiles[2], compression)
        def _write2(fp: TextIO) -> None:
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

    logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, write_logs=write_logs)

    output = read_file(file_path)

    for expected in logs[0][0]['message'], logs[0][1]['message'], logs[1][0]['message']:
        assert expected in output, f'''\
Message not found in output!

  Message:

{indent(expected)}

  Output:

{indent(output)}'''

    for filepath in *logfiles, logmonrc_path, file_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    try:
        rmtree(logdir)
    except Exception as exc:
        print(f'Error deleting {logdir}: {exc}')

def _make_test(is_fifo: bool) -> None:
    def test_glob(logmonrc_path: str, temp_prefix: tuple[str, str]) -> None:
        return _test_glob(is_fifo, logmonrc_path, temp_prefix)
    
    if is_fifo:
        test_glob.__name__ = 'test_glob_fifo'

    globals()[test_glob.__name__] = test_glob

_make_test(False)
_make_test(True)
