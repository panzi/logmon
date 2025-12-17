from typing import Optional

import os
import sys
import pytest

from os.path import join as join_path
from tempfile import gettempdir
from pathlib import Path
from time import sleep
from subprocess import Popen, PIPE

SRC_PATH = str(Path(__file__).resolve().parent.parent)
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

def indent(text: str, width: int=4) -> str:
    prefix = ' ' * width
    return '\n'.join(prefix + line for line in text.split('\n'))

@pytest.fixture(scope="function")
def temp_prefix(request: pytest.FixtureRequest) -> tuple[str, str]:
    tempdir = gettempdir()
    PID = os.getpid()
    func_name = request.function.__name__

    return tempdir, f'logmon.test.{PID}.{func_name}'

@pytest.fixture(scope="function")
def logfiles(temp_prefix: tuple[str, str], count: int = 3):
    tempdir, prefix = temp_prefix

    paths = [
        join_path(tempdir, f'{prefix}.logfile{i}.log')
        for i in range(1, count + 1)
    ]

    yield paths

    for path in paths:
        if os.path.exists(path):
            print(f"{path}: was not deleted", file=sys.stderr)

@pytest.fixture(scope="function")
def logmonrc_path(temp_prefix: tuple[str, str]):
    tempdir, prefix = temp_prefix

    path = join_path(tempdir, f'{prefix}.logmonrc.yaml')

    yield path

    if os.path.exists(path):
        print(f"{path}: was not deleted", file=sys.stderr)

def write_file(filepath: str, contents: str) -> None:
  path = Path('.').joinpath(filepath)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(contents)

def test_simple(logmonrc_path: str, logfiles: list[str]):
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    logmonrc = f'''\
---
email:
  protocol: SMTP
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

    proc = Popen(
        [sys.executable, join_path(SRC_PATH, 'logmon.py'), '--config', logmonrc_path, '--logmails=instead'],
        stdout=PIPE,
        stderr=PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    sleep(0.5)

    with open(logfiles[0], 'w') as fp1:
        print("[2025-12-14T20:15:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        print("[2025-12-14T20:16:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        errmsg1hdr = "ERROR: Something failed!"
        errmsg2hdr = "ERROR: Something else failed!"
        errmsg1 = f"[2025-12-14T20:17:00+0100] {errmsg1hdr}"
        errmsg2 = f"[2025-12-14T20:18:00+0100] {errmsg2hdr}"
        print(errmsg1, file=fp1); fp1.flush()
        print(errmsg2, file=fp1); fp1.flush()
        print("[2025-12-14T20:19:00+0100] INFO: Ok again.", file=fp1); fp1.flush()

    status: Optional[int] = proc.returncode
    if status is not None and status != 0:
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()

        sys.stdout.buffer.write(stdout)
        sys.stdout.flush()

        sys.stderr.buffer.write(stderr)
        sys.stderr.flush()

        assert status == 0

    with open(logfiles[1], 'w') as fp2:
        errmsg3hdr = "ERROR: Starts with an error!"
        errmsg3_1 = f"[2025-12-14T20:16:00+0100] {errmsg3hdr}"
        errmsg3_2 = "Which is actually multi line!"
        print(errmsg3_1, file=fp2); fp2.flush()
        print(errmsg3_2, file=fp2); fp2.flush()
        print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp2); fp2.flush()

    with open(logfiles[2], 'w') as fp3:
        pass

    sleep(0.25)

    proc.terminate()

    status = proc.wait()

    stdout = proc.stdout.read()
    stderr = proc.stderr.read()

    sys.stdout.buffer.write(stdout)
    sys.stdout.flush()

    sys.stderr.buffer.write(stderr)
    sys.stderr.flush()

    assert proc.returncode == 0

    stdout = stdout.decode()
    stderr = stderr.decode()

    expected1 = f'''\
{logfiles[0]}: Simulate sending email
> Subject: [ERROR] {errmsg1hdr}\r
> From: {sender}\r
> To: {', '.join(receivers)}\r
> Content-Type: text/plain; charset="utf-8"\r
> Content-Transfer-Encoding: 7bit\r
> MIME-Version: 1.0\r
> \r
> {logfiles[0]}\r
> \r
> {errmsg1}\r
> \r
> \r
> {errmsg2}\r
> 
'''

    expected2 = f'''\
{logfiles[1]}: Simulate sending email
> Subject: [ERROR] {errmsg3hdr}\r
> From: {sender}\r
> To: {', '.join(receivers)}\r
> Content-Type: text/plain; charset="utf-8"\r
> Content-Transfer-Encoding: 7bit\r
> MIME-Version: 1.0\r
> \r
> {logfiles[1]}\r
> \r
> {errmsg3_1}\r
> {errmsg3_2}\r
> 
'''

    assert expected1 in stderr, f'Message not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(stderr)}'
    assert expected2 in stderr, f'Message not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(stderr)}'

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close()
    proc.stdout.close()

# TODO: test all features
