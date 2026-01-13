from typing import Generator, Optional

import os
import sys
import json

from time import sleep
from subprocess import Popen, PIPE
from cysystemd import journal
from cysystemd.journal import Priority

from os.path import join as join_path

from tests.testutils import *

def write_systemd_logs(prefix: str) -> Generator[list[str], None, None]:
    journal.send(
        priority = Priority.INFO,
        message = "Info message.",
        SYSLOG_IDENTIFIER = f'{prefix}1',
    )
    journal.send(
        priority = Priority.INFO,
        message = "Info message.",
        SYSLOG_IDENTIFIER = f'{prefix}1',
    )
    journal.send(
        priority = Priority.ERROR,
        message = (err1 := "Something failed!"),
        SYSLOG_IDENTIFIER = f'{prefix}1',
    )
    journal.send(
        priority = Priority.CRITICAL,
        message = (err2 := "Something else failed!"),
        SYSLOG_IDENTIFIER = f'{prefix}1',
    )
    journal.send(
        priority = Priority.INFO,
        message = "Ok again.",
        SYSLOG_IDENTIFIER = f'{prefix}1',
    )

    yield [err1, err2]

    journal.send(
        priority = Priority.ERROR,
        message = (err3 := "Starts with an error!\nWhich is actually multi line!"),
        SYSLOG_IDENTIFIER = f'{prefix}2',
    )
    journal.send(
        priority = Priority.INFO,
        message = "Ok again.",
        SYSLOG_IDENTIFIER = f'{prefix}2',
    )

    yield [err3]
    yield []

    journal.send(
        priority = Priority.ERROR,
        message = (err4 := "\n\n"),
        SYSLOG_IDENTIFIER = f'{prefix}4',
    )

    yield [err4]

def test_systemd(logmonrc_path: str, temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path1 = join_path(tempdir, f'{prefix}.output1.log')
    file_path2 = join_path(tempdir, f'{prefix}.output2.log')
    service_prefix = f'logmon_test_{os.getpid()}_'
    logmonrc = f'''\
---
do:
  action: "file:{file_path1}"
  output_format: JSON
  output_indent: null
default:
  systemd_priority: ERROR
  seek_end: true
log:
  format: "%(message)s"
logfiles:
  "systemd:CURRENT_USER:SYSLOG:{service_prefix}1": {{}}
  "systemd:CURRENT_USER:SYSLOG:{service_prefix}2": {{}}
  "systemd:CURRENT_USER:SYSLOG:{service_prefix}3": {{}}
  "systemd:CURRENT_USER":
    do: "file:{file_path2}"
    systemd_ignore:
      SYSLOG_IDENTIFIER: "{service_prefix}1"
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

    logs: list[list[str]] = []

    try:
        for l in write_systemd_logs(service_prefix):
            logs.append(l)

            status: Optional[int] = proc.returncode
            if status is not None and status != 0:
                assert status == 0

        sleep(0.5)

        proc.terminate()

        status = proc.wait(5)
    finally:
        stdout, stderr = pipe_io(proc.stdout, proc.stderr)

    assert proc.returncode == 0

    output1: list[dict] = []
    with open(file_path1) as fp:
        for line in fp:
            output1.append(json.loads(line))

    output2: list[dict] = []
    with open(file_path2) as fp:
        for line in fp:
            output2.append(json.loads(line))

    output1_messages = [o['MESSAGE'] for o in output1]
    output2_messages = [o['MESSAGE'] for o in output2]

    nr = 0
    for logentries in logs[:-1]:
        for entry in logentries:
            nr += 1
            assert entry in output1_messages, (
                f'Message {nr} not found in output!\n'
                 '\n'
                 '  Message:\n'
                 '\n'
                f'{indent(entry)}\n'
                 '\n'
                 '  Output:\n'
                 '\n'
                f'{indent('\n'.join(output1_messages))}'
            )

    for logentries in logs[1:4]:
        for entry in logentries:
            nr += 1
            assert entry in output2_messages, (
                f'Message {nr} not found in output!\n'
                 '\n'
                 '  Message:\n'
                 '\n'
                f'{indent(entry)}\n'
                 '\n'
                 '  Output:\n'
                 '\n'
                f'{indent('\n'.join(output2_messages))}'
            )

    assert len(output1_messages) == sum(len(logentries) for logentries in logs[:-1])
    assert len(output2_messages) == sum(len(logentries) for logentries in logs[1:4])

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore
