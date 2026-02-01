from typing import Generator

import re

from datetime import datetime, timedelta
from os.path import join as join_path
from time import sleep

from tests.testutils import *

def write_limits_logs(logfiles: list[str], compression: Compression|None = None) -> Generator[list[ExampleLog], None, None]:
    d = datetime(2025, 12, 14, 20, 15, 00)
    log1: list[tuple[str, str]] = [
        (f"[{(d + timedelta(seconds=i * 0.01)).isoformat()}]", f"ERROR: error {i}")
        for i in range(20)
    ]
    log2: list[tuple[str, str]] = [
        (f"[{(d + timedelta(seconds=i * 0.01)).isoformat()}]", f"ERROR: error {i}")
        for i in range(4)
    ]
    log3: list[tuple[str, str]] = [
        (f"[{(d + timedelta(seconds=i * 0.01)).isoformat()}]", f"ERROR: error {i}")
        for i in range(5)
    ]

    for logfile, log in zip(logfiles, [log1, log2, log3]):
        with open(logfile, 'wt') as fp:
            for ts, msg in log:
                fp.write(f'{ts} {msg}\n')
                fp.flush()
                sleep(0.01)

        yield [
            { "header": msg, "message": f'{ts} {msg}'}
            for ts, msg in log
        ]

def test_limits(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
default:
  use_inotify: true
  seek_end: true
  wait_line_incomplete: 0
  wait_for_more: 0
log:
  format: "%(message)s"
  level: DEBUG
limits:
  default: null
  limit1:
    max_actions_per_minute: 3
    max_actions_per_hour: 6
  limit2:
    max_actions_per_minute: null
    max_actions_per_hour: 3
logfiles:
  "{logfiles[0]}": "file:{logfiles[0]}.out"
  "{logfiles[1]}":
    do: "file:{logfiles[1]}.out"
    limiter: limit1
  "{logfiles[2]}":
    do:
      action: "file:{logfiles[2]}.out"
      limiter: limit2
'''
    write_file(logmonrc_path, logmonrc)

    logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, write_logs=write_limits_logs)

    #output1 = read_file(f'{logfiles[0]}.out')
    #output2 = read_file(f'{logfiles[1]}.out')
    #output3 = read_file(f'{logfiles[2]}.out')

    assert 'WARNING: [limit1] Maximum actions per minute exceeded!' in stderr
    assert 'WARNING: [limit2] Maximum actions per hour exceeded!'   in stderr

    assert re.search('DEBUG: ' + re.escape(logfiles[0]) + r': Action with \d+ entries was rate limited', stderr) is None
    assert re.search('DEBUG: ' + re.escape(logfiles[1]) + r': Action with \d+ entries was rate limited', stderr) is not None
    assert re.search('DEBUG: ' + re.escape(logfiles[2]) + r': Action with \d+ entries was rate limited', stderr) is not None
