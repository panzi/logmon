from typing import Generator

import os
import json

from os.path import join as join_path

from tests.testutils import *

def write_json_logs(logfiles: list[str]) -> Generator[list[dict], None, None]:
    with open(logfiles[0], 'w') as fp1:
        fp1.write(json.dumps({
            "datetime": "2025-12-14T20:15:00+0100",
            "level": "INFO",
            "message": "Info message.",
        }) + "\n"); fp1.flush()

        fp1.write(json.dumps({
            "datetime": "2025-12-14T20:16:00+0100",
            "level": "INFO",
            "message": "Info message.",
        }) + "\n"); fp1.flush()

        fp1.write(json.dumps(err1 := {
            "datetime": "2025-12-14T20:17:00+0100",
            "level": "ERROR",
            "message": "Something failed!",
        }) + "\n"); fp1.flush()

        fp1.write(json.dumps(err2 := {
            "datetime": "2025-12-14T20:18:00+0100",
            "level": "CRITICAL",
            "message": "Something else failed!",
        }) + "\n"); fp1.flush()

        fp1.write(json.dumps({
            "datetime": "2025-12-14T20:19:00+0100",
            "level": "INFO",
            "message": "Ok again.",
        }) + "\n"); fp1.flush()

    yield [err1, err2]

    with open(logfiles[1], 'w') as fp2:
        fp2.write(json.dumps(err3 := {
            "datetime": "2025-12-14T20:16:00+0100",
            "level": "ERROR",
            "message": "Starts with an error!\nWhich is actually multi line!",
        }) + "\n"); fp2.flush()

        fp2.write(json.dumps({
            "datetime": "2025-12-14T20:17:00+0100",
            "level": "INFO",
            "message": "Ok again.",
        }) + "\n"); fp2.flush()

    yield [err3]

    with open(logfiles[2], 'w') as fp3:
        pass

    yield []

def test_json(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
  output_format: JSON
  output_indent: null
default:
  json: true
  json_match:
    level: ['in', [ERROR, CRITICAL]]
  json_breif: message
  use_inotify: true
  seek_end: true
log:
  format: "%(message)s"
logfiles:
  "{logfiles[0]}": {{}}
  "{logfiles[1]}": {{}}
  "{logfiles[2]}": {{}}
'''
    write_file(logmonrc_path, logmonrc)

    proc, logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, write_logs=write_json_logs)

    output: list[dict] = []
    with open(file_path) as fp:
        for line in fp:
            output.append(json.loads(line))

    nr = 0
    for logentries in logs:
        for entry in logentries:
            nr += 1
            assert entry in output, (
                f'Message {nr} not found in output!\n'
                 '\n'
                 '  Message:\n'
                 '\n'
                f'{indent(json.dumps(entry, indent=2))}\n'
                 '\n'
                 '  Output:\n'
                 '\n'
                f'{indent(json.dumps(output, indent=2))}'
            )

    assert len(output) == sum(len(logentries) for logentries in logs)

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore
