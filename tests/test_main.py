from typing import Optional, TypedDict, Generator, Any

import os
import sys
import json
import pytest

from os.path import join as join_path
from tempfile import gettempdir
from pathlib import Path
from time import sleep
from subprocess import Popen, PIPE
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

SRC_PATH = str(Path(__file__).resolve().parent.parent)
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

def indent(text: str, width: int=4) -> str:
    prefix = ' ' * width
    return prefix + text.replace('\n', '\n' + prefix)

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

class ExampleLog(TypedDict):
    header: str
    message: str

def write_logs(logfiles: list[str]) -> Generator[list[ExampleLog], None, None]:
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

    yield [
        { "header": errmsg1hdr, "message": errmsg1 },
        { "header": errmsg2hdr, "message": errmsg2 },
    ]

    with open(logfiles[1], 'w') as fp2:
        errmsg3hdr = "ERROR: Starts with an error!"
        errmsg3_1 = f"[2025-12-14T20:16:00+0100] {errmsg3hdr}"
        errmsg3_2 = "Which is actually multi line!"
        print(errmsg3_1, file=fp2); fp2.flush()
        print(errmsg3_2, file=fp2); fp2.flush()
        print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp2); fp2.flush()

    yield [
        { "header": errmsg3hdr, "message": f"{errmsg3_1}\n{errmsg3_2}" },
    ]

    with open(logfiles[2], 'w') as fp3:
        pass

    yield []

def test_simple(logmonrc_path: str, logfiles: list[str]):
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    logmonrc = f'''\
---
do:
  action: SMTP
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
        [sys.executable, '-m', 'logmon', '--config', logmonrc_path, '--logmails=instead'],
        cwd=SRC_PATH,
        stdout=PIPE,
        stderr=PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    sleep(0.5)

    status: Optional[int] = proc.returncode

    logs: list[list[ExampleLog]] = []
    for l in write_logs(logfiles):
        logs.append(l)

        status: Optional[int] = proc.returncode
        if status is not None and status != 0:
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()

            sys.stdout.buffer.write(stdout)
            sys.stdout.flush()

            sys.stderr.buffer.write(stderr)
            sys.stderr.flush()

            assert status == 0

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
> Subject: {logs[0][0]['header']}
> From: {sender}
> To: {', '.join(receivers)}
> 
> {logfiles[0]}
> 
> {logs[0][0]['message']}
> 
> 
> {logs[0][1]['message']}
> 
'''

    expected2 = f'''\
{logfiles[1]}: Simulate sending email
> Subject: {logs[1][0]['header']}
> From: {sender}
> To: {', '.join(receivers)}
> 
> {logfiles[1]}
> 
> {logs[1][0]['message'].replace('\n', '\n> ')}
> 
'''

    assert expected1 in stderr, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(stderr)}'
    assert expected2 in stderr, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(stderr)}'

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close()
    proc.stdout.close()

#@pytest.mark.skip("TODO: test_http")
def test_http(logmonrc_path: str, logfiles: list[str]):
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    logmonrc = f'''\
---
do:
  action: http://localhost:8080/log
  http_method: POST
  http_content_type: JSON
  http_params:
    sender: "{{sender}}"
    receivers: "{{receivers}}"
    entries: "{{...entries}}"
    subject: "{{subject}}"
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

    entries: list[Any] = []
    server_errors: list[Exception] = []

    def do_illegal_method(self: BaseHTTPRequestHandler) -> None:
        try:
            self.send_response(405)
            self.end_headers()
            self.wfile.write(b'')

            raise Exception(f"unexpected {self.command} request")
        except Exception as exc:
            server_errors.append(exc)

    class Handler(BaseHTTPRequestHandler):
        do_GET     = do_illegal_method
        do_PUT     = do_illegal_method
        do_PATCH   = do_illegal_method
        do_DELETE  = do_illegal_method
        do_HEAD    = do_illegal_method
        do_OPTIONS = do_illegal_method
        do_TRACE   = do_illegal_method

        def do_POST(self):
            try:
                assert self.path == "/log"

                content_type = self.headers.get('Content-Type')
                content_len = int(self.headers.get('Content-Length') or '0')
                post_body = self.rfile.read(content_len)

                assert content_type is not None
                content_type = content_type.split(';', 1)[0]
                assert content_type == 'application/json'

                entries.append(json.loads(post_body))

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()

                self.wfile.write('{"success": true}'.encode())
            except Exception as exc:
                server_errors.append(exc)


    server = HTTPServer(('localhost', 8080), Handler)
    thread = Thread(target=lambda: server.serve_forever())
    thread.start()

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
    for l in write_logs(logfiles):
        logs.append(l)

        status: Optional[int] = proc.returncode
        if status is not None and status != 0:
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()

            sys.stdout.buffer.write(stdout)
            sys.stdout.flush()

            sys.stderr.buffer.write(stderr)
            sys.stderr.flush()

            assert status == 0

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

    server.shutdown()
    thread.join()
    server.server_close()

    assert server_errors == []

    def assert_entry(props: dict[str, Any]):
        for entry in entries:
            if isinstance(entry, dict):
                missing = False
                for key, expected in props.items():
                    actual = entry.get(key)
                    if actual != expected:
                        missing = True
                        break

                if not missing:
                    return

        assert False, f"""\
Entry not found:

    Entry:

{indent(json.dumps(props, indent=4), 8)}

    Entries:

{indent(json.dumps(entries, indent=4), 8)}
"""

    assert_entry({
        "subject": logs[0][0]['header'],
        "sender": sender,
        "receivers": ', '.join(receivers),
        "entries": [
            logs[0][0]['message'] + "\n",
            logs[0][1]['message'] + "\n",
        ]
    })

    assert_entry({
        "subject": logs[1][0]['header'],
        "sender": sender,
        "receivers": ', '.join(receivers),
        "entries": [
            logs[1][0]['message'] + "\n",
        ]
    })

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close()
    proc.stdout.close()

# TODO: test all features
