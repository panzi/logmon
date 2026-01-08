from typing import Optional, TypedDict, Generator, Any, Literal, NamedTuple, IO

import os
import sys
import json
import pytest
import pydantic
import traceback

from os.path import join as join_path
from tempfile import gettempdir
from pathlib import Path
from time import sleep
from subprocess import Popen, PIPE
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from base64 import b64encode
from uuid import uuid4
from urllib.parse import parse_qsl
from datetime import datetime, timedelta
from select import poll, POLLIN, POLLRDHUP, POLLHUP

class OAuthTokenRequestBase(pydantic.BaseModel):
    scope: Optional[str|list[str]] = None

class OAuthClientCredentialsRequest(OAuthTokenRequestBase):
    grant_type: Literal['client_credentials']
    client_id: str
    client_secret: str

class OAuthPasswordRequest(OAuthTokenRequestBase):
    grant_type: Literal['password']
    username: str
    password: str

class OAuthRefreshTokenRequest(OAuthTokenRequestBase):
    grant_type: Literal['refresh_token']
    refresh_token: str

class OAuthTokenRequest(pydantic.BaseModel):
    request: OAuthClientCredentialsRequest|OAuthPasswordRequest|OAuthRefreshTokenRequest

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

def pipe_io(stdout: IO[bytes], stderr: IO[bytes]) -> tuple[str, str]:
    poller = poll()
    poller.register(stdout.fileno(), POLLIN | POLLRDHUP)
    poller.register(stderr.fileno(), POLLIN | POLLRDHUP)
    wait_stdout = True
    wait_stderr = True
    prefix = "logmon.py: ".encode()
    infix = b'\n' + prefix

    stdout_buf = bytearray()
    stderr_buf = bytearray()

    while wait_stdout or wait_stderr:
        poll_events = poller.poll(5)

        if not poll_events:
            break

        for fd, event in poll_events:
            if fd == stdout.fileno():
                infile = stdout
                outfile = sys.stdout
                buf = stdout_buf
                if POLLRDHUP & event or POLLHUP & event:
                    wait_stdout = False
                    poller.unregister(stdout.fileno())
                closed = not wait_stdout

            elif fd == stderr.fileno():
                infile = stderr
                outfile = sys.stderr
                buf = stderr_buf
                if POLLRDHUP & event or POLLHUP & event:
                    wait_stderr = False
                    poller.unregister(stderr.fileno())
                closed = not wait_stderr

            else:
                assert False

            if closed:
                rest = infile.read()
                buf.extend(rest)
                outfile.buffer.write(prefix)
                outfile.buffer.write(rest.replace(b'\n', infix))
                outfile.flush()

            elif POLLIN & event:
                line = infile.readline()
                buf.extend(line)
                outfile.buffer.write(prefix)
                outfile.buffer.write(line)
                outfile.flush()

    return (
        stdout_buf.decode(errors='replace'),
        stderr_buf.decode(errors='replace'),
    )

def test_simple(logmonrc_path: str, logfiles: list[str]) -> None:
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
        stdout, stderr = pipe_io(proc.stdout, proc.stderr)

    assert proc.returncode == 0

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

class TokenData(NamedTuple):
    client_id: str
    access_token: str
    scopes: set[str]
    expires_at: datetime

def test_http(logmonrc_path: str, logfiles: list[str]) -> None:
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    client_id = str(uuid4())
    client_secret = b64encode(uuid4().bytes).decode('ISO-8859-1')
    client_id = "test_id"
    client_secret = "test_secret"
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
  http_timeout: 0.5
  oauth2_client_id: "{client_id}"
  oauth2_client_secret: "{client_secret}"
  oauth2_grant_type: client_credentials
  oauth2_token_url: http://localhost:8080/oauth/token
  oauth2_scope: ["write_log"]
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
    access_tokens: dict[str, TokenData] = {}
    token_lifetime = timedelta(hours=1)

    def do_illegal_method(self: BaseHTTPRequestHandler) -> None:
        try:
            self.send_response(405)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "invalid_request",
                "error_description": f"invalid method: {self.command}"
            }).encode())

            raise Exception(f"unexpected {self.command} request")
        except Exception as exc:
            server_errors.append(exc)

    allowed_scopes = {"write_log", "read_log"}

    class Handler(BaseHTTPRequestHandler):
        do_GET     = do_illegal_method
        do_PUT     = do_illegal_method
        do_PATCH   = do_illegal_method
        do_DELETE  = do_illegal_method
        do_HEAD    = do_illegal_method
        do_OPTIONS = do_illegal_method
        do_TRACE   = do_illegal_method

        def do_POST(self) -> None:
            headers_sent = False
            post_body = b''
            data = None
            try:
                content_type = self.headers.get('Content-Type')
                content_len = int(self.headers.get('Content-Length') or 0)
                post_body = self.rfile.read(content_len)
                self.rfile.close()

                assert content_type is not None
                content_type = content_type.split(';', 1)[0]

                if self.path == "/oauth/token":
                    match content_type:
                        case 'application/x-www-form-urlencoded':
                            data = { key.decode(): value.decode() for key, value in parse_qsl(post_body) }

                        case 'application/json':
                            data = json.loads(post_body)

                        case _:
                            assert content_type in ('application/x-www-form-urlencoded', 'application/json')
                            raise ValueError(f'illegal Content-Type: {content_type}')

                    request = OAuthTokenRequest(
                        request=data # type: ignore
                    ).request

                    if not isinstance(request, OAuthClientCredentialsRequest):
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        headers_sent = True
                        self.wfile.write(json.dumps({
                            "error": "unsupported_grant_type"
                        }).encode())
                        return

                    if request.client_id != client_id or request.client_secret != client_secret:
                        # not sure if this is the correct error
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        headers_sent = True
                        self.wfile.write(json.dumps({
                            "error": "invalid_client"
                        }).encode())
                        return

                    scope = request.scope
                    if scope is not None:
                        scope_set = set(scope.split() if isinstance(scope, str) else scope)
                    else:
                        scope_set = {"read_log"} # default scopes

                    if not allowed_scopes.issuperset(scope_set):
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        headers_sent = True
                        self.wfile.write(json.dumps({
                            "error": "invalid_request",
                            "error_description": f"Invalid scopes: {', '.join(sorted(scope_set))}"
                        }).encode())
                        return

                    access_token = b64encode(uuid4().bytes).decode('ISO-8859-1')
                    token = TokenData(
                        client_id    = client_id,
                        access_token = access_token,
                        scopes       = scope_set,
                        expires_at   = datetime.now() + token_lifetime,
                    )
                    access_tokens[access_token] = token
                    response = json.dumps({
                        "access_token": access_token,
                        "token_type": "bearer",
                        "expires_in": token_lifetime.total_seconds(),
                    }).encode()

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(response)
                    return

                if self.path != "/log":
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "not_found"
                    }).encode())
                    return

                assert content_type == 'application/json'

                auth_hdr = self.headers.get('Authorization')
                if not auth_hdr:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "unauthorized_client"
                    }).encode())
                    return

                auth_items = auth_hdr.split()
                if len(auth_items) != 2 or auth_items[0].lower() != "bearer":
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "unauthorized_client"
                    }).encode())
                    return

                access_token = auth_items[1]
                token = access_tokens.get(access_token)
                if token is None or token.client_id != client_id:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "unauthorized_client",
                        "error_description": "invalid access token"
                    }).encode())
                    return

                if token.expires_at <= datetime.now():
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "invalid_grant",
                        "error_description": "access token expired"
                    }).encode())
                    return

                if "write_log" not in token.scopes:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    headers_sent = True
                    self.wfile.write(json.dumps({
                        "error": "invalid_scope",
                        "error_description": "access token misses write_log scope"
                    }).encode())
                    return

                entries.append(json.loads(post_body))

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                headers_sent = True
                self.wfile.write('{"success": true}'.encode())
                self.wfile.write(json.dumps({
                    "success": True
                }).encode())

            except Exception as exc:
                server_errors.append(exc)
                if not headers_sent:
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "server_error",
                    "error_description": f"{post_body.decode(errors='replace')}\n\n{data}\n\n{traceback.format_exc()}"
                }).encode())

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

    try:
        for l in write_logs(logfiles):
            logs.append(l)

            status: Optional[int] = proc.returncode
            if status is not None and status != 0:
                assert status == 0

        sleep(0.5)

        proc.terminate()

        status = proc.wait()
    finally:
        pipe_io(proc.stdout, proc.stderr)

    assert proc.returncode == 0

    server.shutdown()
    thread.join()
    server.server_close()

    assert server_errors == []

    def assert_entry(props: dict[str, Any]) -> None:
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
