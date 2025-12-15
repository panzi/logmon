from typing import Self, Optional

import os
import sys
import pytest
import threading

from os.path import join as join_path
from pytest_mock import MockerFixture
from tempfile import gettempdir
from pathlib import Path
from email.message import EmailMessage
from time import sleep

SRC_PATH = str(Path(__file__).resolve().parent.parent)
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

import logmon

@pytest.fixture(scope="function")
def temp_prefix(request: pytest.FixtureRequest) -> tuple[str, str]:
    tempdir = gettempdir()
    PID = os.getpid()
    func_name = request.function.__name__

    return tempdir, f'logmon.test.{PID}.{func_name}'

@pytest.fixture(scope="function")
def logfiles(temp_prefix: tuple[str, str], count: int = 3) -> list[str]:
    tempdir, prefix = temp_prefix

    return [
        join_path(tempdir, f'{prefix}.logfile{i}.log')
        for i in range(1, count + 1)
    ]

@pytest.fixture(scope="function")
def logmonrc_path(temp_prefix: tuple[str, str]) -> str:
    tempdir, prefix = temp_prefix

    return join_path(tempdir, f'{prefix}.logmonrc.yaml')

def write_file(filepath: str, contents: str) -> None:
  path = Path('.').joinpath(filepath)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(contents)

MockSmtpMap = dict[tuple[str, int], "MockSMTP"]

_mock_smtps_instances: MockSmtpMap = {}
_mock_smtps_instances_lock = threading.Lock()

class MockSMTP:
    host: str
    port: int
    messages: list[EmailMessage]

    def __new__(cls: type[Self], host: str = '', port: int = 0) -> "MockSMTP":
        with _mock_smtps_instances_lock:
            key = (host, port)
            self = _mock_smtps_instances.get(key)
            if self is None:
                self = super().__new__(cls)
                self.__init__(host, port)
                _mock_smtps_instances[key] = self
        return self

    def __init__(self, host: str = '', port: int = 0) -> None:
        self.host = host
        self.port = port
        self.messages = []

    def login(self, user: str, password: str, *, initial_response_ok: bool = True):
        return 235, b''

    def send_message(self, msg: EmailMessage):
        self.messages.append(msg)
        return {}

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

@pytest.fixture(scope="function")
def mock_smtp_map(mocker: MockerFixture):
    global _mock_smtps_instances
    _mock_smtps_instances.clear()
    mocker.patch("smtplib.SMTP", MockSMTP)
    return _mock_smtps_instances

def test_simple(logmonrc_path: str, logfiles: list[str], mock_smtp_map: MockSmtpMap, mocker: MockerFixture):
    mocker.patch("signal.signal", lambda sig, handler: None)

    logmonrc = f'''\
---
email:
  protocol: SMTP
  port: 587
  host: localhost
  sender: alice@example.com
  receivers:
  - bob@example.com
  - charly@example.com
default:
  use_inotify: true
  seek_end: true
logfiles:
  "{logfiles[0]}": {{}}
  "{logfiles[1]}": {{}}
  "{logfiles[2]}":
    entry_start_pattern: >-
      "^{{"
'''
    write_file(logmonrc_path, logmonrc)

    thread_exc: Optional[Exception] = None

    def thread_func():
        nonlocal thread_exc
        try:
            logmon.main(['--config', logmonrc_path])
        except Exception as exc:
            thread_exc = exc

    thread = threading.Thread(target=thread_func)
    thread.start()
    assert thread.ident is not None

    sleep(0.2)
    if thread_exc is not None:
        raise thread_exc

    with open(logfiles[0], 'w') as fp1:
        print("[2025-12-14T20:15:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        print("[2025-12-14T20:16:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        print("[2025-12-14T20:17:00+0100] ERROR: Something failed!", file=fp1); fp1.flush()
        print("[2025-12-14T20:18:00+0100] ERROR: Something else failed!", file=fp1); fp1.flush()
        print("[2025-12-14T20:19:00+0100] INFO: Ok again.", file=fp1); fp1.flush()

    sleep(0.2)
    if thread_exc is not None:
        raise thread_exc

    with open(logfiles[1], 'w') as fp2:
        print("[2025-12-14T20:16:00+0100] ERROR: Starts with an error!", file=fp2); fp2.flush()
        print("Which is actually multi line!", file=fp2); fp2.flush()
        print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp2); fp2.flush()

    with open(logfiles[2], 'w') as fp3:
        pass

    sleep(0.2)
    logmon._running = False

    with open(logfiles[0], 'a') as fp1, open(logfiles[1], 'a') as fp2:
        print("[2025-12-14T20:30:00+0100] INFO: EOF", fp1)
        print("[2025-12-14T20:30:00+0100] INFO: EOF", fp2)

    #signal.pthread_kill(thread.ident, signal.SIGTERM)
    thread.join(3)
    #sleep(3)

    if thread_exc is not None:
        raise thread_exc

    mock_smtp = mock_smtp_map.get(('localhost', 587))
    assert mock_smtp is not None

    assert len(mock_smtp.messages) == 2
    #for msg in mock_smtp.messages:
    #    print(msg.get_content())
    #    print()

    msg = mock_smtp.messages[0]
    assert msg['Subject'] == '[ERROR] [2025-12-14T20:17:00+0100] ERROR: Something failed!'
    assert msg['From'] == 'alice@example.com'
    assert msg['To'] == 'bob@example.com, charly@example.com'
    content = msg.get_content()
    assert content == f'''\
{logfiles[0]}

[2025-12-14T20:17:00+0100] ERROR: Something failed!

[2025-12-14T20:18:00+0100] ERROR: Something else failed!'''

    # TODO: test all messages
