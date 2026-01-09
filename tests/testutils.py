from typing import TypedDict, Generator, IO, Optional

import sys

from time import sleep
from pathlib import Path
from select import poll, POLLIN, POLLRDHUP, POLLHUP
from subprocess import Popen, PIPE

__all__ = (
    'SRC_PATH',
    'indent',
    'write_file',
    'ExampleLog',
    'write_logs',
    'pipe_io',
    'run_logmon',
)

SRC_PATH = str(Path(__file__).resolve().parent.parent)

def indent(text: str, width: int=4) -> str:
    prefix = ' ' * width
    return prefix + text.replace('\n', '\n' + prefix)

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

def run_logmon(logfiles: list[str], *args: str) -> tuple[Popen[bytes], list[list[ExampleLog]], str, str]:
    proc = Popen(
        [sys.executable, '-m', 'logmon', *args],
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

        status = proc.wait(5)
    finally:
        stdout, stderr = pipe_io(proc.stdout, proc.stderr)

    assert proc.returncode == 0

    return proc, logs, stdout, stderr
