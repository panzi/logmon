from typing import TypedDict, Generator, IO, Optional, Callable, Literal, TextIO, TypeVar, overload

import sys
import gzip
import bz2

try:
    from compression import zstd
except ImportError:
    zstd = None # type: ignore

from time import sleep
from pathlib import Path
from select import poll, POLLIN, POLLRDHUP, POLLHUP
from subprocess import Popen, PIPE

__all__ = (
    'SRC_PATH',
    'indent',
    'write_file',
    'read_file',
    'read_file_if_exists',
    'ExampleLog',
    'write_logs',
    'pipe_io',
    'run_logmon',
    'Compression',
    'open_compressed_file',
)

SRC_PATH = str(Path(__file__).resolve().parent.parent)

def indent(text: str, width: int=4) -> str:
    prefix = ' ' * width
    return prefix + text.replace('\n', '\n' + prefix)

def write_file(filepath: str|Path, contents: str) -> None:
  path = Path('.').joinpath(filepath)
  path.parent.mkdir(parents=True, exist_ok=True)
  data = contents.encode()
  path.write_bytes(data)
  print(f"{filepath}: written {len(data)} bytes", file=sys.stderr)

def read_file(filepath: str|Path) -> str:
    with open(filepath, "r") as fp:
        return fp.read()

@overload
def read_file_if_exists(filepath: str|Path, default: str) -> str: ...

@overload
def read_file_if_exists(filepath: str|Path, default: Optional[str] = None) -> Optional[str]: ...

def read_file_if_exists(filepath: str|Path, default: Optional[str] = None) -> Optional[str]:
    try:
        return read_file(filepath)
    except FileNotFoundError:
        return default

class ExampleLog(TypedDict):
    header: str
    message: str

Compression = Literal['gzip', 'bz2', 'zstd']

def open_compressed_file(path: str, compression: Compression|None) -> TextIO:
    match compression:
        case None:
            return open(path, 'wt')

        case 'gzip':
            return gzip.open(path, 'wt')

        case 'bz2':
            return bz2.open(path, 'wt')

        case 'zstd':
            assert zstd is not None
            return zstd.open(path, 'wt')

        case _:
            raise ValueError(f'Unsupported compression: {compression!r}')

def write_logs(logfiles: list[str], compression: Compression|None = None) -> Generator[list[ExampleLog], None, None]:
    sleep(0.25)

    with open_compressed_file(logfiles[0], compression) as fp1:
        print("[2025-12-14T20:15:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        print("[2025-12-14T20:16:00+0100] INFO: Info message.", file=fp1); fp1.flush()
        errmsg1hdr = "ERROR: Something failed!"
        errmsg2hdr = "CRITICAL: Something else failed!"
        errmsg1 = f"[2025-12-14T20:17:00+0100] {errmsg1hdr}"
        errmsg2 = f"[2025-12-14T20:18:00+0100] {errmsg2hdr}"
        print(errmsg1, file=fp1); fp1.flush()
        print(errmsg2, file=fp1); fp1.flush()
        print("[2025-12-14T20:19:00+0100] INFO: Ok again.", file=fp1); fp1.flush()

    yield [
        { "header": errmsg1hdr, "message": errmsg1 },
        { "header": errmsg2hdr, "message": errmsg2 },
    ]

    sleep(0.25)

    with open_compressed_file(logfiles[1], compression) as fp2:
        errmsg3hdr = "ERROR: Starts with an error!"
        errmsg3_1 = f"[2025-12-14T20:16:00+0100] {errmsg3hdr}"
        errmsg3_2 = "Which is actually multi line!"
        print(errmsg3_1, file=fp2); fp2.flush()
        print(errmsg3_2, file=fp2); fp2.flush()
        print("[2025-12-14T20:17:00+0100] INFO: Ok again.", file=fp2); fp2.flush()

    yield [
        { "header": errmsg3hdr, "message": f"{errmsg3_1}\n{errmsg3_2}" },
    ]

    sleep(0.25)

    with open_compressed_file(logfiles[2], compression) as fp3:
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
                if (POLLRDHUP | POLLHUP) & event:
                    wait_stdout = False
                    poller.unregister(stdout.fileno())
                closed = not wait_stdout

            elif fd == stderr.fileno():
                infile = stderr
                outfile = sys.stderr
                buf = stderr_buf
                if (POLLRDHUP | POLLHUP) & event:
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

T = TypeVar('T')

@overload
def run_logmon(logfiles: list[str], *args: str, compression: Compression|None=None) -> tuple[list[list[ExampleLog]], str, str]: ...

@overload
def run_logmon(logfiles: list[str], *args: str, write_logs: Callable[[list[str], Compression|None], Generator[list[T], None, None]], compression: Compression|None=None) -> tuple[list[list[T]], str, str]: ...

def run_logmon(
        logfiles: list[str],
        *args: str,
        write_logs: Callable[[list[str], Compression|None], Generator[list[T], None, None]]=write_logs, # type: ignore
        compression: Compression|None=None,
) -> tuple[list[list[T]], str, str]:
    proc = Popen(
        [sys.executable, '-m', 'logmon', *args],
        cwd=SRC_PATH,
        stdout=PIPE,
        stderr=PIPE,
    )

    with proc:
        assert proc.stdout is not None
        assert proc.stderr is not None

        sleep(0.25)

        status: Optional[int] = proc.returncode

        logs: list[list[T]] = []

        try:
            for l in write_logs(logfiles, compression):
                logs.append(l)

                status = proc.returncode
                if status is not None and status != 0:
                    assert status == 0

            sleep(1.75)

            proc.terminate()

            status = proc.wait(5)
        finally:
            stdout, stderr = pipe_io(proc.stdout, proc.stderr)

        assert proc.returncode == 0

        return logs, stdout, stderr
