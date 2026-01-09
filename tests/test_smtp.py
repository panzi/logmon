from typing import Optional, Sequence, NamedTuple

import re
import os
import sys
import pytest

from threading import Thread
from socketserver import TCPServer, StreamRequestHandler
from tests.testutils import *

class EMail(NamedTuple):
    sender: str
    receivers: list[str]
    data: str

@pytest.mark.skip("TODO")
def test_smtp(logmonrc_path: str, logfiles: list[str]) -> None:
    host = 'localhost'
    port = (os.getpid() % (65535 - 1024)) + 1024
    sender = "alice@example.com"
    receivers = ["bob@example.com", "charly@example.com"]
    logmonrc = f'''\
---
do:
  action: smtp://{host}:{port}
  sender: "{sender}"
  receivers:
  - "{receivers[0]}"
  - "{receivers[1]}"
default:
  use_inotify: true
  seek_end: true
log:
  format: "%(message)s"
  #file: /tmp/smtp.log
logfiles:
  "{logfiles[0]}": {{}}
  "{logfiles[1]}": {{}}
  "{logfiles[2]}":
    entry_start_pattern: >-
      "^{{"
'''
    write_file(logmonrc_path, logmonrc)

    emails: list[EMail] = []
    server_errors: list[Exception] = []

    class Handler(StreamRequestHandler):
        def recv_command(self) -> Optional[tuple[str, Optional[str]]]:
            while True:
                line = self.rfile.readline()
                if not line:
                    return None

                line = line.decode('ASCII').strip()
                if not line:
                    continue
                with open('/tmp/server.log', 'a') as fp:
                    print('C: ' + line, file=fp)
                cmd = line.split(maxsplit=1)
                arg = cmd[1] if len(cmd) > 1 else None
                return cmd[0], arg

        def expect_command(self) -> tuple[str, Optional[str]]:
            command = self.recv_command()
            if command is None:
                raise ValueError('unexpected end of stream')
            return command

        def send_message(self, status: int, message: str) -> None:
            self.send_message_lines(status, message.split('\n'))

        def send_message_lines(self, status: int, lines: Sequence[str]) -> None:
            buf: list[str] = []
            str_status = str(status)
            if not lines:
                buf.append(str_status)
                buf.append(' \r\n')
            else:
                for line in lines[:-1]:
                    buf.append(str_status)
                    buf.append('-')
                    buf.append(line)
                    buf.append('\r\n')

                buf.append(str_status)
                buf.append(' ')
                buf.append(lines[-1])
                buf.append('\r\n')

            message = ''.join(buf)
            with open('/tmp/server.log', 'a') as fp:
                print('S: ' + message.rstrip().replace('\r\n', '\nS: '), file=fp)
            self.wfile.write(message.encode('ASCII'))
            self.wfile.flush()

        def handle(self) -> None:
            try:
                self.send_message(220, f'{host} ESMTP MockServer')

                while True:
                    command = self.recv_command()
                    if command is None:
                        break

                    cmd, arg = command

                    match cmd.upper():
                        case 'HELO':
                            self.send_message(250, f'Hello {arg or ""}')

                        case 'EHLO':
                            adr = f'[127.0.0.1]'
                            self.send_message_lines(250, [
                                f'{host} Hello {arg} {adr}',
                                'SIZE 14680064',
                            ])

                        case 'QUIT':
                            self.send_message(211, 'Bye')
                            break

                        case 'MAIL':
                            sender: Optional[str] = None
                            receivers: list[str] = []

                            try:
                                assert arg is not None
                                what, adr, args = parse_mail_line(arg)
                                assert what.upper() == 'FROM'
                            except Exception as exc:
                                raise ValueError(f'unexpected argument to MAIL command: {cmd} {arg or ''}: {exc}') from exc
                            sender = adr

                            self.send_message(250, 'Ok')

                            if sender is None:
                                raise ValueError(f'no sender in command: {cmd} {arg or ''}')

                            while True:
                                cmd, arg = self.expect_command()
                                match cmd.upper():
                                    case 'RCPT':
                                        try:
                                            assert arg is not None
                                            what, adr, args = parse_mail_line(arg)
                                            assert what.upper() == 'TO'
                                        except Exception as exc:
                                            raise ValueError(f'unexpected argument to RCPT command: {cmd} {arg or ''}: {exc}') from exc

                                        receivers.append(adr)

                                        self.send_message(250, 'Ok')

                                    case 'DATA':
                                        self.send_message(354, 'End data with <CR><LF>.<CR><LF>')
                                        buf = bytearray()
                                        crlf = False
                                        with open('/tmp/server.log', 'a') as fp:
                                            while True:
                                                line = self.rfile.readline()
                                                print('C: ' + line.decode('ASCII').rstrip('\r\n'), file=fp)
                                                if crlf and line == b'.\r\n':
                                                    break
                                                crlf = line.endswith(b'\r\n')
                                                buf.extend(line)

                                        emails.append(EMail(
                                            sender = sender,
                                            receivers = receivers,
                                            data = buf.decode('ASCII'),
                                        ))
                                        break

                        case _:
                            raise ValueError(f'unexpected command: {cmd} {arg or ''}')

            except Exception as exc:
                print(f">>> Error handling SMTP connection: {exc}", file=sys.stderr)
                server_errors.append(exc)

    server = TCPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever)
    thread.start()

    proc, logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path)

    server.shutdown()
    thread.join()
    server.server_close()

    from pprint import pprint
    pprint(emails)

    import traceback
    for err in server_errors:
        print(file=sys.stderr)
        traceback.print_exception(err, file=sys.stderr)

    if server_errors:
        print(file=sys.stderr)

    assert server_errors == []

    # TODO: check messages

    for filepath in *logfiles, logmonrc_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore

MAIL_LINE_PATTERN = re.compile(r'^\s*(?P<what>[^:]+):(?P<adr>(?:\"[^"]*")?\s*<[^>]*>)(?P<args>(?:\s+[^\s=]+=\S*)*)\s*$', re.I)

def parse_mail_line(line: str) -> tuple[str, str, dict[str, str]]:
    m = MAIL_LINE_PATTERN.match(line)
    assert m is not None

    what = m.group('what')
    adr = m.group('adr')
    args_str = m.group('args')
    args: dict[str, str] = {}

    if args_str:
        for arg in args_str.split():
            key, value = arg.split('=', 1)
            args[key] = value

    return what, adr, args
