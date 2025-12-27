from typing import Optional, Literal, Any, override, IO

import re
import logging

from subprocess import Popen, PIPE, DEVNULL, STDOUT

from .action import Action
from ..schema import Config
from ..entry_readers import LogEntry

logger = logging.getLogger(__name__)

__all__ = (
    'CommandAction',
)

PATH_PATTERN = re.compile(r'^([-_a-z0-9]+):(.*)$', re.I)

type IOType = Literal['inherit', 'pipe', 'file', 'null', 'stdout']
type OpenMode = Literal['r', 'w', 'a']
type ParsedPath = (
    tuple[Literal['file'], str, OpenMode] |
    tuple[Literal['inherit', 'null', 'stdout'], None, None] |
    tuple[Literal['pipe'], str, None]
)

def open_path(path: ParsedPath) -> IO[Any]|int|None:
    match path:
        case ('file', file_path, mode):
            # XXX: mypy somehow gets a totally wrong type for file_path
            return open(
                file_path, # type: ignore
                f'{mode}b',
            )

        case ('inherit', _, _):
            return None

        case ('pipe', _, _):
            return PIPE

        case ('stdout', _, _):
            return STDOUT

        case ('null', _, _):
            return DEVNULL

        case _:
            raise ValueError(f'Illegal path: {path!r}')

def parse_path(path: Optional[str], mode: Literal['r', 'w']) -> ParsedPath:
    if path is None:
        return 'inherit', None, None

    m = PATH_PATTERN.match(path)

    if m is None:
        return 'file', path, mode

    schema = m[1].lower()
    arg = m[2]

    match schema:
        case 'file':
            if not arg:
                raise ValueError(f'Illegal path syntax: {path!r}')

            return schema, arg, mode

        case 'append':
            if mode == 'r':
                raise ValueError(f'Cannot append for input: {path!r}')

            return 'file', arg, 'a'

        case 'null':
            if arg:
                raise ValueError(f'Illegal path syntax: {path!r}')

            return schema, None, None

        case 'pipe':
            return schema, arg, None

        case 'stdout':
            if arg:
                raise ValueError(f'Illegal path syntax: {path!r}')

            if mode == 'r':
                raise ValueError(f'Cannot redirect stdout to stdin: {path!r}')

            return schema, None, None

        case 'inherit':
            if arg:
                raise ValueError(f'Illegal path syntax: {path!r}')

            return schema, None, None

        case _:
            raise ValueError(f'Illegal path syntax: {path!r}')

class CommandAction(Action):
    __slots__ = (
        'command',
        'cwd',
        'user',
        'group',
        'env',
        'stdin',
        'stdout',
        'stderr',
        'stdin_path',
        'stdout_path',
        'stderr_path',
        'interactive',
        'proc',
        'pipe_fmt',
    )

    command: list[str]
    cwd: Optional[str]
    user: Optional[str|int]
    group: Optional[str|int]
    env: Optional[dict[str, str]]
    stdin: Optional[str]
    stdout: Optional[str]
    stderr: Optional[str]
    stdin_path: ParsedPath
    stdout_path: ParsedPath
    stderr_path: ParsedPath
    interactive: bool
    proc: Optional[Popen]
    pipe_fmt: Optional[str]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        interactive = config.get('command_interactive')
        command = config.get('command')

        if not command:
            if interactive or interactive is None:
                interactive = True
                command = ['cat']
            else:
                command = ['echo', '{...entries}']

        self.command = command
        self.cwd     = config.get('command_cwd')
        self.user    = config.get('command_user')
        self.group   = config.get('command_group')
        self.env     = config.get('command_env')
        self.stdin   = config.get('command_stdin')
        self.stdout  = config.get('command_stdout')
        self.stderr  = config.get('command_stderr')
        self.stdin_path  = parse_path(self.stdin, 'r')
        self.stdout_path = parse_path(self.stdout, 'w')
        self.stderr_path = parse_path(self.stderr, 'w')
        self.interactive = interactive or False
        self.proc = None
        self.pipe_fmt = None

    def create_process(self, entries: list[LogEntry], templ_params: dict[str, str]) -> tuple[Popen, str|None]:
        command: list[str] = []
        for arg in self.command:
            parts = [item.format_map(templ_params) for item in arg.split('{...entries}')]

            if len(parts) > 1:
                for entry in entries:
                    command.append(entry.formatted.join(parts))
            else:
                command.append(parts[0])

        env = self.env
        if env is not None:
            env = {key: value.format_map(templ_params) for key, value in env.items()}

        proc = Popen(
            args   = command,
            env    = env,
            cwd    = self.cwd,
            user   = self.user,
            group  = self.group,
            stdin  = open_path(self.stdin_path),
            stdout = open_path(self.stdout_path),
            stderr = open_path(self.stderr_path),
        )

        match self.stdin_path:
            case ('pipe', pipe_fmt, _):
                return proc, pipe_fmt

            case _:
                return proc, None

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        proc = self.proc
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                self.proc = None

        return super().__exit__(exc_type, exc_value, traceback)

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        proceed, msg = self.check_logmails(logfile, templ_params)

        if not proceed:
            return

        try:
            if self.interactive:
                proc = self.proc
                if proc is not None and (status := proc.poll()) is not None:
                    if status != 0:
                        logger.error(f'Interactive process failed: {proc.args!r} status: {status}')

                    proc, pipe_fmt = self.create_process(entries, templ_params)
                    self.proc = proc
                    self.pipe_fmt = pipe_fmt

                elif proc is None:
                    proc, pipe_fmt = self.create_process(entries, templ_params)
                    self.proc = proc
                    self.pipe_fmt = pipe_fmt
                else:
                    pipe_fmt = self.pipe_fmt

                if pipe_fmt is not None:
                    write_stdin(proc, entries, pipe_fmt, templ_params)
                    if proc.stdin is not None:
                        proc.stdin.flush()

                if (status := proc.poll()) is not None and status != 0:
                    logger.error(f'Interactive process failed: {proc.args!r} status: {status}')
            else:
                proc, pipe_fmt = self.create_process(entries, templ_params)

                if pipe_fmt is not None:
                    write_stdin(proc, entries, pipe_fmt, templ_params)
                    if proc.stdin is not None:
                        proc.stdin.close()

                status = proc.wait()
                if status != 0:
                    raise Exception(f'Error running program: {proc.args!r} status: {status}', proc.args, status)

        except Exception as exc:
            self.handle_error(msg, templ_params, exc)
            raise

def write_stdin(proc: Popen, entries: list[LogEntry], pipe_fmt: str, templ_params: dict[str, str]) -> None:
    stdin = proc.stdin
    if stdin is not None:
        parts = [item.format_map(templ_params) for item in pipe_fmt.split('{...entries}')]

        if len(parts) > 1:
            for entry in entries:
                stdin.write(entry.formatted.join(parts).encode())
                stdin.write(b'\n')
        else:
            stdin.write(parts[0].encode())
            stdin.write(b'\n')

