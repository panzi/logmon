from typing import Optional, Literal, Any, override, IO

import re
import os
import logging

from subprocess import Popen, TimeoutExpired, PIPE, DEVNULL, STDOUT
from math import inf

from .action import Action, TemplParams
from ..schema import Config
from ..entry_readers import LogEntry
from ..template import expand_args_inline, expand

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

def open_io(path: ParsedPath) -> IO[Any]|int|None:
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

def close_io(obj: IO[Any]|int|None) -> None:
    if isinstance(obj, int):
        if obj >= 0:
            os.close(obj)
    elif isinstance(obj, IO):
        if not obj.closed:
            obj.close()

def parse_path(path: Optional[str], mode: Literal['r', 'w']) -> ParsedPath:
    if path is None:
        return 'null', None, None

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
        'timeout',
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
    timeout: Optional[float]

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

        env_raw = config.get('command_env')
        env: Optional[dict[str, str]]
        if env_raw is None:
            env = None
        else:
            env = {}
            for key, value in env_raw.items():
                if value is None:
                    value = os.getenv(key)

                if value is not None:
                    env[key] = value

        self.command = command
        self.cwd     = config.get('command_cwd')
        self.user    = config.get('command_user')
        self.group   = config.get('command_group')
        self.env     = env
        self.stdin   = config.get('command_stdin')
        self.stdout  = config.get('command_stdout')
        self.stderr  = config.get('command_stderr')
        self.stdin_path  = parse_path(self.stdin, 'r')
        self.stdout_path = parse_path(self.stdout, 'w')
        self.stderr_path = parse_path(self.stderr, 'w')
        self.interactive = interactive or False
        self.proc     = None
        self.pipe_fmt = None
        self.timeout  = config.get('command_timeout')
        if self.timeout == inf:
            self.timeout = None

    def create_process(self, templ_params: TemplParams) -> tuple[Popen, str|None]:
        command: list[str] = expand_args_inline(self.command, templ_params)

        env = self.env
        if env is not None:
            env = {key: value.format_map(templ_params) for key, value in env.items()}

        stdin = open_io(self.stdin_path)
        try:
            stdout = open_io(self.stdout_path)
            try:
                stderr = open_io(self.stderr_path)
                try:
                    proc = Popen(
                        args   = command,
                        env    = env,
                        cwd    = self.cwd,
                        user   = self.user,
                        group  = self.group,
                        stdin  = stdin,
                        stdout = stdout,
                        stderr = stderr,
                    )
                except:
                    close_io(stderr)
                    raise
            except:
                close_io(stdout)
                raise
        except:
            close_io(stdin)
            raise

        match self.stdin_path:
            case ('pipe', pipe_fmt, _):
                return proc, pipe_fmt

            case _:
                return proc, None

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop_process(kill_on_timeout=True)

    def stop_process(self, kill_on_timeout: bool = False) -> None:
        proc = self.proc
        if proc is not None:
            pid = proc.pid
            try:
                if (status := proc.poll()) is None:
                    proc.terminate()
                    try:
                        status = proc.wait(self.timeout)
                    except TimeoutExpired:
                        logger.error(f'Termination timeout for process (PID: {pid}) exceeded: {proc.args!r}')
                        if kill_on_timeout:
                            logger.error(f'Killing process {pid} now!')
                            proc.kill()
                    else:
                        if status != 0:
                            logger.error(f'Error terminating process (PID: {pid}): {proc.args!r} status: {status}')
                elif status != 0:
                    logger.error(f'Error terminating process (PID: {pid}): {proc.args!r} status: {status}')
            except Exception as exc:
                logger.error(f'Error terminating process (PID: {pid}): {proc.args!r}: {exc}', exc_info=exc)
            finally:
                self.proc = None
                self.pipe_fmt = None

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return

        try:
            if self.interactive:
                proc = self.proc
                if proc is not None and (status := proc.poll()) is not None:
                    if status != 0:
                        logger.error(f'Interactive process failed: {proc.args!r} status: {status}')

                    proc, pipe_fmt = self.create_process(templ_params)
                    self.proc = proc
                    self.pipe_fmt = pipe_fmt

                elif proc is None:
                    proc, pipe_fmt = self.create_process(templ_params)
                    self.proc = proc
                    self.pipe_fmt = pipe_fmt
                else:
                    pipe_fmt = self.pipe_fmt

                if pipe_fmt is not None:
                    write_stdin(proc, pipe_fmt, templ_params)
                    if proc.stdin is not None:
                        proc.stdin.flush()

                if (status := proc.poll()) is not None and status != 0:
                    logger.error(f'Interactive process failed: {proc.args!r} status: {status}')
            else:
                if self.proc is not None:
                    self.stop_process(kill_on_timeout=True)

                proc, pipe_fmt = self.create_process(templ_params)
                pid = proc.pid
                self.proc = proc
                self.pipe_fmt = pipe_fmt

                try:
                    if pipe_fmt is not None:
                        write_stdin(proc, pipe_fmt, templ_params)
                        if proc.stdin is not None:
                            proc.stdin.close()

                    try:
                        status = proc.wait(self.timeout)
                    except TimeoutExpired:
                        logger.error(f'Termination timeout for process (PID: {pid}) exceeded: {proc.args!r}')
                    else:
                        if status != 0:
                            raise Exception(f'Error running program: {proc.args!r} status: {status}', proc.args, status)
                finally:
                    self.proc = None
                    self.pipe_fmt = None

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise

def write_stdin(proc: Popen, pipe_fmt: str, templ_params: TemplParams) -> None:
    stdin = proc.stdin
    if stdin is not None:
        for line in expand(pipe_fmt, templ_params):
            stdin.write(line.encode())
            stdin.write(b'\n')
