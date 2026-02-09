from typing import Optional, Literal, Any, override, IO, Callable, TypedDict, NotRequired

import re
import os
import sys
import shlex
import logging

from subprocess import Popen, TimeoutExpired, PIPE, DEVNULL, STDOUT
from math import inf

from .action import Action, TemplParams
from ..schema import Config, ActionConfig
from ..entry_readers import LogEntry
from ..template import expand_args_inline, expand
from ..limiter import AbstractLimiter
from ..types import EncodingErrors
from ..constants import DEFAULT_ENCODING_ERRORS

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

class CommandTemplParams(TypedDict):
    entries: list[str]
    entries_str: str
    entries_raw: list[Any]
    logfile: str
    brief: str
    line1: str
    entry1: str
    entrynum: str
    sender: str
    receivers: str
    receiver_list: list[str]
    nl: str
    subject: NotRequired[str]

    python: str
    python_version: str
    python_version_major: int
    python_version_minor: int
    python_version_micro: int

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
        'chroot',
        'umask',
        'nice',
        'process_group',
        'new_session',
        'extra_groups',
        'encoding',
        'encoding_errors',
    )

    command: list[str]
    cwd: Optional[str]
    user: Optional[str|int]
    group: Optional[str|int]
    env: Optional[dict[str, Optional[str]]]
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
    chroot: Optional[str]
    umask: Optional[int]
    nice: Optional[int]
    process_group: Optional[int]
    new_session: bool
    extra_groups: Optional[list[str|int]]
    encoding: Optional[str]
    encoding_errors: Optional[EncodingErrors]

    def __init__(self, action_config: ActionConfig, config: Config, limiter: AbstractLimiter) -> None:
        super().__init__(action_config, config, limiter)

        interactive = action_config.get('command_interactive')
        command = action_config.get('command')

        if not command:
            if interactive or interactive is None:
                interactive = True
                command = ['cat']
            else:
                command = ['echo', '{...entries}']

        env_raw = action_config.get('command_env')
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

        self.command = command if isinstance(command, list) else shlex.split(command)
        self.cwd     = action_config.get('command_cwd')
        self.user    = action_config.get('command_user')
        self.group   = action_config.get('command_group')
        self.env     = action_config.get('command_env')
        self.stdin   = action_config.get('command_stdin')
        self.stdout  = action_config.get('command_stdout')
        self.stderr  = action_config.get('command_stderr')
        self.stdin_path  = parse_path(self.stdin, 'r')
        self.stdout_path = parse_path(self.stdout, 'w')
        self.stderr_path = parse_path(self.stderr, 'w')
        self.interactive = interactive or False
        self.proc     = None
        self.pipe_fmt = None
        self.timeout  = action_config.get('command_timeout')
        if self.timeout == inf:
            self.timeout = None
        self.chroot   = action_config.get('command_chroot')
        self.umask    = action_config.get('command_umask')
        self.nice     = action_config.get('command_nice')
        self.process_group   = action_config.get('command_process_group')
        self.new_session     = action_config.get('command_new_session', False)
        self.extra_groups    = action_config.get('command_extra_groups')
        self.encoding        = action_config.get('command_encoding')
        self.encoding_errors = action_config.get('command_encoding_errors', DEFAULT_ENCODING_ERRORS)

    def create_process(self, templ_params: CommandTemplParams) -> tuple[Popen, str|None]:
        command: list[str] = expand_args_inline(self.command, templ_params)

        raw_env = self.env
        env: Optional[dict[str, str]]
        if raw_env is not None:
            env = {}
            for key, value in raw_env.items():
                if value is None:
                    value = os.getenv(key)

                    if value is not None:
                        env[key] = value
                else:
                    env[key] = value.format_map(templ_params)
        else:
            env = None

        stdin = open_io(self.stdin_path)
        try:
            stdout = open_io(self.stdout_path)
            try:
                stderr = open_io(self.stderr_path)
                try:
                    umask  = self.umask
                    nice   = self.nice
                    chroot = self.chroot

                    preexec_fn: Callable[[], None]|None
                    if chroot or nice is not None:
                        def _preexec_fn() -> None:
                            if chroot:
                                os.chroot(chroot)

                            if nice is not None:
                                os.nice(nice)

                        preexec_fn = _preexec_fn
                    else:
                        preexec_fn = None

                    proc = Popen(
                        args       = command,
                        env        = env,
                        cwd        = self.cwd,
                        user       = self.user,
                        group      = self.group,
                        stdin      = stdin,
                        stdout     = stdout,
                        stderr     = stderr,
                        umask      = umask if umask is not None else -1,
                        encoding   = self.encoding,
                        errors     = self.encoding_errors,
                        preexec_fn = preexec_fn,
                        process_group     = self.process_group,
                        start_new_session = self.new_session,
                        extra_groups      = self.extra_groups,
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
    def get_templ_params(self, logfile: str, entries: list[LogEntry], brief: str) -> CommandTemplParams:
        templ_params: CommandTemplParams = {
            **super().get_templ_params(logfile, entries, brief),
            'python': sys.executable,
            'python_version': sys.version,
            'python_version_major': sys.version_info.major,
            'python_version_minor': sys.version_info.minor,
            'python_version_micro': sys.version_info.micro,
        }
        return templ_params

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> bool:
        if not self.limiter.check():
            return False

        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return True

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

        return True

def write_stdin(proc: Popen, pipe_fmt: str, templ_params: TemplParams) -> None:
    stdin = proc.stdin
    if stdin is not None:
        for line in expand(pipe_fmt, templ_params):
            stdin.write(line.encode())
            stdin.write(b'\n')
