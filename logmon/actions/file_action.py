from typing import Optional, IO, override

import os
import pwd
import grp
import stat
import logging

from .action import Action
from ..types import FileType
from ..schema import Config, FILE_MODE_PATTERN
from ..entry_readers import LogEntry
from ..constants import DEFAULT_FILE_MODE

__all__ = (
    'FileAction',
)

logger = logging.getLogger(__name__)

def parse_file_mode(value: int|str|None) -> Optional[int]:
    if value is None:
        return value

    if isinstance(value, int):
        if value < 0 or value > 0o777:
            raise ValueError(f"file mode out of range: {value:o}")

        return value

    if not value:
        return 0

    m = FILE_MODE_PATTERN.match(value)
    if m is None:
        raise ValueError(f'illegal file mode: {value!r}')

    if (ls := m.group('ls')) is not None:
        mode = 0
        for offset in range(0, 9, 3):
            rwx = ls[offset:offset + 3]

            i = 0
            if rwx[0] == 'r':
                i |= 4

            if rwx[1] == 'w':
                i |= 2

            if rwx[2] == 'x':
                i |= 1

            mode *= 8
            mode += i

        return mode

    elif (eq := m.group('eq')) is not None:
        mode = 0
        for item in eq.split(','):
            who, rwx = item.split('=')

            i = 0
            for ch in rwx:
                match ch:
                    case 'r':
                        i |= 4

                    case 'w':
                        i |= 2

                    case 'x':
                        i |= 1

                    case _:
                        raise ValueError(f'illegal item {item!r} in file mode: {value!r}')

            match who:
                case 'u':
                    i *= 8 * 8

                case 'g':
                    i *= 8

                case 'o':
                    pass

                case _:
                    raise ValueError(f'illegal item {item!r} in file mode: {value!r}')

            mode += i

        return mode

    elif (o := m.group('oct')) is not None:
        mode = int(o, 8)
        if mode < 0 or mode > 0o777:
            raise ValueError(f"file mode out of range: {mode:o}")

        return mode

    else:
        raise TypeError('internal error: FILE_MODE_PATTERN matches but no group is defined')

class FileAction(Action):
    __slots__ = (
        'file_path',
        'file_encoding',
        'file_append',
        'file_user',
        'file_group',
        'file_type',
        'file_mode',
        'stream',
    )

    file_path: str
    file_encoding: str
    file_append: bool
    file_user: Optional[int|str]
    file_group: Optional[int|str]
    file_type: FileType
    file_mode: int
    stream: Optional[IO[str]]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        file = config.get('file')
        if not file:
            raise ValueError('Required field `file` is not defined.')

        self.file_path = file
        self.file_encoding = config.get('file_encoding', 'UTF-8')
        self.file_append = config.get('file_append', True)
        self.file_user = config.get('file_user')
        self.file_group = config.get('file_group')
        self.file_type = config.get('file_type', 'regular')

        mode = parse_file_mode(config.get('file_mode'))
        self.file_mode = mode if mode is not None else DEFAULT_FILE_MODE
        self.stream = None

    def reopen(self) -> IO[str]:
        try:
            self.close()
        except Exception as exc:
            self.stream = None
            logger.error(f'{self.file_path}: Error closing file: {exc}')

        return self.get_stream()

    def get_stream(self) -> IO[str]:
        stream = self.stream
        if stream is None or stream.closed:
            mode = self.file_mode
            open_mode = getattr(os, 'O_CLOEXEC', 0) | os.O_WRONLY | os.O_CREAT

            if self.file_append:
                open_mode |= os.O_APPEND
            else:
                open_mode |= os.O_TRUNC

            if self.file_type == 'fifo':
                try:
                    os.mkfifo(self.file_path, mode)
                except FileExistsError:
                    fd = os.open(self.file_path, open_mode, mode)
                    try:
                        meta = os.fstat(fd)
                        if stat.S_IFIFO & meta.st_mode == 0:
                            raise TypeError(f"{self.file_path}: File exists but isn't a FIFO")
                    except:
                        os.close(fd)
                        raise
                else:
                    fd = os.open(self.file_path, open_mode, mode)
            else:
                fd = os.open(self.file_path, open_mode, mode)

            stream = os.fdopen(fd, "w", encoding=self.file_encoding)
            self.stream = stream

            user  = self.file_user
            group = self.file_group

            uid = -1
            gid = -1

            if user:
                if isinstance(user, str):
                    uid = pwd.getpwnam(user).pw_uid
                else:
                    uid = user

            if group:
                if isinstance(group, str):
                    gid = grp.getgrnam(group).gr_gid
                else:
                    gid = group

            if uid != -1 or gid != -1:
                try:
                    os.chown(fd, uid, gid)
                except PermissionError as exc:
                    who: list[str] = []

                    if user:
                        who.append(f"user={user!r}")

                    if group:
                        who.append(f"group={group!r}")

                    logger.error(f"{self.file_path}: Could not change owner of file to {', '.join(who)}: {exc} ")

        return stream

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return

        try:
            stream = self.get_stream()
            buf = ''.join(
                entry.formatted if entry.formatted.endswith('\n') else entry.formatted + '\n'
                for entry in entries
            )

            try:
                stream.write(buf)
                stream.flush()
            except BrokenPipeError:
                logger.warning(f"{self.file_path}: Broken pipe, reopening...")
                self.reopen()
                stream.write(buf)
                stream.flush()

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise

    def close(self) -> None:
        stream = self.stream
        if stream is not None:
            if not stream.closed:
                stream.close()
            self.stream = None

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
