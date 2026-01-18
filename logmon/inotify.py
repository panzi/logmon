from typing import Optional, NamedTuple, Callable, Any

import os
import select
import ctypes
import ctypes.util
import logging

from io import BufferedReader
from struct import Struct
from errno import (
    EINTR, ENOENT, EEXIST, ENOTDIR, EISDIR, ENOMEM,
    EACCES, EAGAIN, EALREADY, EWOULDBLOCK, EINPROGRESS,
    ECHILD, EPERM, ETIMEDOUT, EPIPE, ECONNABORTED,
    ECONNREFUSED, ECONNRESET, ENOSYS,
)

_logger = logging.getLogger(__name__)

_LIBC_PATH = ctypes.util.find_library('c') or 'libc.so.6'

try:
    _LIBC = ctypes.CDLL(_LIBC_PATH, use_errno=True)
except OSError as exc:
    _LIBC = None
    _logger.debug(f'Loading {_LIBC_PATH!r}: {exc}', exc_info=exc)

__all__ = (
    'InotifyEvent',
    'Inotify',
    'TerminalEventException',
    'IN_CLOEXEC',
    'IN_NONBLOCK',
    'IN_ACCESS',
    'IN_MODIFY',
    'IN_ATTRIB',
    'IN_CLOSE_WRITE',
    'IN_CLOSE_NOWRITE',
    'IN_OPEN',
    'IN_MOVED_FROM',
    'IN_MOVED_TO',
    'IN_CREATE',
    'IN_DELETE',
    'IN_DELETE_SELF',
    'IN_MOVE_SELF',
    'IN_UNMOUNT',
    'IN_Q_OVERFLOW',
    'IN_IGNORED',
    'IN_CLOSE',
    'IN_MOVE',
    'IN_ONLYDIR',
    'IN_DONT_FOLLOW',
    'IN_EXCL_UNLINK',
    'IN_MASK_CREATE',
    'IN_MASK_ADD',
    'IN_ISDIR',
    'IN_ONESHOT',
    'IN_ALL_EVENTS',
)

_HEADER_STRUCT = Struct('iIII')

## from linux/inotify.h

# Flags for sys_inotify_init1

IN_CLOEXEC  = os.O_CLOEXEC
IN_NONBLOCK = os.O_NONBLOCK

# the following are legal, implemented events that user-space can watch for
IN_ACCESS        = 0x00000001 # File was accessed
IN_MODIFY        = 0x00000002 # File was modified
IN_ATTRIB        = 0x00000004 # Metadata changed
IN_CLOSE_WRITE   = 0x00000008 # Writtable file was closed
IN_CLOSE_NOWRITE = 0x00000010 # Unwrittable file closed
IN_OPEN          = 0x00000020 # File was opened
IN_MOVED_FROM    = 0x00000040 # File was moved from X
IN_MOVED_TO      = 0x00000080 # File was moved to Y
IN_CREATE        = 0x00000100 # Subfile was created
IN_DELETE        = 0x00000200 # Subfile was deleted
IN_DELETE_SELF   = 0x00000400 # Self was deleted
IN_MOVE_SELF     = 0x00000800 # Self was moved

# the following are legal events.  they are sent as needed to any watch
IN_UNMOUNT    = 0x00002000 # Backing fs was unmounted
IN_Q_OVERFLOW = 0x00004000 # Event queued overflowed
IN_IGNORED    = 0x00008000 # File was ignored

# helper events
IN_CLOSE = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE # close
IN_MOVE  = IN_MOVED_FROM  | IN_MOVED_TO      # moves

# special flags
IN_ONLYDIR     = 0x01000000 # only watch the path if it is a directory
IN_DONT_FOLLOW = 0x02000000 # don't follow a sym link
IN_EXCL_UNLINK = 0x04000000 # exclude events on unlinked objects
IN_MASK_CREATE = 0x10000000 # only create watches
IN_MASK_ADD    = 0x20000000 # add to the mask of an already existing watch
IN_ISDIR       = 0x40000000 # event occurred against dir
IN_ONESHOT     = 0x80000000 # only send event once

# All of the events - we build the list by hand so that we can add flags in
# the future and not break backward compatibility.  Apps will get only the
# events that they originally wanted.  Be sure to add new events here
IN_ALL_EVENTS = (
    IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
    IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM |
    IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF |
    IN_MOVE_SELF
)

def _check_return(value: int, filename: Optional[str] = None) -> int:
    if value < 0:
        errnum = ctypes.get_errno()
        message = os.strerror(errnum)

        if errnum == ENOENT:
            raise FileNotFoundError(errnum, message, filename)

        if errnum == ENOMEM:
            raise MemoryError

        if errnum in (EACCES, EPERM):
            raise PermissionError(errnum, message, filename)

        if errnum == EINTR:
            raise InterruptedError(errnum, message, filename)

        if errnum == ENOTDIR:
            raise NotADirectoryError(errnum, message, filename)

        if errnum == EEXIST:
            raise FileExistsError(errnum, message, filename)

        if errnum == EISDIR:
            raise IsADirectoryError(errnum, message, filename)

        if errnum in (EAGAIN, EALREADY, EWOULDBLOCK, EINPROGRESS):
            raise BlockingIOError(errnum, message, filename)

        if errnum == ETIMEDOUT:
            raise TimeoutError(errnum, message, filename)

        if errnum == ECHILD:
            raise ChildProcessError(errnum, message, filename)

        if errnum == EPIPE:
            raise BrokenPipeError(errnum, message, filename)

        if errnum == ECONNABORTED:
            raise ConnectionAbortedError(errnum, message, filename)

        if errnum == ECONNREFUSED:
            raise ConnectionRefusedError(errnum, message, filename)

        if errnum == ECONNRESET:
            raise ConnectionResetError(errnum, message, filename)

        raise OSError(errnum, message, filename)

    return value

HAS_INOTIFY = True

_CDataType = type[ctypes.c_int]|type[ctypes.c_char_p]|type[ctypes.c_uint32]

def _load_sym(name: str, argtypes: tuple[_CDataType, ...], restype: _CDataType|Callable[[int], Any]) -> Callable:
    global HAS_INOTIFY

    if sym := getattr(_LIBC, name, None):
        sym.argtypes = argtypes
        sym.restype = restype
        return sym

    else:
        HAS_INOTIFY = False

        def symbol_not_found(*args, **kwargs):
            raise OSError(ENOSYS, f'{name} is not supported')
        symbol_not_found.__name__ = name

        return symbol_not_found

inotify_init1 = _load_sym('inotify_init1', (ctypes.c_int,), _check_return)
inotify_add_watch = _load_sym('inotify_add_watch', (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint32,
), ctypes.c_int)
inotify_rm_watch = _load_sym('inotify_rm_watch', (ctypes.c_int, ctypes.c_int), ctypes.c_int)

class TerminalEventException(Exception):
    __slots__ = (
        'wd',
        'mask',
        'watch_path',
        'filename',
    )

    wd: int
    mask: int
    watch_path: Optional[str]
    filename: Optional[str]

    def __init__(self, wd: int, mask: int, watch_path: Optional[str], filename: Optional[str]) -> None:
        super().__init__(wd, mask, watch_path, filename)
        self.wd = wd
        self.mask = mask
        self.watch_path = watch_path
        self.filename = filename

class InotifyEvent(NamedTuple):
    wd: int
    mask: int
    cookie: int
    filename_len: int
    watch_path: str
    filename: str

class Inotify:
    """
    Listen for inotify events.

    Supports the context manager protocol.
    """
    __slots__ = (
        '_inotify_fd',
        '_inotify_stream',
        '_epoll',
        '_path_to_wd',
        '_wd_to_path',
        '_stopfd',
    )

    _epoll: select.epoll
    _stopfd: Optional[int]
    _path_to_wd: dict[str, int]
    _wd_to_path: dict[int, str]
    _inotify_fd: int
    _inotify_stream: BufferedReader

    def __init__(self, stopfd: Optional[int] = None) -> None:
        """
        If not `None` then stopfd is a file descriptor that will
        be added to the `poll()` call in `Inotify.wait()`.
        """
        self._stopfd = stopfd
        self._inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        self._inotify_stream = os.fdopen(self._inotify_fd, 'rb')
        self._epoll = select.epoll(1 if stopfd is None else 2)
        self._epoll.register(self._inotify_fd, select.POLLIN)

        if stopfd is not None:
            self._epoll.register(stopfd, select.POLLIN)

        self._path_to_wd = {}
        self._wd_to_path = {}

    def fileno(self) -> int:
        """
        The inotify file descriptor.

        You can use this to call `poll()` or similar yourself
        instead of using `Inotify.wait()`.
        """
        return self._inotify_fd

    @property
    def closed(self) -> bool:
        return self._inotify_fd == -1

    @property
    def stopfd(self) -> Optional[int]:
        return self._stopfd

    def close(self) -> None:
        try:
            stream = self._inotify_stream
            if not stream.closed:
                stream.close()
        finally:
            self._inotify_fd = -1
            epoll = self._epoll
            if not epoll.closed:
                epoll.close()

    def __enter__(self) -> "Inotify":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def add_watch(self, path: str, mask: int = IN_ALL_EVENTS) -> int:
        """
        If the path is already watched returns the pre-existing watch id.
        """
        wd = self._path_to_wd.get(path)
        if wd is not None:
            return wd

        path_bytes = path.encode('UTF-8', 'surrogateescape')

        wd = inotify_add_watch(self._inotify_fd, path_bytes, mask)
        _check_return(wd, path)

        self._path_to_wd[path] = wd
        self._wd_to_path[wd] = path

        return wd

    def remove_watch(self, path: str) -> None:
        wd = self._path_to_wd.get(path)
        if wd is None:
            return

        try:
            res = inotify_rm_watch(self._inotify_fd, wd)
            _check_return(res, path)
        finally:
            del self._path_to_wd[path]
            del self._wd_to_path[wd]

    def remove_watch_with_id(self, wd: int) -> None:
        path = self._wd_to_path.get(wd)
        if path is None:
            return

        try:
            res = inotify_rm_watch(self._inotify_fd, wd)
            _check_return(res, path)
        finally:
            del self._wd_to_path[wd]
            del self._path_to_wd[path]

    def watch_paths(self) -> set[str]:
        return set(self._path_to_wd)

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for inotify events or for any `POLLIN` on `stopfd`,
        if that is not `None`. If `stopfd` signals this function will
        return `False`, otherwise `True`.

        Raises `TimeoutError` if `timeout` is not `None` and expired.
        """
        events = self._epoll.poll(timeout)

        if not events and timeout is not None and timeout >= 0.0:
            raise TimeoutError

        stopfd = self._stopfd
        if stopfd is not None:
            for fd, mask in events:
                if fd == stopfd:
                    return False

        return True

    def read_events(self, terminal_events: int = IN_Q_OVERFLOW | IN_UNMOUNT) -> list[InotifyEvent]:
        """
        Reads available events. Might return an empty list.

        Raises `TerminalEventException` if the flags in `terminal_events` are set in an event `mask`.
        """
        stream = self._inotify_stream
        wd_to_path = self._wd_to_path

        events: list[InotifyEvent] = []

        while header_bytes := stream.read(_HEADER_STRUCT.size):
            wd, mask, cookie, filename_len = _HEADER_STRUCT.unpack(header_bytes)

            filename_bytes = stream.read(filename_len)
            filename = filename_bytes.rstrip(b'\0').decode('UTF-8', 'surrogateescape')

            watch_path = wd_to_path.get(wd)

            if mask & terminal_events:
                raise TerminalEventException(wd, mask, watch_path, filename or None)

            if watch_path is not None:
                events.append(InotifyEvent(wd, mask, cookie, filename_len, watch_path, filename))
            else:
                _logger.debug(f'Got inotify event for unknown watch handle: {wd}')

        return events
