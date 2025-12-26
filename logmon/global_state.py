from typing import Optional

import os
import signal
import logging

__all__ = (
    'is_running',
    'get_read_stopfd',
    'get_write_stopfd',
    'handle_keyboard_interrupt',
    'handle_stop_signal',
)

logger = logging.getLogger(__name__)

_running: bool = True
_read_stopfd:  Optional[int] = None
_write_stopfd: Optional[int] = None

def is_running() -> bool:
    return _running

def get_read_stopfd() -> Optional[int]:
    return _read_stopfd

def get_write_stopfd() -> Optional[int]:
    return _write_stopfd

def handle_keyboard_interrupt() -> None:
    global _running
    if _running:
        _running = False
        logger.info("Shutting down on SIGINT...")
        _signal_stopfd()

def handle_stop_signal(signum: int, frame) -> None:
    global _running
    _running = False
    signame: str
    try:
        signame = signal.Signals(signum).name
    except:
        signame = f'signal {signum}'
    logger.info(f"Shutting down on {signame}...")
    _signal_stopfd()

def _signal_stopfd() -> None:
    global _running, _write_stopfd

    write_stopfd = _write_stopfd
    if not _running and write_stopfd is not None:
        try:
            os.write(write_stopfd, b'\0')
        except Exception as exc:
            logger.warning(f"Error signaling stop through write_stopfd {write_stopfd}: {exc}", exc_info=exc)

def open_stopfds() -> tuple[int, int]:
    global _write_stopfd, _read_stopfd

    stopfds = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    _read_stopfd, _write_stopfd = stopfds
    return stopfds

def close_stopfds() -> None:
    global _write_stopfd, _read_stopfd

    write_stopfd = _write_stopfd
    if write_stopfd is not None:
        try:
            os.close(write_stopfd)
        except Exception as exc:
            logger.warning(f"Error closing write_stopfd {write_stopfd}: {exc}", exc_info=exc)
        _write_stopfd = None

    read_stopfd = _read_stopfd
    if read_stopfd is not None:
        try:
            os.close(read_stopfd)
        except Exception as exc:
            logger.warning(f"Error closing read_stopfd {read_stopfd}: {exc}", exc_info=exc)
        _read_stopfd = None
