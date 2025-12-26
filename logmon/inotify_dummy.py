from typing import Optional, Generator, Any

__all__ = (
    'InotifyError',
    'TerminalEventException',
    'IN_MODIFY',
    'IN_MOVED_FROM',
    'IN_MOVED_TO',
    'IN_CREATE',
    'IN_DELETE',
    'IN_MOVE_SELF',
    'IN_ALL_EVENTS',
    'Inotify',
    'inotify_wait_for_exists',
)

InotifyError = Exception
TerminalEventException = Exception
IN_MODIFY = 2
IN_MOVED_FROM = 64
IN_MOVED_TO = 128
IN_CREATE = 256
IN_DELETE = 512
IN_MOVE_SELF = 2048

IN_ALL_EVENTS = 0xffff_ffff

class Inotify:
    def add_watch(self, path_unicode: str, mask: int = IN_ALL_EVENTS) -> None:
        raise Exception('needs inotify')

    def remove_watch(self, path: str, superficial: bool = False) -> None:
        raise Exception('needs inotify')

    def event_gen(
            self, timeout_s: Optional[float]=None, yield_nones=True, filter_predicate=None,
            terminal_events=('IN_Q_OVERFLOW','IN_UNMOUNT')) -> Generator[tuple[Any, list[str], str, str]|None]:
        raise Exception('needs inotify')
        return
        yield None, [], '', ''

def inotify_wait_for_exists(inotify: Inotify, path: str) -> bool:
    raise Exception('needs inotify')
