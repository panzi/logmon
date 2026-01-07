import os
import logging

from os.path import normpath, dirname, join as joinpath
from select import poll, POLLIN

from .global_state import is_running, get_read_stopfd

__all__ = (
    'inotify_wait_for_exists',
    'HAS_INOTIFY',
)

logger = logging.getLogger(__name__)

try:
    # inotify has no proper type annotations!
    from inotify.adapters import Inotify, TerminalEventException # type: ignore
    from inotify.constants import IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_MOVE_SELF # type: ignore
    from inotify.calls import InotifyError # type: ignore

    def inotify_wait_for_exists(inotify: Inotify, path: str) -> bool: # type: ignore
        path = normpath(path)
        dirpath = dirname(path)
        while is_running():
            try:
                inotify.add_watch(dirpath, IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
            except InotifyError:
                if not os.path.exists(dirpath):
                    parentdir = dirname(dirpath)
                    if parentdir == dirpath:
                        raise Exception(f'Root dir ({dirpath}) does not exist?')
                    inotify_wait_for_exists(inotify, parentdir)
                    continue
                raise
            except FileNotFoundError:
                parentdir = dirname(dirpath)
                if parentdir == dirpath:
                    raise Exception(f'Root dir ({dirpath}) does not exist?')
                inotify_wait_for_exists(inotify, parentdir)
                continue
            else:
                deleted = False
                try:
                    if os.path.exists(path):
                        return True

                    stopfd = get_read_stopfd()
                    if stopfd is not None:
                        poller = poll()
                        poller.register(stopfd, POLLIN)
                        # why is there no official way to get that file discriptor!?
                        poller.register(inotify._Inotify__inotify_fd, POLLIN) # type: ignore
                        pevents = poller.poll()
                        if not pevents:
                            return False

                        if any(fd == stopfd for fd, _pevent in pevents):
                            return False

                    for event in inotify.event_gen():
                        if not is_running():
                            return False

                        if event is None:
                            continue

                        _, type_names, event_path, event_filename = event
                        if normpath(joinpath(event_path, event_filename)) == path:
                            if 'IN_CREATE' in type_names or 'IN_MOVED_TO' in type_names:
                                return True

                        elif normpath(event_path) == dirpath:
                            if 'IN_DELETE_SELF' in type_names or 'IN_MOVE_SELF' in type_names:
                                # continue outer loop
                                deleted = True
                                break

                except TerminalEventException as exc:
                    # filesystem unmounted
                    logger.debug(f'{path}: Retrying because of: {exc}')
                    continue

                finally:
                    try:
                        if not deleted:
                            inotify.remove_watch(dirpath)
                    except Exception as exc:
                        logger.error(f'{dirpath}: Error while removing inotify watch: {exc}', exc_info=exc)
        return False

    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False

    from .inotify_dummy import * # type: ignore
