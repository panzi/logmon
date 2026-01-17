import os
import logging

from os.path import normpath, dirname, join as joinpath
from errno import EINVAL

from .global_state import is_running
from .better_inotify import BetterInotify, TerminalEventException, IN_CREATE, IN_MOVED_TO, IN_DELETE_SELF, IN_MOVE_SELF

__all__ = (
    'inotify_wait_for_exists',
)

logger = logging.getLogger(__name__)

def inotify_wait_for_exists(inotify: BetterInotify, path: str) -> bool: # type: ignore
    path = normpath(path)
    dirpath = dirname(path)
    while is_running():
        try:
            inotify.add_watch(dirpath, IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
        except FileNotFoundError:
            parentdir = dirname(dirpath)
            if parentdir == dirpath:
                raise Exception(f'Root dir ({dirpath}) does not exist?')
            inotify_wait_for_exists(inotify, parentdir)
            continue
        else:
            try:
                if os.path.exists(path):
                    logger.debug(f'{path}: Path exists!')
                    return True

                logger.debug(f'{path}: Waiting for path')

                do_wait = True
                while do_wait and inotify.wait() and is_running():
                    for event in inotify.read_events():
                        if not is_running():
                            return False

                        mask = event.mask
                        if normpath(joinpath(event.watch_path, event.filename)) == path:
                            if (IN_CREATE | IN_MOVED_TO) & mask:
                                return True

                        elif normpath(event.watch_path) == dirpath:
                            if (IN_DELETE_SELF | IN_MOVE_SELF) & mask:
                                # continue outer loop
                                do_wait = False
                                break

            except TerminalEventException as exc:
                # filesystem unmounted
                logger.debug(f'{path}: Retrying because of: {exc}')
                continue

            finally:
                try:
                    inotify.remove_watch(dirpath)
                except OSError as exc:
                    if exc.errno == EINVAL:
                        pass # happens when the file was deleted/moved away
                    else:
                        logger.error(f'{dirpath}: Error while removing inotify watch: {exc}', exc_info=exc)
                except Exception as exc:
                    logger.error(f'{dirpath}: Error while removing inotify watch: {exc}', exc_info=exc)
    return False

if __name__ == '__main__':
    import sys

    logger.setLevel(logging.DEBUG)

    inotify = BetterInotify()

    for path in sys.argv[1:]:
        print(f'{path}: Waiting for path')
        res = inotify_wait_for_exists(inotify, path)
        if res:
            print(f'{path}: Appeared!')
        else:
            print(f'result: {res}')
