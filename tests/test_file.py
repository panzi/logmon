import os
import gzip
import bz2
import json
import pytest

from os.path import join as join_path

try:
    from compression import zstd
except ImportError:
    zstd = None # type: ignore

from tests.testutils import *

COMPRESSIONS: list[Compression|None] = [None, 'gzip', 'bz2', 'zstd']

def read_compressed_file(path: str, compression: str|None) -> str:
    match compression:
        case None:
            with open(path, 'rt') as fp:
                return fp.read()

        case 'gzip':
            with gzip.open(path, 'rt') as fp:
                return fp.read()

        case 'bz2':
            with bz2.open(path, 'rt') as fp:
                return fp.read()

        case 'zstd':
            assert zstd is not None
            with zstd.open(path, 'rt') as fp:
                return fp.read()

        case _:
            raise ValueError(f'Unsupported compression: {compression!r}')

def _test_file(compression: Compression|None, logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
    tempdir, prefix = temp_prefix
    file_path = join_path(tempdir, f'{prefix}.output.log')
    logmonrc = f'''\
---
do:
  action: "file:{file_path}"
  file_compression: {json.dumps(compression)}
default:
  compression: {json.dumps(compression)}
  use_inotify: true
  seek_end: true
log:
  format: "%(message)s"
logfiles:
  "{logfiles[0]}": "file:{logfiles[0]}.out"
  "{logfiles[1]}": "file:{logfiles[1]}.out"
  "{logfiles[2]}":
    action: "file:{logfiles[2]}.out"
    entry_start_pattern: >-
      "^{{"
'''
    write_file(logmonrc_path, logmonrc)

    proc, logs, stdout, stderr = run_logmon(logfiles, '--config', logmonrc_path, compression=compression)

    expected1 = f'''\
{logs[0][0]['message']}
{logs[0][1]['message']}
'''

    expected2 = f'''\
{logs[1][0]['message']}
'''

    output1 = read_compressed_file(f'{logfiles[0]}.out', compression)
    output2 = read_compressed_file(f'{logfiles[1]}.out', compression)

    assert expected1 in output1, f'Message 1 not found in output!\n\n  Message:\n\n{indent(expected1)}\n\n  Output:\n\n{indent(output1)}'
    assert expected2 in output2, f'Message 2 not found in output!\n\n  Message:\n\n{indent(expected2)}\n\n  Output:\n\n{indent(output2)}'

    for filepath in *logfiles, logmonrc_path, file_path:
        try:
            os.remove(filepath)
        except Exception as exc:
            print(f'Error deleting {filepath}: {exc}')

    proc.stderr.close() # type: ignore
    proc.stdout.close() # type: ignore

def _make_test(compression: Compression|None):
    def test_file(logmonrc_path: str, logfiles: list[str], temp_prefix: tuple[str, str]) -> None:
        return _test_file(compression, logmonrc_path, logfiles, temp_prefix)

    if compression is not None:
        test_file.__name__ = f'test_{compression}_file'

    if compression == 'zstd':
      if zstd is None:
          test_file = pytest.mark.skip('zstd not supported on your system')(test_file)
      else:
          test_file = pytest.mark.skip('TODO: zstd support')(test_file)

    globals()[test_file.__name__] = test_file

for compression in COMPRESSIONS:
    _make_test(compression)
