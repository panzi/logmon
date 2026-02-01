import os
import sys
import pytest
import tracemalloc

from pathlib import Path
from os.path import join as join_path
from tempfile import gettempdir

tracemalloc.start()

SRC_PATH = str(Path(__file__).resolve().parent.parent)

if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

@pytest.fixture(scope="function")
def temp_prefix(request: pytest.FixtureRequest) -> tuple[str, str]:
    tempdir = gettempdir()
    PID = os.getpid()
    func_name = request.function.__name__

    return tempdir, f'logmon.test.{PID}.{func_name}'

@pytest.fixture(scope="function")
def logfiles(temp_prefix: tuple[str, str], count: int = 3):
    tempdir, prefix = temp_prefix

    paths = [
        join_path(tempdir, f'{prefix}.logfile{i}.log')
        for i in range(1, count + 1)
    ]

    yield paths

    for path in paths:
        if os.path.exists(path):
            print(f"{path}: was not deleted", file=sys.stderr)

@pytest.fixture(scope="function")
def logmonrc_path(temp_prefix: tuple[str, str]):
    tempdir, prefix = temp_prefix

    path = join_path(tempdir, f'{prefix}.logmonrc.yaml')

    yield path

    if os.path.exists(path):
        print(f"{path}: was not deleted", file=sys.stderr)
