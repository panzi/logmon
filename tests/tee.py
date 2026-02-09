#!/usr/bin/env python

import sys

def tee(path: str) -> None:
    with open(path, "wt") as fp:
        for line in sys.stdin:
            fp.write(line)
            sys.stdout.write(line)

if __name__ == '__main__':
    tee(sys.argv[1])
