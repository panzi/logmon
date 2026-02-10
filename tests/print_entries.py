#!/usr/bin/env python

import argparse

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.set_defaults(entries=[])
    ap.add_argument('--entry', action='append', dest='entries')
    ap.add_argument('outfile')

    args = ap.parse_args()

    with open(args.outfile, 'wt') as fp:
        for entry in args.entries:
            fp.write(entry)

if __name__ == '__main__':
    main()
