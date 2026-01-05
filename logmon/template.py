from typing import Any, Generator, Iterable, Mapping

import re

from itertools import product

TEMPL_PATTERN = re.compile(r'{(?P<splat>\.\.\.)?(?P<var>[-_0-9a-z]+)(?P<fmt>(?:![^:{}]+)?(?::[^{}]*)?)?}|{{|}}|{|}', re.I)

def expand(templ: str, params: Mapping[str, Any]) -> Generator[str, None, None]:
    buf: list[str] = []
    items: list[str] = []
    splats: list[list[str]] = []

    index = 0
    search = TEMPL_PATTERN.search
    while True:
        m = search(templ, index)
        if m is None:
            break

        start_index = m.start()
        buf.append(templ[index:m.start()])

        item = m.group(0)
        match item:
            case '{{':
                buf.append('{')

            case '}}':
                buf.append('}')

            case '{' | '}':
                lineno = templ.count('\n', 0, start_index) + 1
                linestart = templ.rfind('\n', 0, start_index) + 1
                column = start_index - linestart

                raise SyntaxError(f'in line {lineno} at column {column}: illegal single {item!r}')

            case _:
                splat = m.group('splat')
                var = m.group('var')
                value = params.get(var)
                fmt = m.group('fmt')

                if splat:
                    items.append(''.join(buf))
                    if fmt:
                        xfmt = f'{{{fmt}}}'

                        if hasattr(value, '__iter__'):
                            splats.append([xfmt.format(v) for v in value]) # type: ignore
                        else:
                            splats.append([xfmt.format(value)])
                    else:
                        if hasattr(value, '__iter__'):
                            splats.append([str(v) for v in value]) # type: ignore
                        else:
                            splats.append([str(value)])
                    buf.clear()
                else:
                    if fmt:
                        buf.append(f'{{{fmt}}}'.format(value))
                    else:
                        buf.append(str(value))

        index = start_index + len(item)

    buf.append(templ[index:])
    items.append(''.join(buf))

    for row in product(*splats):
        buf.clear()

        for prefix, item in zip(items, row):
            buf.append(prefix)
            buf.append(item)

        buf.append(items[-1])
        yield ''.join(buf)

def expand_args_multi(args: Iterable[str], params: Mapping[str, Any]) -> Generator[tuple[str, ...], None, None]:
    xargs: list[list[str]] = [list(expand(arg, params)) for arg in args]

    yield from product(*xargs)

def expand_args_inline(args: Iterable[str], params: Mapping[str, Any]) -> list[str]:
    return [
        item
        for arg in args
        for item in expand(arg, params)
    ]

if __name__ == '__main__':
    import sys
    import json

    templ = sys.argv[1]
    params: dict[str, Any] = {}

    for arg in sys.argv[2:]:
        key, value = arg.split('=', 1)
        ch = value[:1]
        if ch not in "{}[].0123456789" and value not in ("true", "false", "null"):
            params[key] = value
        else:
            params[key] = json.loads(value)

    for res in expand(templ, params):
        print('---')
        print(res)
