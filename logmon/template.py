from typing import Any, Generator, Iterable, Mapping

import re

from copy import deepcopy
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

BRACKETS = re.compile(r'[\[\]]')

def parse_object_path(path: str) -> list[str|None]:
    search_br = BRACKETS.search
    m = search_br(path)
    if m is None:
        return [path]

    br = m.group(0)
    if br != '[':
        raise SyntaxError(f'illegal object path: {path!r}')

    parsed: list[str|None] = []

    br_start = m.start()
    if br_start > 0:
        parsed.append(path[:br_start])

    pos = m.start()
    while pos < len(path):
        if not path.startswith('[', pos):
            raise SyntaxError(f'illegal object path: {path!r}')

        pos += 1
        m = search_br(path, pos)
        if m is None:
            raise SyntaxError(f'illegal object path: {path!r}')

        br = m.group(0)
        if br != ']':
            raise SyntaxError(f'illegal object path: {path!r}')

        br_start = m.start()

        if pos == br_start:
            parsed.append(None)
        else:
            parsed.append(path[pos:br_start])

        pos = br_start + 1

    return parsed

def expand_object(object: Iterable[tuple[str, str]], params: Mapping[str, Any]) -> dict[str, Any]|list[Any]:
    expanded: dict[str, Any]|list[Any]|None = None
    match_templ = TEMPL_PATTERN.match

    for strpath, templ in object:
        path = parse_object_path(strpath)

        if expanded is None:
            expanded = [] if path[0] is None else {}

        obj: Any = expanded
        for key, next_key in zip(path, path[1:]):
            if key is None:
                if not isinstance(obj, list):
                    raise TypeError(f'Conflict: path {strpath} expects list but found {type(obj).__name__}')

                new_obj: dict[str, Any]|list[Any] = [] if next_key is None else {}
                obj.append(new_obj)
                obj = new_obj
            elif not isinstance(obj, dict):
                raise TypeError(f'Conflict: path {strpath} expects dict but found {type(obj).__name__}')
            else:
                if key not in obj:
                    new_obj = [] if next_key is None else {}
                    obj[key] = new_obj
                    obj = new_obj
                else:
                    obj = obj[key]

        key = path[-1]
        m = match_templ(templ)
        extend = False
        value: Any

        if m is None:
            value = templ

        elif m.start() == 0 and m.end() == len(templ):
            splat = m.group('splat')
            var = m.group('var')
            fmt = m.group('fmt')

            value = params.get(var)

            if splat:
                extend = True
                if fmt:
                    xfmt = f'{{{fmt}}}'

                    if hasattr(value, '__iter__'):
                        value = [xfmt.format(v) for v in value] # type: ignore
                    else:
                        value = [xfmt.format(value)]
                else:
                    if hasattr(value, '__iter__'):
                        value = deepcopy(value)
                        if not isinstance(value, (list, tuple)):
                            value = list(value) # type: ignore
                    else:
                        value = [deepcopy(value)]

            elif fmt:
                xfmt = f'{{{fmt}}}'
                value = xfmt.format(value)

        else:
            value = list(expand(templ, params))
            if len(value) == 1:
                value = value[0]

        if key is None:
            if not isinstance(obj, list):
                raise TypeError(f'Conflict: path {strpath} expects list but found {type(obj).__name__}')

            if extend:
                obj.extend(value) # type: ignore
            else:
                obj.append(value)

        elif not isinstance(obj, dict):
            raise TypeError(f'Conflict: path {strpath} expects dict but found {type(obj).__name__}')

        elif key in obj:
            raise TypeError(f'Conflict: path {strpath} defined multiple times')

        else:
            obj[key] = value

    return expanded if expanded is not None else {}

if __name__ == '__main__':
    import sys
    import json

    templ: list[tuple[str, str]] = []
    params: dict[str, Any] = {}

    argind = 1
    while argind < len(sys.argv):
        arg = sys.argv[argind]
        argind += 1
        if arg == '--':
            break

        key, value = arg.split('=', 1)
        templ.append((key, value))

    for arg in sys.argv[argind:]:
        key, value = arg.split('=', 1)
        ch = value[:1]
        if ch not in "{}[].0123456789" and value not in ("true", "false", "null"):
            params[key] = value
        else:
            params[key] = json.loads(value)

    json.dump(expand_object(templ, params), sys.stdout, indent=4)
    sys.stdout.write('\n')

    #for res in expand(templ, params):
    #    print('---')
    #    print(res)
