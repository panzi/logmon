from typing import Literal, Any, Callable, Optional

import re
import json
import pydantic

from .types import JsonPath

__all__ = (
    'JsonPath',
    'JsonMatch',
    'get_json_path',
    'check_json_match',
    'parse_json_path',
    'parse_json_match',
    'compile_json_match',
    'compile_json_match_expr',
)

JSON_PATH_PATTERN_STR = r'(?P<key>[\$_a-z][\$_a-z0-9]*)|\[(?:(?P<index>[0-9]+)|(?P<qkey>"(?:[^"\\]|\\.)*"))\]'
JSON_PATH_START_PATTERN = re.compile(JSON_PATH_PATTERN_STR, re.I)
JSON_PATH_TAIL_PATTERN = re.compile(r'\.' + JSON_PATH_PATTERN_STR, re.I)

class Range(pydantic.BaseModel):
    start: int
    stop: int

    def __contains__(self, other) -> bool:
        if not isinstance(other, (int, float)):
            return False

        return other >= self.start and other < self.stop

class RangeValidator(pydantic.BaseModel):
    range: list[str|float|int|None]|Range

type EqExpr = tuple[Literal["=","!="],None|bool|float|int|str]
type OrdExpr = tuple[Literal["<",">","<=",">="],float|int|str]
type RangeExpr = tuple[Literal["in","not in"],list[str|float|int|None]|Range]
type RegExExpr = tuple[Literal["~"], str]
type JsonExpr = EqExpr|OrdExpr|RangeExpr|RegExExpr
type JsonMatch = dict[str|int, JsonExpr|JsonMatch]
type CompiledJsonMatch = dict[str|int, Callable[[Any], bool]|CompiledJsonMatch]

def get_json_path(obj: Any, path: JsonPath) -> Optional[Any]:
    try:
        for key in path:
            obj = obj[key]
    except (KeyError, IndexError, TypeError):
        return None

    return obj

def check_json_match(obj: Any, json_match: CompiledJsonMatch) -> bool:
    for key, check in json_match.items():
        try:
            value = obj[key]
        except (KeyError, IndexError, TypeError):
            return False

        if callable(check):
            if not check(value):
                return False

        elif not check_json_match(value, check):
            return False

    return True

def parse_json_path(path_def: str) -> JsonPath:
    path, index = _parse_json_path(path_def)
    tail = path_def[index:].strip()
    if tail:
        raise ValueError(f'Illegal JSON path: {path_def!r}')
    return path

def _parse_json_path(path_def: str) -> tuple[JsonPath, int]:
    m = JSON_PATH_START_PATTERN.match(path_def)
    if m is None:
        raise ValueError(f'Illegal JSON path: {path_def!r}')

    match = JSON_PATH_TAIL_PATTERN.match

    path: JsonPath = []
    index = m.end()

    while m is not None:
        if (key := m.group('key')) is not None:
            path.append(key)
        elif (index_str := m.group('index')) is not None:
            path.append(int(index_str, 10))
        elif (qkey := m.group('qkey')) is not None:
            path.append(json.loads(qkey))
        else:
            assert False, "No group defined!"

        index = m.end()
        m = match(path_def, index)

    return path, index

def parse_json_match(match_def: str) -> tuple[JsonPath, JsonExpr]:
    path, index = _parse_json_path(match_def)

    tail = match_def[index:].lstrip()
    try:
        for ord_op in "<=", ">=", "<", ">":
            if tail.startswith(ord_op):
                ord_value = json.loads(tail[len(ord_op):])

                if not isinstance(ord_value, (int, float, str)):
                    raise ValueError(f'{ord_op} is only defined for int, float, and str: {match_def!r}')

                return path, (ord_op, ord_value)

        for eq_op in "!=", "=":
            if tail.startswith(eq_op):
                eq_value = json.loads(tail[len(eq_op):])

                if not isinstance(eq_value, (int, float, str, bool)) and eq_value is not None:
                    raise ValueError(f'{eq_op} is only defined for int, float, str, bool and None: {match_def!r}')

                return path, (eq_op, eq_value)

        if tail.startswith("~"):
            tail = tail[1:].lstrip()
            re_value = json.loads(tail)
            if not isinstance(re_value, str):
                raise ValueError(f'~ is only defined for str: {match_def!r}')

            return path, ('~', re_value)

        in_op: Literal["in", "not in"]
        if tail.startswith("in") and not _is_json_word(tail[2:3]):
            tail = tail[2:]
            in_op = "in"
        elif tail.startswith("not") and not _is_json_word(tail[3:4]):
            tail = tail[3:]
            if tail.startswith("in") and not _is_json_word(tail[2:3]):
                tail = tail[2:]
                in_op = "not in"
            else:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}')
        else:
            raise ValueError(f'Illegal JSON match definition: {match_def!r}')

        if tail[1:2].isnumeric():
            range_parts = tail.split('..', 1)
            if len(range_parts) != 2:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}')

            try:
                start = int(range_parts[0], 10)
                stop = int(range_parts[1], 10)
            except ValueError as exc:
                raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

            return path, (in_op, Range(start=start, stop=stop))

        try:
            in_value = RangeValidator(range = json.loads(tail)).range
        except pydantic.ValidationError as exc:
            raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

        return path, (in_op, in_value)

    except json.JSONDecodeError as exc:
        raise ValueError(f'Illegal JSON match definition: {match_def!r}') from exc

def compile_json_match(json_match: JsonMatch) -> CompiledJsonMatch:
    compiled: CompiledJsonMatch = {}

    for key, value in json_match.items():
        if isinstance(value, dict):
            compiled[key] = compile_json_match(value)
        else:
            compiled[key] = compile_json_match_expr(value)

    return compiled

def compile_json_match_expr(expr: JsonExpr) -> Callable[[Any], bool]:
    op, expected = expr
    match op:
        case "=":  return lambda value: value == expected
        case "!=": return lambda value: value != expected
        case "in": return lambda value: value in expected # type: ignore
        case "not in": return lambda value: value not in expected # type: ignore
        case "~":
            regex = re.compile(expected) # type: ignore
            def check(value: Any) -> bool:
                if not isinstance(value, str):
                    return False
                return regex.match(value) is not None

            return check
        case "<":
            def check(value: Any) -> bool:
                try:
                    return value < expected
                except TypeError:
                    return False

            return check
        case ">":
            def check(value: Any) -> bool:
                try:
                    return value > expected
                except TypeError:
                    return False

            return check
        case "<=":
            def check(value: Any) -> bool:
                try:
                    return value <= expected
                except TypeError:
                    return False

            return check
        case ">=":
            def check(value: Any) -> bool:
                try:
                    return value >= expected
                except TypeError:
                    return False

            return check
        case _:
            raise NotImplementedError

def _is_json_word(ch: str) -> bool:
    return ch.isalnum() or ch == '_' or ch == '$'
