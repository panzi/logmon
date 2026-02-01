from typing import Mapping, Optional, Literal, override

import logging
import threading

from time import monotonic
from math import inf
from abc import ABC, abstractmethod

from .constants import *
from .schema import LimitsConfig, ActionConfig, Config, MTConfig

logger = logging.getLogger(__name__)

__all__ = (
    'AbstractLimiter',
    'Limiter',
    'NullLimiter',
    'resolve_limiter',
    'build_limiters',
)

def remove_smaller(items: list[float], cutoff: float) -> None:
    index = 0
    while index < len(items):
        start_index = index
        while index < len(items):
            item = items[index]
            if item >= cutoff:
                break
            index += 1
        end_index = index
        if start_index != end_index:
            del items[start_index:end_index]
            index = start_index
        else:
            index += 1

class AbstractLimiter(ABC):
    __slots__ = (
        '_name'
    )

    _name: str

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    def check(self) -> bool:
        ...

class NullLimiter(AbstractLimiter):
    __slots__ = ()

    @override
    def check(self) -> bool:
        return True

    @staticmethod
    def get_instance() -> "NullLimiter":
        global _null_limiter

        limiter = _null_limiter
        if limiter is None:
            limiter = _null_limiter = NullLimiter('')

        return limiter

_null_limiter: Optional[NullLimiter] = None

class Limiter(AbstractLimiter):
    __slots__ = (
        '_lock', '_hour_timestamps', '_minute_timestamps',
        '_max_actions_per_minute', '_max_actions_per_hour',
        '_last_minute_warning_ts', '_last_hour_warning_ts',
    )

    _lock: threading.Lock
    _hour_timestamps: list[float]
    _minute_timestamps: list[float]
    _max_actions_per_minute: Optional[int]
    _max_actions_per_hour: Optional[int]
    _last_minute_warning_ts: float
    _last_hour_warning_ts: float

    def __init__(self, name: str, max_actions_per_minute: Optional[int], max_actions_per_hour: Optional[int]) -> None:
        super().__init__(name)
        self._lock = threading.Lock()
        self._hour_timestamps   = []
        self._minute_timestamps = []
        self._max_actions_per_minute = max_actions_per_minute
        self._max_actions_per_hour   = max_actions_per_hour
        self._last_minute_warning_ts = -inf
        self._last_hour_warning_ts = -inf

    @staticmethod
    def from_config(name: str, config: LimitsConfig) -> 'Limiter':
        return Limiter(
            name=name,
            max_actions_per_hour=config.get('max_actions_per_hour', DEFAULT_MAX_ACTIONS_PER_HOUR),
            max_actions_per_minute=config.get('max_actions_per_minute', DEFAULT_MAX_ACTIONS_PER_MINUTE),
        )

    @property
    def name(self) -> str:
        return self._name

    @property
    def max_actions_per_minute(self) -> Optional[int]:
        return self._max_actions_per_minute

    @property
    def max_actions_per_hour(self) -> Optional[int]:
        return self._max_actions_per_hour

    def check(self) -> bool:
        warn_minute = False
        warn_hour = False

        with self._lock:
            now = monotonic()
            hour_cutoff = now - (60 * 60)
            minute_cutoff = now - 60

            remove_smaller(self._minute_timestamps, minute_cutoff)
            remove_smaller(self._hour_timestamps, hour_cutoff)

            minutes_count = len(self._minute_timestamps)
            hours_count   = len(self._hour_timestamps)

            max_actions_per_minute = self._max_actions_per_minute
            max_actions_per_hour   = self._max_actions_per_hour

            minutes_ok = max_actions_per_minute is None or minutes_count < max_actions_per_minute
            hours_ok   = max_actions_per_hour   is None or hours_count   < max_actions_per_hour

            if not minutes_ok:
                if self._last_minute_warning_ts < minute_cutoff:
                    warn_minute = True
                    self._last_minute_warning_ts = now

            elif not hours_ok:
                if self._last_hour_warning_ts < hour_cutoff:
                    warn_hour = True
                    self._last_hour_warning_ts = now

            else:
                self._hour_timestamps.append(now)
                self._minute_timestamps.append(now)

        if warn_minute:
            logger.warning(f"[{self._name}] Maximum actions per minute exceeded! {minutes_count} >= {max_actions_per_minute}")

        if warn_hour:
            logger.warning(f"[{self._name}] Maximum actions per hour exceeded! {hours_count} >= {max_actions_per_hour}")

        return minutes_ok and hours_ok

def resolve_limiter(limiters: Mapping[str, AbstractLimiter], action_config: ActionConfig, config: Config) -> AbstractLimiter:
    global _null_limiter

    name: str|None|Literal[-1] = action_config.get('limiter', -1)
    if name == -1:
        name = config.get('limiter', -1)

        if name == -1:
            name = 'default'

    if name is None:
        return NullLimiter.get_instance()

    limiter = limiters.get(name)

    if limiter is None:
        raise KeyError(f'Limiter {name!r} is not defined!')

    return limiter

def build_limiters(config: MTConfig) -> Mapping[str, AbstractLimiter]:
    limiters: dict[str, AbstractLimiter] = {}

    limits = config.get('limits')
    if limits:
        for name, cfg in limits.items():
            if cfg is None:
                limiters[name] = NullLimiter(name)
            elif not name:
                # because the empty string is used for the default NullLimiter
                raise ValueError(f'Limiter name may not be empty!')
            else:
                max_actions_per_hour   = cfg.get('max_actions_per_hour', DEFAULT_MAX_ACTIONS_PER_HOUR)
                max_actions_per_minute = cfg.get('max_actions_per_minute', DEFAULT_MAX_ACTIONS_PER_MINUTE)

                if max_actions_per_hour is None and max_actions_per_minute is None:
                    limiters[name] = NullLimiter(name)
                else:
                    limiters[name] = Limiter(
                        name = name,
                        max_actions_per_hour   = max_actions_per_hour,
                        max_actions_per_minute = max_actions_per_minute,
                    )

    if 'default' not in limiters:
        limiters['default'] = Limiter(
            name = 'default',
            max_actions_per_minute = DEFAULT_MAX_ACTIONS_PER_MINUTE,
            max_actions_per_hour   = DEFAULT_MAX_ACTIONS_PER_HOUR,
        )

    return limiters
