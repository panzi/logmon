import logging
import threading

from time import monotonic
from math import inf
from .constants import *
from .schema import LimitsConfig

logger = logging.getLogger(__name__)

__all__ = (
    'LimitsService',
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

class LimitsService:
    __slots__ = (
        '_lock', '_hour_timestamps', '_minute_timestamps',
        '_max_emails_per_minute', '_max_emails_per_hour',
        '_last_minute_warning_ts', '_last_hour_warning_ts',
    )

    _lock: threading.Lock
    _hour_timestamps: list[float]
    _minute_timestamps: list[float]
    _max_emails_per_minute: int
    _max_emails_per_hour: int
    _last_minute_warning_ts: float
    _last_hour_warning_ts: float

    def __init__(self, max_emails_per_minute: int, max_emails_per_hour: int) -> None:
        self._lock = threading.Lock()
        self._hour_timestamps   = []
        self._minute_timestamps = []
        self._max_emails_per_minute = max_emails_per_minute
        self._max_emails_per_hour   = max_emails_per_hour
        self._last_minute_warning_ts = -inf
        self._last_hour_warning_ts = -inf

    @staticmethod
    def from_config(config: LimitsConfig) -> 'LimitsService':
        return LimitsService(
            max_emails_per_hour=config.get('max_emails_per_hour', DEFAULT_MAX_EMAILS_PER_HOUR),
            max_emails_per_minute=config.get('max_emails_per_minute', DEFAULT_MAX_EMAILS_PER_MINUTE),
        )

    @property
    def max_emails_per_minute(self) -> int:
        return self._max_emails_per_minute

    @property
    def max_emails_per_hour(self) -> int:
        return self._max_emails_per_hour

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

            minutes_ok = minutes_count < self._max_emails_per_minute
            hours_ok   = hours_count   < self._max_emails_per_hour

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
            logger.warning(f"Maximum emails per minute exceeded! {minutes_count} >= {self._max_emails_per_minute}")

        if warn_hour:
            logger.warning(f"Maximum emails per hour exceeded! {hours_count} >= {self._max_emails_per_hour}")

        return minutes_ok and hours_ok
