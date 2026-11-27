"""Shared timing policy for synchronous and asynchronous result polling."""

import math
import time
from email.utils import parsedate_to_datetime


def retry_delay(response, failures: int) -> float:
    """Back off transient API failures, respecting Retry-After seconds or dates."""
    delay = min(2.0 ** min(failures - 1, 5), 30.0)
    value = response.headers.get("Retry-After")
    if value is None:
        return delay
    try:
        retry_after = float(value)
    except (TypeError, ValueError):
        try:
            retry_after = parsedate_to_datetime(value).timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            return delay
    if math.isfinite(retry_after):
        delay = max(delay, retry_after)
    return delay
