"""Instance-owned clearance snapshots with process-wide invalidation support."""

import threading
import weakref


def clearance_cookies(cookies):
    """Solver browser authentication cookies must never enter the caller's jar."""
    value = cookies.get("cf_clearance")
    return {"cf_clearance": value} if value else {}


class ClearanceCache:
    _instances = weakref.WeakSet()
    _lock = threading.Lock()

    def __init__(self):
        self._entries = {}
        with self._lock:
            self._instances.add(self)

    def get(self, key):
        with self._lock:
            return self._entries.get(key)

    def set(self, key, value):
        with self._lock:
            self._entries[key] = value

    def clear(self):
        with self._lock:
            self._entries.clear()

    @classmethod
    def clear_all(cls, host=None):
        with cls._lock:
            for cache in list(cls._instances):
                if host is None:
                    cache._entries.clear()
                else:
                    for key in list(cache._entries):
                        if key[0] == host.lower():
                            del cache._entries[key]
