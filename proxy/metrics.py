"""Tiny in-process metrics. Operational (requests, errors, latency) and product
(records processed, gate outcomes, inline redactions, certs signed, verifies)."""
import threading
import time

_lock = threading.Lock()
_counters = {}
_latency = {}  # name -> [count, total_seconds]


def inc(name, by=1):
    with _lock:
        _counters[name] = _counters.get(name, 0) + by


def observe_latency(name, seconds):
    with _lock:
        c, t = _latency.get(name, (0, 0.0))
        _latency[name] = (c + 1, t + seconds)


class timer:
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        observe_latency(self.name, time.perf_counter() - self._t0)


def snapshot():
    with _lock:
        out = dict(_counters)
        for name, (c, t) in _latency.items():
            out[f"{name}_count"] = c
            out[f"{name}_avg_ms"] = round((t / c) * 1000, 2) if c else 0.0
        return out
