"""Read-only aggregate host telemetry and the Lab SSE subscription hub.

This module intentionally has no filesystem, subprocess, socket, registry, or
signal APIs. ``psutil`` is used only for aggregate counters. Samples live in a
bounded in-memory deque and are published to authenticated SSE subscribers.
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psutil

from app.core.config import get_settings


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _delta_per_second(current: int | None, previous: int | None, elapsed: float) -> float | None:
    if current is None or previous is None or elapsed <= 0:
        return None
    return max(0.0, (current - previous) / elapsed)


def _counter_pair(counter: Any | None) -> tuple[int | None, int | None]:
    if counter is None:
        return None, None
    return getattr(counter, "read_bytes", None), getattr(counter, "write_bytes", None)


def _network_pair(counter: Any | None) -> tuple[int | None, int | None]:
    if counter is None:
        return None, None
    return getattr(counter, "bytes_sent", None), getattr(counter, "bytes_recv", None)


class AggregateProbe:
    """A narrow psutil adapter that never asks for identifying process data."""

    def __init__(self) -> None:
        self._previous_mono: float | None = None
        self._previous_disk: tuple[int | None, int | None] = (None, None)
        self._previous_network: tuple[int | None, int | None] = (None, None)
        self._process_count: int | None = None
        self._thread_count: int | None = None
        self._process_sample_mono: float | None = None

    def _refresh_process_counts(self) -> None:
        try:
            processes = list(psutil.process_iter(["num_threads"]))
            self._process_count = len(processes)
            self._thread_count = sum(int(process.info.get("num_threads") or 0) for process in processes)
        except (psutil.Error, OSError, AttributeError, TypeError, ValueError):
            self._process_count = None
            self._thread_count = None
        self._process_sample_mono = time.monotonic()

    def prime(self) -> None:
        # Establish baselines without using a blocking interval or touching a
        # process object. The first published sample has real current values;
        # rates remain n/a until a second counter is available.
        try:
            psutil.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            pass
        self._previous_mono = time.monotonic()
        try:
            self._previous_disk = _counter_pair(psutil.disk_io_counters())
        except (psutil.Error, OSError):
            self._previous_disk = (None, None)
        try:
            self._previous_network = _network_pair(psutil.net_io_counters())
        except (psutil.Error, OSError):
            self._previous_network = (None, None)
        # Process/thread enumeration is materially more expensive on Windows
        # than the other counters. Refresh it at connection start and then
        # every 90 seconds; the other metrics still publish every second.
        self._refresh_process_counts()

    def sample(self) -> dict[str, Any]:
        now = time.monotonic()
        elapsed = now - (self._previous_mono or now)
        try:
            disk = _counter_pair(psutil.disk_io_counters())
        except (psutil.Error, OSError):
            disk = (None, None)
        try:
            network = _network_pair(psutil.net_io_counters())
        except (psutil.Error, OSError):
            network = (None, None)

        # No process name, command line, username, path, handle, signal, or
        # mutation is read. Counts are intentionally cached to keep the
        # once-per-second collector below the bounded-overhead target.
        if self._process_sample_mono is None or now - self._process_sample_mono >= 90.0:
            self._refresh_process_counts()

        try:
            cpu_percent = psutil.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            cpu_percent = None
        try:
            memory_percent = getattr(psutil.virtual_memory(), "percent", None)
        except (psutil.Error, OSError):
            memory_percent = None

        result = {
            "source": "host",
            "timestamp": _iso_now(),
            "cpu_percent": _number(cpu_percent),
            "memory_percent": _number(memory_percent),
            "disk_read_bytes_per_second": _number(_delta_per_second(disk[0], self._previous_disk[0], elapsed)),
            "disk_write_bytes_per_second": _number(_delta_per_second(disk[1], self._previous_disk[1], elapsed)),
            "network_sent_bytes_per_second": _number(_delta_per_second(network[0], self._previous_network[0], elapsed)),
            "network_received_bytes_per_second": _number(_delta_per_second(network[1], self._previous_network[1], elapsed)),
            "process_count": self._process_count,
            "thread_count": self._thread_count,
        }
        self._previous_mono = now
        self._previous_disk = disk
        self._previous_network = network
        return result


def _number(value: Any) -> int | float | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    return int(numeric) if numeric.is_integer() else numeric


@dataclass(eq=False)
class Subscription:
    events: queue.Queue[dict[str, Any]]


class HostTelemetryHub:
    """Owns the one sampler thread and stops it when the last SSE closes."""

    def __init__(self) -> None:
        settings = get_settings()
        self._ring: deque[dict[str, Any]] = deque(maxlen=max(60, settings.lab_telemetry_ring_seconds))
        self._subscriptions: set[Subscription] = set()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._probe_factory = AggregateProbe

    def subscribe(self) -> Subscription:
        subscription = Subscription(queue.Queue(maxsize=4))
        with self._lock:
            self._subscriptions.add(subscription)
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, name="sentivra-lab-telemetry", daemon=True)
                self._thread.start()
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        with self._lock:
            self._subscriptions.discard(subscription)
            if not self._subscriptions:
                self._stop.set()

    def snapshot(self, limit: int = 1) -> list[dict[str, Any]]:
        return [self._public_sample(sample) for sample in self.snapshot_internal(limit)]

    def snapshot_internal(self, limit: int = 1) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._ring)[-max(1, min(limit, len(self._ring))):]

    @staticmethod
    def _public_sample(sample: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in sample.items() if not key.startswith("_")}

    def subscription_count(self) -> int:
        with self._lock:
            return len(self._subscriptions)

    def _run(self) -> None:
        probe = self._probe_factory()
        try:
            probe.prime()
            interval = max(0.25, float(get_settings().lab_telemetry_sample_interval_s))
            while not self._stop.wait(interval):
                sample = probe.sample()
                sample["_monotonic"] = time.monotonic()
                public_sample = self._public_sample(sample)
                with self._lock:
                    self._ring.append(sample)
                    subscribers = tuple(self._subscriptions)
                for subscriber in subscribers:
                    try:
                        subscriber.events.put_nowait(public_sample)
                    except queue.Full:
                        try:
                            subscriber.events.get_nowait()
                        except queue.Empty:
                            pass
                        try:
                            subscriber.events.put_nowait(public_sample)
                        except queue.Full:
                            pass
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None


hub = HostTelemetryHub()


async def sse_events(request: Any) -> AsyncIterator[str]:
    """Yield SSE frames until the authenticated request disconnects."""
    subscription = hub.subscribe()
    try:
        latest = hub.snapshot(1)
        if latest:
            yield f"data: {json.dumps({'type': 'host_sample', 'sample': latest[0], 'reconnect': True})}\n\n"
        else:
            yield "data: {\"type\":\"telemetry_status\",\"status\":\"sampling\"}\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                sample = await asyncio.to_thread(subscription.events.get, True, 2.0)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {json.dumps({'type': 'host_sample', 'sample': sample})}\n\n"
    finally:
        hub.unsubscribe(subscription)
