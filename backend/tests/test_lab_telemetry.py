from __future__ import annotations

import asyncio
import builtins
import io
import json
import os
import signal
import socket
import subprocess
import time
import uuid
import zipfile
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.telemetry.collector import AggregateProbe, hub


@pytest.fixture()
def telemetry_enabled(monkeypatch):
    monkeypatch.setenv("SENTIVRA_LAB_TELEMETRY_ENABLED", "true")
    get_settings.cache_clear()
    yield
    monkeypatch.setenv("SENTIVRA_LAB_TELEMETRY_ENABLED", "false")
    get_settings.cache_clear()


def test_collector_is_aggregate_only_and_read_only(monkeypatch):
    class Process:
        def num_threads(self):
            return 3

    monkeypatch.setattr("app.telemetry.collector.psutil.cpu_percent", lambda interval=None: 12.5)
    monkeypatch.setattr("app.telemetry.collector.psutil.virtual_memory", lambda: SimpleNamespace(percent=44.0))
    monkeypatch.setattr("app.telemetry.collector.psutil.disk_io_counters", lambda: SimpleNamespace(read_bytes=100, write_bytes=200))
    monkeypatch.setattr("app.telemetry.collector.psutil.net_io_counters", lambda: SimpleNamespace(bytes_sent=300, bytes_recv=400))
    monkeypatch.setattr("app.telemetry.collector.psutil.process_iter", lambda *args, **kwargs: iter([SimpleNamespace(info={"num_threads": 3}), SimpleNamespace(info={"num_threads": 3})]))
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("collector attempted a file operation"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("collector spawned a process"))
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("collector opened a socket"))
    monkeypatch.setattr(os, "kill", lambda *args, **kwargs: pytest.fail("collector signaled a process"))
    monkeypatch.setattr(signal, "raise_signal", lambda *args, **kwargs: pytest.fail("collector signaled a process"))

    probe = AggregateProbe()
    probe.prime()
    sample = probe.sample()
    assert sample["source"] == "host"
    assert sample["process_count"] == 2
    assert sample["thread_count"] == 6
    assert {"cpu_percent", "memory_percent", "disk_read_bytes_per_second", "network_sent_bytes_per_second"} <= set(sample)
    assert "cmdline" not in json.dumps(sample)
    assert "username" not in json.dumps(sample)


async def test_sse_samples_then_stops_after_disconnect(telemetry_enabled, app_client):
    assert app_client.get("/api/v1/lab-telemetry/status").status_code == 200
    class Request:
        async def is_disconnected(self):
            return False

    from app.telemetry.collector import sse_events

    events = sse_events(Request())
    first = await anext(events)
    assert "telemetry_status" in first or "host_sample" in first
    found_sample = False
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        frame = await asyncio.wait_for(anext(events), timeout=3)
        if '"type": "host_sample"' in frame:
            found_sample = True
            break
    assert found_sample
    await events.aclose()
    deadline = time.monotonic() + 3
    while hub.subscription_count() and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert hub.subscription_count() == 0


def test_mode_a_run_and_exports_are_private_and_match(telemetry_enabled, app_client):
    request_key = f"telemetry-{uuid.uuid4()}"
    start = app_client.post("/api/v1/lab-telemetry/runs/start", json={
        "scenario_id": "sqli-indicator", "scenario_run_id": request_key, "mode": "mode_a",
    })
    assert start.status_code == 200, start.text
    result = app_client.post("/api/simulation/run", json={
        "scenario_id": "sqli-indicator", "mode": "simulation", "request_key": request_key,
    })
    assert result.status_code == 200, result.text
    telemetry = result.json()["lab_telemetry"]
    assert telemetry["mode"] == "Mode A replay"
    assert telemetry["metadata"]["mode_b"] == "Not enabled"
    assert all(event["source"] in {"simulated", "sentivra", "mitigation"} for event in telemetry["timeline"])
    assert telemetry["timeline"] == app_client.get(f"/api/v1/lab-telemetry/runs/{request_key}").json()["timeline"]
    serialized = json.dumps(telemetry)
    for forbidden in ("cmd.exe", "C:\\Users\\", "/home/", "127.0.0.1", "192.168.", "sentinel-user"):
        assert forbidden not in serialized

    json_response = app_client.get(f"/api/v1/lab-telemetry/runs/{request_key}/export.json")
    assert json_response.status_code == 200
    assert json.loads(json_response.content)["timeline"] == telemetry["timeline"]

    zip_response = app_client.get(f"/api/v1/lab-telemetry/runs/{request_key}/export.zip")
    assert zip_response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(zip_response.content)) as archive:
        assert {"metadata.json", "summary.json", "host_samples.csv", "timeline.csv"} <= set(archive.namelist())
        assert request_key not in archive.read("timeline.csv").decode()

    html_response = app_client.get(f"/api/v1/lab-telemetry/runs/{request_key}/export.html")
    assert html_response.status_code == 200
    assert "Mode A replay: no real malware" in html_response.text
    assert "127.0.0.1" not in html_response.text


def test_flag_off_preserves_existing_simulation_response(monkeypatch, app_client):
    monkeypatch.setenv("SENTIVRA_LAB_TELEMETRY_ENABLED", "false")
    get_settings.cache_clear()
    response = app_client.post("/api/simulation/run", json={"scenario_id": "sqli-indicator", "mode": "simulation", "request_key": f"off-{uuid.uuid4()}"})
    assert response.status_code == 200
    assert "lab_telemetry" not in response.json()
    assert app_client.get("/api/v1/lab-telemetry/status").json()["enabled"] is False
    get_settings.cache_clear()


def test_mode_a_does_not_signal_processes_or_open_network(telemetry_enabled, monkeypatch, app_client):
    calls: list[str] = []
    file_writes: list[str] = []
    real_open = builtins.open

    def audited_open(file, *args, **kwargs):
        mode = kwargs.get("mode", args[0] if args else "r")
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            file_writes.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", audited_open)
    monkeypatch.setattr(os, "kill", lambda *args, **kwargs: calls.append("os.kill"))
    monkeypatch.setattr(signal, "raise_signal", lambda *args, **kwargs: calls.append("signal"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: calls.append("subprocess"))
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: calls.append("network"))
    response = app_client.post("/api/simulation/run", json={"scenario_id": "ransomware-replay", "mode": "simulation", "request_key": f"safe-{uuid.uuid4()}"})
    assert response.status_code == 200
    assert calls == []
    assert file_writes == []


def test_collector_one_second_overhead_measurement():
    probe = AggregateProbe()
    probe.prime()
    started = time.perf_counter()
    cpu_started = time.process_time()
    time.sleep(1.0)
    probe.sample()
    wall = time.perf_counter() - started
    cpu = time.process_time() - cpu_started
    assert wall >= 1.0
    assert cpu / wall < 0.02
