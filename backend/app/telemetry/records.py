"""In-memory Mode A scenario telemetry records.

Scenario telemetry is deliberately not added to the existing SQL schema. The
existing simulation result remains authoritative and unchanged when telemetry
is disabled; enabled records are bounded, aggregate-only, and exportable while
the current process retains them.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from app import __version__
from app.core.config import get_settings
from app.telemetry.collector import hub


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def _payload_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    return None


def _numeric_payload(values: dict[str, Any]) -> dict[str, int | float]:
    return {key: number for key, value in values.items() if (number := _payload_number(value)) is not None}


class ScenarioTelemetryRecord:
    def __init__(self, scenario_run_id: str, scenario_id: str, scenario_name: str) -> None:
        self.scenario_run_id = scenario_run_id
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.mode = "Mode A replay"
        self.started_at = datetime.now(UTC)
        self._started_mono = time.monotonic()
        self._ended_mono: float | None = None
        self._ended_at: datetime | None = None
        self._lock = threading.RLock()
        self._events: list[dict[str, Any]] = []
        self._status = "RUNNING"
        self._final_status = "RUNNING"
        self._result: dict[str, Any] = {}
        self._model_versions: set[str] = set()
        self._thresholds: set[float] = set()
        self._scores: list[float] = []
        self._replayed_samples = 0
        self._record_event("simulated", "scenario_started", "Mode A replay started", {})

    def _offset(self) -> int:
        return max(0, round((time.monotonic() - self._started_mono) * 1000))

    def _record_event(self, source: str, event_type: str, message: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._events.append({
                "t_offset_ms": self._offset(),
                "timestamp": datetime.now(UTC).isoformat(),
                "source": source,
                "type": event_type,
                "message": message[:240],
                "payload": _numeric_payload(payload),
            })

    def record_stage_signal(self, scenario_signals: Iterable[dict[str, Any]]) -> None:
        signals = list(scenario_signals)
        self._replayed_samples += 1
        self._record_event(
            "simulated",
            "stage_signal",
            "Mode A replayed synthetic scenario signal",
            {"signal_count": max(1, len(signals)), "samples_replayed": self._replayed_samples},
        )

    def complete(
        self,
        *,
        detector_results: Iterable[Any],
        findings: Iterable[Any],
        assessment: Any,
        fusion_incident: dict[str, Any] | None,
        detection_state: str,
        enforcement_decision: str,
        errors: Iterable[str] = (),
    ) -> None:
        results = list(detector_results)
        suspicious = list(findings)
        error_list = list(errors)
        for result in results:
            model_version = getattr(result, "model_version", None)
            threshold = getattr(result, "threshold", None)
            score = getattr(result, "score", None)
            if model_version:
                self._model_versions.add(str(model_version))
            if isinstance(threshold, (int, float)):
                self._thresholds.add(float(threshold))
            if isinstance(score, (int, float)):
                self._scores.append(float(score))
            if getattr(result, "detector", "") == "RansomwareBehaviorDetector":
                self._record_event(
                    "sentivra",
                    "ransomware_score",
                    "Sentivra ransomware behavioral score recorded",
                    {"score": score, "threshold": threshold},
                )

        risk_score = getattr(assessment, "risk_score", None)
        self._record_event(
            "sentivra",
            "detection",
            f"Sentivra detection completed: {detection_state}",
            {"risk_score": risk_score, "finding_count": len(suspicious), "detector_count": len(results), "detected": int(detection_state == "DETECTED")},
        )
        if fusion_incident:
            self._record_event("sentivra", "fusion_incident", "Sentivra fusion incident correlated", {"signal_count": fusion_incident.get("signal_count", 0)})
        if detection_state == "DETECTED":
            self._record_event("mitigation", "mitigation_triggered", "would have isolated process (dry-run); Mode A replay only", {"real_world_action_taken": 0, "dry_run": 1})
        else:
            self._record_event("mitigation", "mitigation_triggered", "No host mitigation required; Mode A policy remains dry-run", {"real_world_action_taken": 0, "dry_run": 1})
        self._record_event(
            "mitigation",
            "containment_complete",
            "Mode A replay stopped at the detection boundary; no host action was taken",
            {"real_world_action_taken": 0, "replayed_samples": self._replayed_samples},
        )
        self._finish(
            status="PARTIALLY_COMPLETED" if error_list else "COMPLETED",
            final_status=detection_state,
            enforcement_decision=enforcement_decision,
            fusion_incident=fusion_incident,
        )

    def fail(self, message: str = "Mode A telemetry ended safely after an incomplete analysis") -> None:
        self._record_event("mitigation", "mitigation_triggered", message, {"real_world_action_taken": 0, "dry_run": 1})
        self._finish(status="FAILED", final_status="ANALYSIS_FAILED", enforcement_decision="SIMULATED_UNAVAILABLE", fusion_incident=None)

    def _finish(self, *, status: str, final_status: str, enforcement_decision: str, fusion_incident: dict[str, Any] | None) -> None:
        with self._lock:
            if self._ended_mono is not None:
                return
            self._ended_mono = time.monotonic()
            self._ended_at = datetime.now(UTC)
            self._status = status
            self._final_status = final_status
        self._record_event("sentivra", "scenario_ended", f"Mode A replay ended: {final_status}", {"completed": 1})

    def public_payload(self) -> dict[str, Any]:
        with self._lock:
            events = [dict(event) for event in self._events]
            host_samples = []
            for sample in hub.snapshot_internal(get_settings().lab_telemetry_ring_seconds):
                # The collector keeps no identifying fields. Filter by the
                # monotonic position so wall-clock changes cannot alter the
                # run window. The private counter is never exported.
                sample_mono = sample.get("_monotonic")
                if isinstance(sample_mono, (int, float)) and sample_mono < self._started_mono:
                    continue
                if isinstance(sample_mono, (int, float)) and self._ended_mono is not None and sample_mono > self._ended_mono:
                    continue
                host_samples.append({key: value for key, value in sample.items() if not key.startswith("_")})
            detection_event = next((event for event in events if event["type"] == "detection"), None)
            containment_event = next((event for event in events if event["type"] == "containment_complete"), None)
            relevant_samples = host_samples
            peak_cpu = _peak(relevant_samples, "cpu_percent")
            peak_disk = _peak_sum(relevant_samples, ("disk_read_bytes_per_second", "disk_write_bytes_per_second"))
            time_to_detect = detection_event["t_offset_ms"] if detection_event and detection_event["payload"].get("detected") == 1 else None
            time_to_contain = containment_event["t_offset_ms"] if containment_event else None
            end_time = self._ended_at
            return {
                "scenario_run_id": self.scenario_run_id,
                "scenario_type": self.scenario_id,
                "mode": self.mode,
                "status": self._status,
                "final_status": self._final_status,
                "start_time": _iso(self.started_at),
                "end_time": _iso(end_time),
                "metadata": {
                    "app_version": __version__,
                    "model_versions": sorted(self._model_versions),
                    "thresholds_used": sorted(self._thresholds),
                    "sources_contributing": sorted({event["source"] for event in events} | ({"host"} if host_samples else set())),
                    "safety_statement": "Mode A replay: no real malware, host files not modified.",
                    "mode_b": "Not enabled",
                },
                "timeline": events,
                "host_samples": relevant_samples,
                "summary": {
                    "time_to_detect_ms": time_to_detect,
                    "time_to_contain_ms": time_to_contain,
                    "peak_score": max(self._scores) if self._scores else None,
                    "samples_replayed_before_alert": self._replayed_samples if time_to_detect is not None else None,
                    "samples_replayed": self._replayed_samples,
                    "mitigation_outcome": "dry-run; no host process was signaled",
                    "peak_host_cpu_percent": peak_cpu,
                    "peak_host_disk_bytes_per_second": peak_disk,
                    "host_sample_count": len(relevant_samples),
                    "fusion_incident": bool(any(event["type"] == "fusion_incident" for event in events)),
                },
            }


def _peak(samples: list[dict[str, Any]], key: str) -> float | None:
    values = [float(sample[key]) for sample in samples if isinstance(sample.get(key), (int, float))]
    return max(values) if values else None


def _peak_sum(samples: list[dict[str, Any]], keys: tuple[str, str]) -> float | None:
    values = [sum(float(sample[key]) for key in keys if isinstance(sample.get(key), (int, float))) for sample in samples]
    return max(values) if values else None


class ScenarioTelemetryStore:
    def __init__(self) -> None:
        self._records: OrderedDict[str, ScenarioTelemetryRecord] = OrderedDict()
        self._lock = threading.RLock()
        self._max_records = 100

    def start(self, scenario_run_id: str, scenario_id: str, scenario_name: str) -> ScenarioTelemetryRecord:
        with self._lock:
            existing = self._records.get(scenario_run_id)
            if existing:
                return existing
            record = ScenarioTelemetryRecord(scenario_run_id, scenario_id, scenario_name)
            self._records[scenario_run_id] = record
            while len(self._records) > self._max_records:
                self._records.popitem(last=False)
            return record

    def get(self, scenario_run_id: str) -> ScenarioTelemetryRecord | None:
        with self._lock:
            return self._records.get(scenario_run_id)


store = ScenarioTelemetryStore()
