"""Read-only correlation of ransomware findings with existing signals."""

from __future__ import annotations

import uuid
from typing import Any

from app.schemas.detection import DetectionResult, Severity


def correlate_ransomware(
    ransomware_result: DetectionResult | None,
    context_signals: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Return an additive incident summary without changing detector outputs.

    ``context_signals`` are trusted, already-produced findings from the normal
    Sentivra event pipeline. This helper only correlates them; it does not
    re-score or rewrite the source model results.
    """
    if ransomware_result is None or ransomware_result.severity == Severity.SAFE:
        return None
    signals = [signal for signal in (context_signals or []) if str(signal.get("severity", "SAFE")) != "SAFE"]
    classification = "ransomware_attack_chain" if signals else "ransomware_behavior"
    return {
        "incident_id": str(uuid.uuid4()),
        "classification": classification,
        "ransomware_detector": ransomware_result.detector,
        "supporting_signals": signals,
        "signal_count": len(signals),
        "mitigation": {
            "mode": "dry_run",
            "actions": ["alert", "mark_process_for_isolation", "flag_network_indicators", "notify"],
            "real_world_action_taken": False,
        },
    }
