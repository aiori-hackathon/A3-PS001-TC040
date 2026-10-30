"""Safe Markdown reporting for stored Cyber Defense Lab executions."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any

from app import __version__
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.integrations.common import without_body
from app.services.event_repository import EventRepository
from app.services.simulation import SCENARIO_MAP, serialize

REPORT_CAP = 200
VERIFIED_STANDARDS = (
    ("OAuth 2.0 client credentials", "RFC 6749", "https://www.rfc-editor.org/rfc/rfc6749"),
    ("Bearer token authorization", "RFC 6750", "https://www.rfc-editor.org/rfc/rfc6750"),
    ("HTTP semantics", "RFC 9110", "https://www.rfc-editor.org/rfc/rfc9110"),
    ("JSON data interchange", "RFC 8259", "https://www.rfc-editor.org/rfc/rfc8259"),
    ("Sigma / MITRE ATT&CK", "non-IETF detection frameworks", "https://sigmahq.io/"),
)


def _value(value: Any) -> str:
    if value is None or value == "":
        return "Not recorded"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _markdown_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def _duration(previous: datetime | None, current: str) -> str:
    if previous is None:
        return "—"
    try:
        stamp = datetime.fromisoformat(current)
        return f"{max(0, (stamp - previous).total_seconds()):.3f}s"
    except ValueError:
        return "Not recorded"


def _plain_verdict(decision: str) -> str:
    return {
        "SIMULATED_BLOCK": "BLOCKED",
        "BLOCKED": "BLOCKED",
        "SIMULATED_ALLOW": "ALLOWED",
        "ALLOWED": "ALLOWED",
        "SIMULATED_REVIEW": "REVIEW REQUIRED",
        "REVIEW_REQUIRED": "REVIEW REQUIRED",
    }.get(decision, "UNAVAILABLE")


def render_report(row, db, registry: DetectorRegistry) -> str:
    payload = serialize(row)
    scenario = SCENARIO_MAP.get(row.scenario_id)
    event = EventRepository(db).get(row.event_id, actor=row.actor_id) if row.event_id else None
    redacted_input: Any = None
    if event is not None:
        redacted_input = json.loads(without_body(EventRepository(db).to_domain(event)).model_dump_json())

    result = payload.get("risk_assessment") or {}
    detector_results = payload.get("detector_results") or []
    findings = payload.get("findings") or []
    target = payload.get("target") or {}
    enforcement = payload.get("enforcement") or {}
    timeline = payload.get("timeline") or []
    detector_names = ", ".join(sorted({item.get("detector", "Unknown") for item in detector_results})) or "Not recorded"
    detector_versions = ", ".join(sorted({item.get("model_version") for item in detector_results if item.get("model_version")})) or "Not recorded"
    started = payload.get("started_at", "Not recorded")
    completed = payload.get("completed_at", "Not recorded")
    explanation = enforcement.get("reason") or "No policy explanation was recorded."
    if _plain_verdict(row.enforcement_decision) == "BLOCKED":
        explanation = f"The recorded detector identified a suspicious indicator. {explanation} The synthetic protected operation was not executed."
    elif _plain_verdict(row.enforcement_decision) == "ALLOWED":
        explanation = f"The recorded detector did not identify a suspicious indicator in this trusted control fixture. {explanation} The synthetic protected operation was executed only inside the local target."

    lines = [
        "# SENTIVRA Execution Report",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Execution ID | `{_value(row.execution_id)}` |",
        f"| Scenario | {_value(scenario.name if scenario else row.scenario_id)} (`{_value(row.scenario_id)}`) |",
        "| Data source | SIMULATED |",
        f"| Start time | {_value(started)} |",
        f"| End time | {_value(completed)} |",
        f"| Duration | {_value(f'{row.duration_ms:.2f} ms' if row.duration_ms is not None else None)} |",
        f"| Sentivra version / commit | `{__version__}` / `{os.getenv('SENTIVRA_COMMIT', 'unknown/local')}` |",
        f"| Detector | {_value(detector_names)} |",
        f"| Detector version | {_value(detector_versions)} |",
        f"| Backend environment | {_value(get_settings().env)} |",
        "",
        "## Summary",
        "",
        f"**Verdict:** {_plain_verdict(row.enforcement_decision)}  ",
        f"**Risk / severity:** {_value(result.get('risk_score'))} / {_value(result.get('severity'))}",
        "",
        explanation,
        "",
        "## Input",
        "",
        "This is a trusted, harmless synthetic fixture. The persisted input below is passed through Sentivra's existing body-redaction function before reporting.",
        "",
        "```json",
        _markdown_json(redacted_input) if redacted_input is not None else "Not recorded because the event was not persisted.",
        "```",
        f"\nTarget boundary: `{_value(target.get('endpoint') or scenario.target_endpoint if scenario else None)}`.",
        "",
        "## Detection",
        "",
        f"Detector results: {len(detector_results)}; findings: {len(findings)}.",
        "",
        "### Evidence",
        "",
    ]
    evidence_rows = []
    for detector_result in detector_results:
        for evidence in detector_result.get("evidence", []):
            evidence_rows.append(
                f"- **{_value(detector_result.get('detector'))} — {_value(evidence.get('type'))}:** "
                f"{_value(evidence.get('detail'))}"
            )
    lines.extend(evidence_rows or ["No evidence items were recorded."])
    lines.extend([
        "",
        f"Confidence values returned by detectors: {_value(', '.join(str(item.get('confidence')) for item in detector_results if item.get('confidence') is not None) or None)}.",
        f"Limitations: {_value(scenario.limitation if scenario else None)}",
        "",
        "## Policy decision",
        "",
        f"Decision: **{_value(enforcement.get('decision') or row.enforcement_decision)}**",
        f"Reason: {_value(enforcement.get('reason'))}",
        "Simulation only: no real traffic, system process, database, file, or external application was blocked.",
        "",
        "## Standards exercised",
        "",
        *[f"- [{name}]({url}) — {identifier}" for name, identifier, url in VERIFIED_STANDARDS],
        "",
        "## Timeline",
        "",
        "| Stage | Timestamp | Since previous stage |",
        "| --- | --- | --- |",
    ])
    previous: datetime | None = None
    for entry in timeline:
        stamp = entry.get("timestamp", "Not recorded")
        current: datetime | None = None
        try:
            current = datetime.fromisoformat(stamp)
        except ValueError:
            pass
        lines.append(f"| {_value(entry.get('stage'))} | {_value(stamp)} | {_duration(previous, stamp)} |")
        previous = current or previous
    if not timeline:
        lines.append("| No recorded stages | Not recorded | — |")
    lines.extend([
        "",
        "## Limitations & honesty note",
        "",
        "This report describes a local simulation on trusted synthetic fixtures. Animated progress is presentation only, not live packet telemetry. A detector finding is not proof of compromise, and simulated blocking does not block real traffic.",
        "",
        "## Reproduce",
        "",
        "1. Start the backend with `uvicorn app.main:app --reload` from `backend/`.",
        "2. Start the dashboard with `npm run dev` from `frontend/`.",
        f"3. Sign in, open Cyber Defense Lab, select **{_value(scenario.name if scenario else row.scenario_id)}**, and choose **Run simulation**.",
        "4. Download this report from the execution result or history row.",
        "",
    ])
    body = "\n".join(lines).rstrip() + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    generated = datetime.now(UTC).isoformat()
    return f"{body}\n---\nGenerated at: {generated}\nReport body SHA-256: `{digest}`\n"
