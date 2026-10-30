"""In-memory, privacy-preserving Lab telemetry exports."""

from __future__ import annotations

import csv
import html
import io
import json
import zipfile
from typing import Any


def json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


def _csv_bytes(rows: list[dict[str, Any]], fields: list[str]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def zip_bytes(payload: dict[str, Any]) -> bytes:
    host_rows = payload.get("host_samples", [])
    timeline_rows = []
    for event in payload.get("timeline", []):
        timeline_rows.append({
            "t_offset_ms": event.get("t_offset_ms"),
            "timestamp": event.get("timestamp"),
            "source": event.get("source"),
            "type": event.get("type"),
            "message": event.get("message"),
            "payload_json": json.dumps(event.get("payload", {}), sort_keys=True),
        })
    host_fields = [
        "source", "timestamp", "cpu_percent", "memory_percent",
        "disk_read_bytes_per_second", "disk_write_bytes_per_second",
        "network_sent_bytes_per_second", "network_received_bytes_per_second",
        "process_count", "thread_count",
    ]
    timeline_fields = ["t_offset_ms", "timestamp", "source", "type", "message", "payload_json"]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("metadata.json", json.dumps(payload.get("metadata", {}), indent=2, sort_keys=True))
        archive.writestr("summary.json", json.dumps(payload.get("summary", {}), indent=2, sort_keys=True))
        archive.writestr("host_samples.csv", _csv_bytes(host_rows, host_fields))
        archive.writestr("timeline.csv", _csv_bytes(timeline_rows, timeline_fields))
    return output.getvalue()


def html_bytes(payload: dict[str, Any]) -> bytes:
    metadata = payload.get("metadata", {})
    summary = payload.get("summary", {})
    events = payload.get("timeline", [])
    samples = payload.get("host_samples", [])

    def chart(key: str, title: str, color: str) -> str:
        values = [sample.get(key) for sample in samples if isinstance(sample.get(key), (int, float))]
        if not values:
            return f"<div><h3>{html.escape(title)}</h3><p>n/a</p></div>"
        maximum = max(max(values), 1)
        points = " ".join(f"{index * 100 / max(len(values) - 1, 1):.1f},{80 - (value / maximum) * 70:.1f}" for index, value in enumerate(values))
        return f"<div><h3>{html.escape(title)}</h3><svg viewBox=\"0 0 100 80\" role=\"img\" aria-label=\"{html.escape(title)} aggregate trend\" style=\"width:100%;height:90px;background:#0b1117\"><polyline points=\"{points}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" vector-effect=\"non-scaling-stroke\" /></svg></div>"

    charts = "".join([
        chart("cpu_percent", "CPU %", "#70d0e3"),
        chart("memory_percent", "Memory %", "#bba5f1"),
        chart("process_count", "Processes", "#ef949c"),
    ])
    event_rows = "".join(
        f"<tr><td>{html.escape(str(event.get('t_offset_ms', 'n/a')))}</td>"
        f"<td>{html.escape(str(event.get('source', 'n/a')).upper())}</td>"
        f"<td>{html.escape(str(event.get('type', 'n/a')))}</td>"
        f"<td>{html.escape(str(event.get('message', '')))}</td></tr>"
        for event in events
    )
    summary_rows = "".join(
        f"<tr><th>{html.escape(str(key).replace('_', ' '))}</th><td>{html.escape(str(value if value is not None else 'n/a'))}</td></tr>"
        for key, value in summary.items()
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SENTIVRA Lab telemetry {html.escape(str(payload.get('scenario_run_id', '')))}</title>
<style>body{{background:#0b1117;color:#dce8ee;font:14px system-ui,sans-serif;margin:2rem;line-height:1.5}}main{{max-width:1100px;margin:auto}}.panel{{border:1px solid #294051;border-radius:10px;padding:1rem;margin:1rem 0;background:#111b24}}h1,h2{{color:#70d0e3}}table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #294051;padding:.5rem;text-align:left;vertical-align:top}}th{{color:#adc0cc}}.notice{{border-left:3px solid #eac16c;padding:.6rem 1rem}}</style></head>
<body><main><h1>SENTIVRA Cyber Defense Lab telemetry</h1>
<p class="notice">Mode A replay: no real malware, host files not modified. Host telemetry is aggregate-only.</p>
<section class="panel"><h2>Metadata</h2><table>{''.join(f'<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>' for k,v in metadata.items())}</table></section>
<section class="panel"><h2>Summary</h2><table>{summary_rows}</table></section>
<section class="panel"><h2>Aggregate host charts</h2><div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem">{charts}</div></section>
<section class="panel"><h2>Ordered event timeline</h2><table><thead><tr><th>Offset (ms)</th><th>Source</th><th>Type</th><th>Message</th></tr></thead><tbody>{event_rows}</tbody></table></section>
</main></body></html>"""
    return document.encode("utf-8")
