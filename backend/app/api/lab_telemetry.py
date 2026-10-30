"""Opt-in Cyber Defense Lab Mode A telemetry and exports."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import get_settings
from app.security.auth import require_scopes
from app.services.simulation import SCENARIO_MAP
from app.telemetry.collector import sse_events
from app.telemetry.export import html_bytes, json_bytes, zip_bytes
from app.telemetry.records import store

router = APIRouter(
    prefix="/api/v1/lab-telemetry",
    tags=["lab-telemetry"],
    dependencies=[Depends(require_scopes("read"))],
)


class TelemetryStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=64)
    scenario_run_id: str = Field(min_length=1, max_length=128)
    mode: Literal["mode_a"] = "mode_a"


@router.get("/status")
async def status() -> dict:
    settings = get_settings()
    return {
        "enabled": settings.lab_telemetry_enabled,
        "sample_interval_seconds": settings.lab_telemetry_sample_interval_s if settings.lab_telemetry_enabled else None,
        "ring_seconds": settings.lab_telemetry_ring_seconds if settings.lab_telemetry_enabled else None,
        "transport": "sse" if settings.lab_telemetry_enabled else None,
        "mode_a": "Available" if settings.lab_telemetry_enabled else "Disabled",
        "mode_b": "Not enabled",
    }


@router.get("/stream")
async def stream(request: Request):
    if not get_settings().lab_telemetry_enabled:
        raise HTTPException(status_code=404, detail="Lab telemetry is disabled")
    return StreamingResponse(
        sse_events(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.post("/runs/start")
async def start_run(payload: TelemetryStartRequest) -> dict:
    if not get_settings().lab_telemetry_enabled:
        raise HTTPException(status_code=404, detail="Lab telemetry is disabled")
    scenario = SCENARIO_MAP.get(payload.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Unknown trusted simulation scenario")
    record = store.start(payload.scenario_run_id, scenario.scenario_id, scenario.name)
    return record.public_payload()


@router.get("/runs/{scenario_run_id}")
async def run_telemetry(scenario_run_id: str) -> dict:
    if not get_settings().lab_telemetry_enabled:
        raise HTTPException(status_code=404, detail="Lab telemetry is disabled")
    record = store.get(scenario_run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Lab telemetry run not found")
    return record.public_payload()


def _export_response(data: bytes, media_type: str, filename: str) -> Response:
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _payload_for_export(scenario_run_id: str) -> dict:
    if not get_settings().lab_telemetry_enabled:
        raise HTTPException(status_code=404, detail="Lab telemetry is disabled")
    record = store.get(scenario_run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Lab telemetry run not found")
    return record.public_payload()


@router.get("/runs/{scenario_run_id}/export.json")
async def export_json(scenario_run_id: str) -> Response:
    payload = await _payload_for_export(scenario_run_id)
    return _export_response(json_bytes(payload), "application/json", f"sentivra-lab-{scenario_run_id[:12]}.json")


@router.get("/runs/{scenario_run_id}/export.zip")
async def export_zip(scenario_run_id: str) -> Response:
    payload = await _payload_for_export(scenario_run_id)
    return _export_response(zip_bytes(payload), "application/zip", f"sentivra-lab-{scenario_run_id[:12]}.zip")


@router.get("/runs/{scenario_run_id}/export.html")
async def export_html(scenario_run_id: str) -> Response:
    payload = await _payload_for_export(scenario_run_id)
    return _export_response(html_bytes(payload), "text/html", f"sentivra-lab-{scenario_run_id[:12]}.html")
