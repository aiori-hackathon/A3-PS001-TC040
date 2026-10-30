"""Read-only Markdown reports for authenticated Cyber Defense executions."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.registry import DetectorRegistry
from app.models.simulation import SimulationExecutionORM
from app.security.auth import current_actor, require_scopes
from app.services.cyber_defense_report import REPORT_CAP, render_report
from app.services.simulation import get_execution

router = APIRouter(prefix="/api/v1/cyber-defense", tags=["cyber-defense-reports"], dependencies=[Depends(require_scopes("read"))])


def _response(markdown: str, filename: str) -> Response:
    return Response(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


def _filename(row: SimulationExecutionORM) -> str:
    scenario = "-".join(part for part in row.scenario_id.lower().split("-") if part) or "simulation"
    short_id = row.execution_id[:8]
    started = row.started_at.replace(tzinfo=row.started_at.tzinfo or datetime.now().astimezone().tzinfo)
    return f"sentivra-report-{scenario}-{short_id}-{started.strftime('%Y%m%d-%H%M%S')}.md"


@router.get("/executions/{execution_id}/report.md")
async def execution_report(
    execution_id: str,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> Response:
    try:
        row = get_execution(db, execution_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Simulation execution not found")
        return _response(render_report(row, db, registry), _filename(row))
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable") from exc


@router.get("/executions/report.md")
async def filtered_report(
    from_: str | None = Query(default=None, alias="from", max_length=64),
    to: str | None = Query(default=None, max_length=64),
    verdict: str | None = Query(default=None, max_length=32),
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> Response:
    try:
        statement = select(SimulationExecutionORM).where(
            SimulationExecutionORM.actor_id == current_actor(),
        )
        if from_:
            statement = statement.where(SimulationExecutionORM.started_at >= datetime.fromisoformat(from_))
        if to:
            statement = statement.where(SimulationExecutionORM.started_at <= datetime.fromisoformat(to))
        if verdict:
            normalized = verdict.upper()
            accepted = {
                "BLOCKED": ("BLOCKED", "SIMULATED_BLOCK"),
                "ALLOWED": ("ALLOWED", "SIMULATED_ALLOW"),
                "REVIEW": ("REVIEW_REQUIRED", "SIMULATED_REVIEW"),
                "UNAVAILABLE": ("ENFORCEMENT_UNAVAILABLE", "SIMULATED_UNAVAILABLE"),
            }
            if normalized not in accepted:
                raise HTTPException(status_code=422, detail="Unsupported verdict filter")
            statement = statement.where(SimulationExecutionORM.enforcement_decision.in_(accepted[normalized]))
        rows = list(db.execute(statement.order_by(SimulationExecutionORM.started_at.desc()).limit(REPORT_CAP)).scalars())
        sections = [
            "# SENTIVRA Filtered Execution Reports",
            "",
            f"This file contains at most {REPORT_CAP} actor-scoped simulation executions. Results are trusted stored records; no additional analysis was run while generating this file.",
            "",
        ]
        for row in rows:
            sections.append(render_report(row, db, registry))
            sections.append("\n---\n")
        if not rows:
            sections.append("No executions matched the selected filters.\n")
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return _response("\n".join(sections), f"sentivra-filtered-reports-{stamp}.md")
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Date filters must be ISO 8601 timestamps") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable") from exc
