"""Opt-in ransomware feature-vector scoring and health endpoints.

This route accepts behavioral features only. It does not accept files, execute
samples, inspect the host, or perform mitigation itself; findings enter the
existing event/risk/alert pipeline.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.audit import service as audit_service
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from app.ransomware.fusion import correlate_ransomware
from app.ransomware.model import RansomwareModel
from app.security.auth import current_actor, require_scopes
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api/v1/ransomware", tags=["ransomware"])
DETECTOR_NAME = "RansomwareBehaviorDetector"


class FeatureVectorRequest(BaseModel):
    features: dict[str, float] = Field(min_length=1, max_length=600)
    context_signals: list[dict[str, str]] = Field(default_factory=list, max_length=16)

    @field_validator("features")
    @classmethod
    def feature_keys_are_bounded(cls, value: dict[str, float]) -> dict[str, float]:
        if any(len(key) > 100 for key in value):
            raise ValueError("Feature names are too long")
        return value


@router.get("/health", dependencies=[Depends(require_scopes("read"))])
async def ransomware_health() -> dict:
    settings = get_settings()
    if not settings.ransomware_model_enabled:
        return {"enabled": False, "status": "Disabled", "detail": "Set RANSOMWARE_MODEL_ENABLED=true to opt in."}
    state = RansomwareModel().availability()
    return {"enabled": True, **state}


@router.post("/predict", dependencies=[Depends(require_scopes("analyze"))])
async def predict_ransomware(
    request: FeatureVectorRequest,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    settings = get_settings()
    if not settings.ransomware_model_enabled:
        raise HTTPException(status_code=404, detail="Ransomware model is disabled")
    detector = registry.get(DETECTOR_NAME)
    if detector is None:
        raise HTTPException(status_code=503, detail="Ransomware detector is unavailable")
    event = SecurityEvent(
        event_type=SecurityEventType.ENDPOINT_BATCH,
        source="ransomware-feature-vector",
        source_type=SourceType.LIVE,
        metadata={"ransomware_features": request.features, "ransomware_input": "feature_vector"},
    )
    findings, assessment = await run_pipeline(
        event,
        db=db,
        registry=registry,
        actor=current_actor(),
        detector_allowlist=[DETECTOR_NAME],
    )
    ransomware_result = next((item for item in findings if item.detector == DETECTOR_NAME), None)
    fusion_incident = correlate_ransomware(ransomware_result, request.context_signals)
    if fusion_incident:
        audit_service.record(
            db,
            actor=current_actor(),
            action="ransomware_fusion_dry_run",
            resource=f"event:{event.event_id}",
            detail={"classification": fusion_incident["classification"], "signal_count": fusion_incident["signal_count"], "real_world_action_taken": False},
            commit=True,
        )
    return {
        "event_id": event.event_id,
        "source_type": SourceType.LIVE.value,
        "model": RansomwareModel().availability(),
        "findings": [item.model_dump(mode="json") for item in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
        "fusion_incident": fusion_incident,
    }
