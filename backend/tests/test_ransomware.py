from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

from app.core.config import get_settings
from app.ransomware.fusion import correlate_ransomware
from app.ransomware.model import RansomwareModel
from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    Evidence,
    FindingStatus,
    RecommendedAction,
    Severity,
)


def _finding() -> DetectionResult:
    return DetectionResult(
        detector="RansomwareBehaviorDetector",
        category=DetectorCategory.BEHAVIORAL_ANOMALY,
        severity=Severity.HIGH,
        score=0.99,
        confidence=0.99,
        evidence=[Evidence(type="test", detail="synthetic behavioral evidence")],
        recommended_action=RecommendedAction.BLOCK,
        status=FindingStatus.SUSPICIOUS,
        model_id="mlran-ransomware-binary",
    )


def test_ransomware_fusion_is_additive_and_dry_run():
    incident = correlate_ransomware(_finding(), [{"source": "network-detector", "severity": "MEDIUM"}])
    assert incident is not None
    assert incident["classification"] == "ransomware_attack_chain"
    assert incident["signal_count"] == 1
    assert incident["mitigation"]["mode"] == "dry_run"
    assert incident["mitigation"]["real_world_action_taken"] is False


def test_safe_ransomware_result_does_not_create_incident():
    safe = _finding().model_copy(update={"severity": Severity.SAFE, "score": 0.01, "evidence": []})
    assert correlate_ransomware(safe, [{"source": "document-detector", "severity": "HIGH"}]) is None


def test_model_is_disabled_when_flag_is_false(monkeypatch):
    monkeypatch.setenv("SENTIVRA_RANSOMWARE_MODEL_ENABLED", "false")
    get_settings.cache_clear()
    try:
        assert RansomwareModel().availability()["status"] == "Not Configured"
    finally:
        get_settings.cache_clear()


def test_trained_model_scores_a_behavioral_vector(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    artifact_dir = root / "models" / "ransomware" / "mlran"
    if not (artifact_dir / "model.joblib").is_file():
        return
    monkeypatch.setattr(
        "app.ransomware.model.get_settings",
        lambda: SimpleNamespace(ransomware_model_enabled=True, ransomware_model_dir=artifact_dir),
    )
    schema = __import__("json").loads((artifact_dir / "feature_schema.json").read_text(encoding="utf-8"))["features"]
    with (root / "data" / "mlran" / "MLRan_X_test_RFE.csv").open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    prediction = RansomwareModel().predict({name: float(row[name]) for name in schema})
    assert 0.0 <= prediction["ransomware_probability"] <= 1.0
    assert prediction["model_id"] == "mlran-ransomware-binary"
