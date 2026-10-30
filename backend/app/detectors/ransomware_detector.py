"""Opt-in MLRan behavioral ransomware detector."""

from __future__ import annotations

from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for
from app.events.schema import SecurityEvent, SecurityEventType
from app.ransomware.model import (
    RansomwareModel,
    RansomwareModelInputError,
    RansomwareModelUnavailable,
)
from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    Evidence,
    FindingStatus,
    Severity,
)


class RansomwareDetector(BaseDetector):
    name = "RansomwareBehaviorDetector"
    version = "mlran-1.0"
    category = DetectorCategory.BEHAVIORAL_ANOMALY
    applicable_event_types = frozenset({SecurityEventType.ENDPOINT_BATCH})

    def __init__(self) -> None:
        self.model = RansomwareModel()

    async def is_available(self) -> DetectorAvailability:
        state = self.model.availability()
        return DetectorAvailability(status=AvailabilityStatus(state["status"]), detail=state["detail"], engine_version=self.model.version)

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        features = event.metadata.get("ransomware_features")
        if not isinstance(features, dict):
            return DetectionResult(
                detector=self.name, category=self.category, severity=Severity.SAFE, score=0,
                confidence=0, recommended_action=action_for(Severity.SAFE),
                status=FindingStatus.INVALID_INPUT, model_id="mlran-ransomware-binary",
                model_version=self.model.version,
                evidence=[Evidence(type="input", detail="No MLRan behavioral feature vector was supplied.")],
            )
        try:
            prediction = self.model.predict(features)
        except RansomwareModelUnavailable:
            return DetectionResult(
                detector=self.name, category=self.category, severity=Severity.SAFE, score=0,
                confidence=0, recommended_action=action_for(Severity.SAFE),
                status=FindingStatus.SCANNER_OR_MODEL_UNAVAILABLE, model_id="mlran-ransomware-binary",
                model_version=self.model.version,
            )
        except RansomwareModelInputError as exc:
            return DetectionResult(
                detector=self.name, category=self.category, severity=Severity.SAFE, score=0,
                confidence=0, recommended_action=action_for(Severity.SAFE),
                status=FindingStatus.INVALID_INPUT, model_id="mlran-ransomware-binary",
                model_version=self.model.version,
                evidence=[Evidence(type="input_schema", detail=str(exc))],
            )

        probability = float(prediction["ransomware_probability"])
        suspicious = bool(prediction["is_ransomware"])
        severity = Severity.HIGH if suspicious else Severity.SAFE
        evidence = []
        if suspicious:
            evidence.append(Evidence(
                type="mlran_behavioral_score",
                detail=f"Ransomware probability {probability:.4f} crossed threshold {prediction['threshold']:.4f}.",
                weight=probability,
            ))
            for item in prediction.get("top_features", []):
                evidence.append(Evidence(
                    type="shap_global_feature",
                    detail=f"Feature {item['feature']} observed={item['observed_value']} mean_abs_shap={item.get('mean_abs_shap', 0):.6f}.",
                    weight=float(item.get("mean_abs_shap", 0.0)),
                ))
        else:
            evidence.append(Evidence(type="mlran_behavioral_score", detail=f"Ransomware probability {probability:.4f} remained below threshold {prediction['threshold']:.4f}."))
        return DetectionResult(
            detector=self.name, category=self.category, severity=severity, score=probability,
            confidence=max(probability, 1.0 - probability), evidence=evidence,
            recommended_action=action_for(severity),
            status=FindingStatus.SUSPICIOUS if suspicious else FindingStatus.NO_FINDING_OBSERVED,
            model_id=prediction["model_id"], threshold=prediction["threshold"],
            model_version=prediction["model_version"],
        )
