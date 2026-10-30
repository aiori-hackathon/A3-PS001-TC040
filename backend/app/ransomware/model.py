"""Safe loader and scorer for the trained MLRan ransomware model.

The model consumes only a bounded behavioral feature vector. It never reads
host files, launches processes, watches the host, or performs network I/O.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.core.config import get_settings

MODEL_NAME = "RanDe-method-MLRan-ransomware"
MODEL_ID = "mlran-ransomware-binary"


class RansomwareModelUnavailable(RuntimeError):
    """The opt-in model is not configured or its artifact is incomplete."""


class RansomwareModelInputError(ValueError):
    """A feature vector does not match the trained schema."""


class RansomwareModel:
    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or get_settings().ransomware_model_dir
        self._model: Any | None = None
        self._pipeline: Any | None = None
        self._schema: list[str] = []
        self._threshold = 0.5
        self._metadata: dict[str, Any] = {}
        self._global_features: list[dict[str, Any]] = []
        self._error: str | None = None
        self._load()

    @property
    def enabled(self) -> bool:
        return get_settings().ransomware_model_enabled

    @property
    def version(self) -> str:
        return str(self._metadata.get("model_version", "unavailable"))

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def feature_names(self) -> list[str]:
        return list(self._schema)

    @property
    def global_features(self) -> list[dict[str, Any]]:
        return list(self._global_features)

    def availability(self) -> dict[str, str]:
        if not self.enabled:
            return {"status": "Not Configured", "detail": "Ransomware model is disabled by RANSOMWARE_MODEL_ENABLED."}
        if self._error:
            return {"status": "Not Configured", "detail": self._error}
        return {
            "status": "Available",
            "detail": f"MLRan 483-feature behavioral model loaded ({self.version}); no host monitoring is performed.",
        }

    def _load(self) -> None:
        if not self.enabled:
            return
        required = ["model.joblib", "pipeline.joblib", "feature_schema.json", "threshold.json", "metadata.json"]
        missing = [name for name in required if not (self.model_dir / name).is_file()]
        if missing:
            self._error = f"Missing ransomware model artifacts: {', '.join(missing)}"
            return
        try:
            self._model = joblib.load(self.model_dir / "model.joblib")
            self._pipeline = joblib.load(self.model_dir / "pipeline.joblib")
            self._schema = json.loads((self.model_dir / "feature_schema.json").read_text(encoding="utf-8"))["features"]
            self._threshold = float(json.loads((self.model_dir / "threshold.json").read_text(encoding="utf-8"))["threshold"])
            self._metadata = json.loads((self.model_dir / "metadata.json").read_text(encoding="utf-8"))
            importance_path = self.model_dir / "shap_global.json"
            if importance_path.is_file():
                self._global_features = json.loads(importance_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - availability must fail closed
            self._error = f"Ransomware model artifacts could not be loaded: {type(exc).__name__}"
            self._model = self._pipeline = None

    def predict(self, features: Mapping[str, float]) -> dict[str, Any]:
        if not self.enabled or self._model is None or self._pipeline is None:
            raise RansomwareModelUnavailable(self.availability()["detail"])
        supplied = set(features)
        expected = set(self._schema)
        missing = sorted(expected - supplied)
        extra = sorted(supplied - expected)
        if missing or extra:
            detail = []
            if missing:
                detail.append(f"missing {len(missing)} feature(s)")
            if extra:
                detail.append(f"unknown {len(extra)} feature(s)")
            raise RansomwareModelInputError("Feature vector schema mismatch: " + "; ".join(detail))
        vector = np.asarray([[float(features[name]) for name in self._schema]], dtype=np.float64)
        transformed = self._pipeline.transform(vector)
        probabilities = self._model.predict_proba(transformed)
        classes = list(getattr(self._model, "classes_", [0, 1]))
        positive_index = classes.index(1) if 1 in classes else len(classes) - 1
        probability = float(probabilities[0][positive_index])
        top_features = self._top_features(vector[0])
        return {
            "ransomware_probability": probability,
            "threshold": self._threshold,
            "is_ransomware": probability >= self._threshold,
            "model_id": MODEL_ID,
            "model_version": self.version,
            "top_features": top_features,
        }

    def _top_features(self, vector: np.ndarray) -> list[dict[str, Any]]:
        # SHAP global rankings are saved by the training script. Per-vector
        # ranking uses the observed magnitude as a transparent, deterministic
        # explanation without claiming a new local SHAP computation.
        ranked = []
        for item in self._global_features[:25]:
            index = self._schema.index(str(item["feature"])) if str(item["feature"]) in self._schema else -1
            if index >= 0:
                ranked.append({**item, "observed_value": float(vector[index])})
        return sorted(ranked, key=lambda item: abs(float(item.get("mean_abs_shap", 0.0)) * float(item["observed_value"])), reverse=True)[:5]


def load_model() -> RansomwareModel:
    return RansomwareModel()


def load_held_out_replay_vector(*, ransomware: bool = True) -> dict[str, float]:
    """Load one fixed MLRan test row for the host-safe lab replay.

    This reads only the gitignored behavioral CSV. It never opens a sample,
    touches a host path outside the repository data directory, or executes
    anything from the dataset.
    """
    data_path = get_settings().ransomware_model_dir.parents[2] / "data" / "mlran" / "MLRan_X_test_RFE.csv"
    if not data_path.is_file():
        raise RansomwareModelUnavailable("MLRan held-out replay data is not present in data/mlran")
    model = RansomwareModel()
    if not model.feature_names:
        raise RansomwareModelUnavailable("Ransomware feature schema is unavailable")
    with data_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if bool(int(row.get("sample_type", "0"))) is ransomware:
                return {name: float(row[name]) for name in model.feature_names}
    raise RansomwareModelUnavailable("No matching held-out MLRan replay row was found")
