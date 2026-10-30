"""Train and evaluate Sentivra's opt-in MLRan ransomware detector.

Usage from the repository root::

    backend/.venv/Scripts/python.exe scripts/train_ransomware_model.py

The script reads only behavioral feature vectors. It never downloads, opens,
executes, or writes malware samples. The downloaded MLRan data is expected in
``data/mlran`` and is gitignored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

SEED = 20261030
METADATA_COLUMNS = {"sample_id", "sample_type", "family_label", "type_label"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/mlran"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/ransomware/mlran"))
    parser.add_argument("--trials", type=int, default=8, help="Optuna trials for the LightGBM candidate")
    parser.add_argument("--seed", type=int, default=SEED)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_data(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame, list[str], dict[str, str]]:
    train = pd.read_csv(data_dir / "MLRan_X_train_RFE.csv")
    test = pd.read_csv(data_dir / "MLRan_X_test_RFE.csv")
    if set(train.columns) != set(test.columns):
        raise ValueError("MLRan train/test feature schemas differ")
    features = [column for column in train.columns if column not in METADATA_COLUMNS]
    if len(features) != 483:
        raise ValueError(f"Expected MLRan's 483 selected features, found {len(features)}")
    if any(train[column].dtype.kind not in "biufc" for column in features):
        raise ValueError("MLRan selected feature matrix must be numeric")
    mapping_path = data_dir / "RFE_selected_feature_names_dic.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8")) if mapping_path.is_file() else {}
    return train, test, features, {str(key): str(value) for key, value in mapping.items()}


def leakage_audit(train: pd.DataFrame, features: list[str]) -> dict[str, Any]:
    prohibited = {"sample_type", "family_label", "type_label", "ground_truth", "label", "verdict", "ransomware"}
    name_hits = [name for name in features if any(word in name.lower() for word in prohibited)]
    value_hits: list[str] = []
    for name in features:
        values = train[name].astype(str).str.lower()
        if values.isin({"ransomware", "benign", "goodware"}).any():
            value_hits.append(name)
    if name_hits or value_hits:
        raise ValueError(f"Leakage audit failed: names={name_hits}, values={value_hits}")
    exact_duplicates = int(train[features].duplicated().sum())
    near_duplicates = int(train[features].round(6).duplicated().sum())
    return {
        "label_columns_excluded": sorted(METADATA_COLUMNS - {"sample_id"}),
        "feature_name_keyword_hits": name_hits,
        "feature_value_keyword_hits": value_hits,
        "exact_duplicate_rows": exact_duplicates,
        "near_duplicate_rows_rounded_6dp": near_duplicates,
        "action": "No rows were silently removed; duplicate counts are reported for review.",
    }


def metrics(y_true: np.ndarray, probability: np.ndarray, threshold: float) -> dict[str, float]:
    predicted = (probability >= threshold).astype(int)
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probability)) if len(np.unique(y_true)) == 2 else float("nan"),
        "false_positive_rate": float(((predicted == 1) & (y_true == 0)).sum() / max(1, (y_true == 0).sum())),
    }


def choose_threshold(y_true: np.ndarray, probability: np.ndarray, target_recall: float = 0.98) -> dict[str, Any]:
    candidates = sorted({float(value) for value in probability}, reverse=True)
    scored = [(threshold, metrics(y_true, probability, threshold)) for threshold in candidates]
    eligible = [(threshold, result) for threshold, result in scored if result["recall"] >= target_recall]
    if eligible:
        threshold, result = eligible[0]
    else:
        threshold, result = min(scored, key=lambda item: abs(item[1]["recall"] - target_recall))
    return {"threshold": threshold, "target_recall": target_recall, "validation_metrics": result, "met_target": result["recall"] >= target_recall}


def make_model(name: str, seed: int, params: dict[str, Any] | None = None) -> Any:
    params = params or {}
    if name == "LightGBM":
        from lightgbm import LGBMClassifier

        defaults = {
            "objective": "binary", "n_estimators": 180, "learning_rate": 0.05, "num_leaves": 31,
            "min_child_samples": 15, "subsample": 0.9, "colsample_bytree": 0.85,
            "random_state": seed, "n_jobs": 2, "verbosity": -1,
        }
        defaults.update(params)
        return LGBMClassifier(**defaults)
    if name == "XGBoost":
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=180, max_depth=6, learning_rate=0.05, subsample=0.9,
            colsample_bytree=0.85, eval_metric="logloss", tree_method="hist",
            random_state=seed, n_jobs=2, **params,
        )
    if name == "RandomForest":
        return RandomForestClassifier(n_estimators=180, class_weight="balanced", random_state=seed, n_jobs=2, **params)
    if name == "ExtraTrees":
        return ExtraTreesClassifier(n_estimators=180, class_weight="balanced", random_state=seed, n_jobs=2, **params)
    if name == "LogisticRegression":
        return LogisticRegression(max_iter=1500, class_weight="balanced", C=1.0, solver="liblinear", random_state=seed, **params)
    raise ValueError(name)


def candidate_pipeline(name: str, seed: int, params: dict[str, Any] | None = None) -> Pipeline:
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", make_model(name, seed, params)),
    ])


def tune_lightgbm(x: np.ndarray, y: np.ndarray, groups: np.ndarray, seed: int, trials: int) -> dict[str, Any]:
    try:
        import optuna
    except ImportError:
        return {}
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=seed)

    def objective(trial: Any) -> float:
        params = {
            "num_leaves": trial.suggest_int("num_leaves", 15, 63),
            "min_child_samples": trial.suggest_int("min_child_samples", 10, 50),
            "learning_rate": trial.suggest_float("learning_rate", 0.02, 0.12, log=True),
            "n_estimators": trial.suggest_int("n_estimators", 100, 240),
        }
        scores = []
        for train_index, valid_index in splitter.split(x, y, groups):
            model = candidate_pipeline("LightGBM", seed, params)
            model.fit(x[train_index], y[train_index])
            if len(np.unique(y[valid_index])) == 2:
                scores.append(roc_auc_score(y[valid_index], model.predict_proba(x[valid_index])[:, 1]))
        if not scores:
            return 0.0
        return float(np.mean(scores))

    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=max(1, trials), show_progress_bar=False)
    return {**study.best_params, "best_value": study.best_value, "trials": trials}


def cross_validate(
    name: str,
    x: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    seed: int,
    params: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], np.ndarray]:
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    oof = np.zeros(len(y), dtype=float)
    fold_results = []
    for fold, (train_index, valid_index) in enumerate(splitter.split(x, y, groups), start=1):
        model = candidate_pipeline(name, seed + fold, params)
        model.fit(x[train_index], y[train_index])
        oof[valid_index] = model.predict_proba(x[valid_index])[:, 1]
        fold_results.append(metrics(y[valid_index], oof[valid_index], 0.5))
    aggregate = {key: float(np.mean([item[key] for item in fold_results])) for key in fold_results[0] if key != "threshold"}
    aggregate["folds"] = fold_results
    aggregate["group_count"] = len(np.unique(groups))
    return aggregate, oof


def save_figures(output: Path, y_test: np.ndarray, test_probability: np.ndarray, feature_importance: list[dict[str, Any]]) -> None:
    figures = output / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_test, (test_probability >= 0.5).astype(int))
    ConfusionMatrixDisplay(cm, display_labels=["benign", "ransomware"]).plot(cmap="Blues")
    plt.tight_layout(); plt.savefig(figures / "confusion_matrix.png", dpi=140); plt.close()
    fpr, tpr, _ = roc_curve(y_test, test_probability)
    plt.plot(fpr, tpr); plt.plot([0, 1], [0, 1], "--", color="grey"); plt.xlabel("False positive rate"); plt.ylabel("True positive rate"); plt.title("MLRan held-out ROC")
    plt.tight_layout(); plt.savefig(figures / "roc_curve.png", dpi=140); plt.close()
    precision, recall, _ = precision_recall_curve(y_test, test_probability)
    plt.plot(recall, precision); plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("MLRan held-out precision-recall")
    plt.tight_layout(); plt.savefig(figures / "precision_recall_curve.png", dpi=140); plt.close()
    top = feature_importance[:20][::-1]
    plt.barh([str(item["feature"]) for item in top], [item["mean_abs_shap"] for item in top]); plt.xlabel("Mean absolute SHAP value"); plt.title("Top behavioral features")
    plt.tight_layout(); plt.savefig(figures / "shap_summary.png", dpi=140); plt.close()


def main() -> None:
    args = parse_args()
    random.seed(args.seed); np.random.seed(args.seed)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    train, test, features, feature_mapping = load_data(args.data_dir)
    audit = leakage_audit(train, features)
    x_train = train[features].to_numpy(dtype=np.float64)
    y_train = train["sample_type"].to_numpy(dtype=int)
    # Family groups prevent the same ransomware family appearing in both sides
    # of a validation fold. Goodware is one family in MLRan, so deterministic
    # benign subgroups keep both classes present without mixing ransomware
    # families across folds.
    groups = np.where(
        train["sample_type"].to_numpy(dtype=int) == 0,
        "benign-" + (train["sample_id"].to_numpy(dtype=int) % 5).astype(str),
        "family-" + train["family_label"].astype(str).to_numpy(),
    )
    x_test = test[features].to_numpy(dtype=np.float64)
    y_test = test["sample_type"].to_numpy(dtype=int)

    tune_params = tune_lightgbm(x_train, y_train, groups, args.seed, args.trials)
    lightgbm_params = {key: value for key, value in tune_params.items() if key in {"num_leaves", "min_child_samples", "learning_rate", "n_estimators"}}
    candidates = ["XGBoost", "LightGBM", "RandomForest", "ExtraTrees", "LogisticRegression"]
    candidate_results: dict[str, Any] = {}
    oof_by_model: dict[str, np.ndarray] = {}
    available_candidates = []
    for name in candidates:
        try:
            start = time.perf_counter()
            params = lightgbm_params if name == "LightGBM" else None
            result, oof = cross_validate(name, x_train, y_train, groups, args.seed, params)
            result["training_seconds"] = time.perf_counter() - start
            candidate_results[name] = result
            oof_by_model[name] = oof
            available_candidates.append(name)
        except ImportError as exc:
            candidate_results[name] = {"status": "unavailable", "reason": str(exc)}
    if not available_candidates:
        raise RuntimeError("No ransomware model implementation is available")
    selected = max(available_candidates, key=lambda name: (candidate_results[name].get("recall", 0), candidate_results[name].get("f1", 0)))
    threshold_info = choose_threshold(y_train, oof_by_model[selected])
    final_params = lightgbm_params if selected == "LightGBM" else None
    final_base = candidate_pipeline(selected, args.seed, final_params)
    final_base.fit(x_train, y_train)
    final_imputer = final_base.named_steps["imputer"]
    calibrated = CalibratedClassifierCV(estimator=make_model(selected, args.seed, final_params), method="sigmoid", cv=3, n_jobs=2)
    calibrated.fit(final_imputer.transform(x_train), y_train)
    test_probability = calibrated.predict_proba(final_imputer.transform(x_test))[:, 1]
    test_metrics = metrics(y_test, test_probability, threshold_info["threshold"])

    feature_importance: list[dict[str, Any]]
    shap_status = "available"
    try:
        import shap

        estimator = calibrated.calibrated_classifiers_[0].estimator
        sample = final_imputer.transform(x_train[: min(500, len(x_train))])
        explainer = shap.LinearExplainer(estimator, sample) if hasattr(estimator, "coef_") else shap.TreeExplainer(estimator)
        values = explainer(sample).values
        if values.ndim == 3:
            values = values[:, :, 1]
        mean_abs = np.abs(values).mean(axis=0)
        feature_importance = [
            {"feature": features[index], "mean_abs_shap": float(mean_abs[index]), "source_name": feature_mapping.get(features[index])}
            for index in np.argsort(mean_abs)[::-1]
        ]
    except Exception as exc:  # noqa: BLE001 - artifact records explainability availability
        shap_status = f"unavailable: {type(exc).__name__}"
        importance = permutation_importance(final_base, x_test, y_test, n_repeats=2, random_state=args.seed, scoring="roc_auc", n_jobs=2).importances_mean
        feature_importance = [
            {"feature": features[index], "mean_abs_shap": float(max(0.0, importance[index])), "source_name": feature_mapping.get(features[index]), "fallback": "permutation_importance"}
            for index in np.argsort(importance)[::-1]
        ]

    joblib.dump(calibrated, args.output_dir / "model.joblib", compress=3)
    joblib.dump(final_imputer, args.output_dir / "pipeline.joblib", compress=3)
    (args.output_dir / "feature_schema.json").write_text(json.dumps({"features": features, "feature_names": feature_mapping}, indent=2), encoding="utf-8")
    (args.output_dir / "threshold.json").write_text(json.dumps(threshold_info, indent=2), encoding="utf-8")
    (args.output_dir / "shap_global.json").write_text(json.dumps(feature_importance, indent=2), encoding="utf-8")
    data_files = [args.data_dir / name for name in ["MLRan_X_train_RFE.csv", "MLRan_X_test_RFE.csv", "MLRan_labels.csv"]]
    metadata = {
        "name": "MLRan ransomware behavioral detector",
        "domain": "ransomware",
        "model_version": "mlran-ransomware-1.0.0",
        "version": "mlran-ransomware-1.0.0",
        "model_id": "mlran-ransomware-binary",
        "artifact_filename": "model.joblib",
        "artifact_format": "joblib",
        "sha256": sha256(args.output_dir / "model.joblib") if (args.output_dir / "model.joblib").is_file() else "generated-after-save",
        "training_seed": args.seed,
        "selected_model": selected,
        "feature_count": len(features),
        "train_rows": len(train),
        "test_rows": len(test),
        "source_hashes": {str(path.name): sha256(path) for path in data_files if path.is_file()},
        "shap_status": shap_status,
        "leakage_audit": audit,
        "dataset": "MLRan feature-selected RFE split from faithfulco/mlran",
        "training_dataset": "MLRan feature-selected RFE split (4,880 behavioral rows)",
        "datasets": [
            {"name": "MLRan", "role": "train/test", "license": "MIT", "source": "https://github.com/faithfulco/mlran", "notes": "Feature-selected 483-feature split; raw malware is not used."},
        ],
        "splits": {"train": len(train), "test": len(test)},
        "split_method": "MLRan supplied split with family-grouped five-fold validation",
        "preprocessing": {"numeric_features": len(features), "imputation": "median", "leakage_audit": "RanDe-inspired name/value audit"},
        "feature_schema": features,
        "threshold": threshold_info["threshold"],
        "threshold_policy": "Out-of-fold threshold selected for target recall >= 0.98",
        "calibration": {"method": "sigmoid", "cv": 3},
        "evaluation_metrics": {key: float(value) for key, value in test_metrics.items() if key != "threshold"},
        "evaluation": {"candidate_models": candidate_results, "threshold_selection": threshold_info, "held_out_test": test_metrics},
        "evaluation_date": __import__("datetime").date.today().isoformat(),
        "limitations": ["MLRan-derived metrics do not transfer 1:1 to live hosts.", "No OS-level isolation or automated host mitigation is implemented."],
        "methodology_reference": "RanDe-W11 preprocessing and leakage-audit methodology; no RanDe model used.",
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    metrics_payload = {
        "model_version": metadata["model_version"],
        "selected_model": selected,
        "candidate_models": candidate_results,
        "threshold_selection": threshold_info,
        "held_out_test": test_metrics,
        "class_balance": {"train": train["sample_type"].value_counts().to_dict(), "test": test["sample_type"].value_counts().to_dict()},
        "family_counts": {"train": int(train["family_label"].nunique()), "test": int(test["family_label"].nunique()), "group_held_out": len(np.unique(groups))},
        "data_card": {
            "rows": int(len(train) + len(test)), "features": len(features), "missing_values": int(pd.concat([train, test])[features].isna().sum().sum()),
            "exact_duplicates": audit["exact_duplicate_rows"], "near_duplicates_rounded_6dp": audit["near_duplicate_rows_rounded_6dp"],
        },
        "explainability": {"shap_status": shap_status, "top_features_file": "shap_global.json"},
    }
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    save_figures(args.output_dir, y_test, test_probability, feature_importance)
    model_card = f"""# Sentivra MLRan ransomware model card\n\n- Model: `{selected}`\n- Version: `{metadata['model_version']}`\n- Features: {len(features)} MLRan RFE behavioral features\n- Train/test rows: {len(train)} / {len(test)}\n- Threshold: {threshold_info['threshold']:.6f} (validation target recall {threshold_info['target_recall']:.2f})\n- Group-held-out evaluation: 5-fold `StratifiedGroupKFold`, grouped by MLRan family label\n- Explainability: {shap_status}; see `shap_global.json` and `figures/shap_summary.png`\n\nThe complete measured results are in `metrics.json`. The test set is the supplied MLRan held-out split and was not used for training, tuning, or threshold selection. Dataset metrics do not transfer 1:1 to live hosts.\n"""
    (args.output_dir / "model_card.md").write_text(model_card, encoding="utf-8")
    print(json.dumps({"selected_model": selected, "threshold": threshold_info["threshold"], "held_out_test": test_metrics, "output": str(args.output_dir)}, indent=2))


if __name__ == "__main__":
    main()
