# Sentivra MLRan ransomware model card

- Model: `LogisticRegression`
- Version: `mlran-ransomware-1.0.0`
- Features: 483 MLRan RFE behavioral features
- Train/test rows: 3905 / 975
- Threshold: 0.685108 (validation target recall 0.98)
- Group-held-out evaluation: 5-fold `StratifiedGroupKFold`, grouped by MLRan family label
- Explainability: available; see `shap_global.json` and `figures/shap_summary.png`

The complete measured results are in `metrics.json`. The test set is the supplied MLRan held-out split and was not used for training, tuning, or threshold selection. Dataset metrics do not transfer 1:1 to live hosts.
