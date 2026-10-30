# Ransomware integration phase 0

## Scope

This branch adds an opt-in ransomware behavioral capability without changing
existing detector inputs, outputs, thresholds, routes, or alert behavior when
`RANSOMWARE_MODEL_ENABLED=false` or the model artifact is unavailable.

The implementation will use MLRan's feature-selected behavioral data for
training and evaluation. RanDe-W11 is a methodology and schema reference only;
it contains no deployable pretrained model in the inspected repository.

## Baseline

Captured 2026-10-30 in the local test environment:

- Backend: `288 passed, 1 failed, 4 errors, 1 skipped`.
- The five existing network failures/errors occur while Scapy imports its Windows
  executable-discovery path because this worker environment has no `ProgramFiles`
  variable/Wireshark installation.
- Frontend: 8 Vitest tests passed; ESLint, TypeScript, and Next production build
  passed.
- API golden responses: [`docs/baseline/api/golden-responses.json`](baseline/api/golden-responses.json).

The golden responses were collected with a temporary test database and a
throwaway test OAuth client. No secret or local database state is included.

## Old versus current Cyber Defense Lab

The older lab implementation at commit `ae809c67` used a compact two-column
workspace: topology on the left, trusted scenario launcher on the right, followed
by selected execution evidence and history. The current local implementation
retains that structure while adding recorded timeline playback, target outcomes,
comparison cards, and report downloads. The restoration work will keep those
working features and tighten visual density only inside the lab module.

## Planned files

- `backend/app/core/config.py`: opt-in model settings only.
- `backend/app/detectors/ransomware_detector.py`: guarded model adapter.
- `backend/app/ransomware/`: feature schema, model loading, scoring, and safe
  behavioral feature conversion.
- `backend/app/api/ransomware.py`: additive predict/health/replay endpoints.
- `backend/app/main.py`: conditional detector registration.
- `backend/app/services/simulation.py`: trusted host-safe ransomware fixture only.
- `frontend/app/cyber-defense/*`: lab controls and evidence panels only.
- `scripts/train_ransomware_model.py`: reproducible training/evaluation command.
- `models/ransomware/mlran/`: generated model metadata/artifacts, with no dataset.
- `docs/RANSOMWARE_DETECTION.md` and `README.md`: measured results, limitations,
  safety design, and dataset citations.

No raw malware, credentials, downloaded datasets, or host-monitoring code will be
committed.
