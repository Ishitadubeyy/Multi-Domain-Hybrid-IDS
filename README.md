# Multi-Domain Hybrid IDS

This repository implements a modular intrusion detection system designed around the five-domain architecture described in the project brief:

- Network security
- Database and application security
- Host and endpoint security
- Authentication and identity security
- DNS security

The project preserves the legacy hybrid ensemble from the earlier network IDS work and extends it with domain-aware pipelines, threat intelligence scoring, and SIEM-style alert generation.

## Repository structure

- `src/multi_domain_ids/ensemble.py` – legacy-inspired soft-voting hybrid network ensemble
- `src/multi_domain_ids/domains.py` – domain-specific detection pipelines
- `src/multi_domain_ids/threat_intel.py` – deterministic threat intelligence scoring
- `src/multi_domain_ids/cli.py` – training and evaluation entry points
- `tests/test_ids.py` – smoke tests that validate the core behavior

## Phase 1: Network IDS migration

This repository now includes the original, pre-trained network IDS artifact from the earlier project and uses it as the `NetworkSecurityPipeline` implementation.

The actual legacy artifact is loaded through the preserved compatibility loader at [src/multi_domain_ids/model_loader.py](src/multi_domain_ids/model_loader.py), which maps the legacy sklearn global required by the saved joblib file. The model is expected at `models/final_model.joblib` in this repository and can also fall back to the reference project location under `../Hybrid-Threat-detection-ids-main/models/final_model.joblib` if needed.

### Network model contract

- Model artifact: `models/final_model.joblib`
- Model type: `hybrid_voting_5ensemble_v3`
- Scaler: `RobustScaler`
- Feature ordering: exact 17-feature CICIDS schema preserved in the same order as the old project
- Threshold: preserved from the saved artifact (`0.21` in the original model)
- Loader: `src/multi_domain_ids/model_loader.py`
- Feature extractor: `src/multi_domain_ids/feature_extractor.py`
- Inference wrapper: `src/multi_domain_ids/domains.py` (`NetworkSecurityPipeline`)

### Important constraints

- The original project is left intact; the new repository consumes a copy of the trained artifact.
- No retraining is performed in Phase 1.
- No benchmark claims are introduced beyond the existing legacy artifact metadata.
- The remaining domain pipelines remain available, but this phase focuses only on the network domain integration.

## Quick start

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m pytest
python -m multi_domain_ids.cli train-demo
```

## Example usage

```python
from multi_domain_ids.domains import MultiDomainIDS

ids = MultiDomainIDS()
ids.fit_demo()
summary = ids.predict({
    "network": {"Flow Duration": 1.2, "Total Fwd Packets": 10, "Total Backward Packets": 5},
    "sql": "SELECT * FROM users WHERE username = 'admin' OR 1=1",
    "host": {"cpu_usage": 0.9, "memory_usage": 0.8},
    "identity": {"failed_logins": 5, "privilege_escalation": 1},
    "dns": {"query_length": 40, "is_malicious_tld": 1},
})
print(summary)
```

## Dataset guidance

- CICIDS2017 remains the baseline network dataset.
- ToN_IoT network, Linux and Windows telemetry should be used with domain-specific preprocessing and careful train/test isolation.
- LANL `auth`, `proc`, `flows`, and `dns` datasets should be evaluated by event type and context rather than treated as a single homogeneous table.
- SQL injection detection must use structured text features rather than network-flow columns.

## Notes

This is a production-style starter implementation rather than a claim of benchmark parity with the original pipeline on the full CICIDS2017 corpus. The full evaluation requires the downloaded datasets and a machine with enough memory to train the network ensemble over those data volumes.
