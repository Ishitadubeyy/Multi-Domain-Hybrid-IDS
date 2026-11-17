# Multi-Domain Hybrid IDS

This repository implements a modular intrusion detection system designed around six detection domains:

- Network security
- Database and application security
- Host and endpoint security
- Authentication and identity security
- DNS security
- IoT security

The project preserves the legacy network model and provides a Wazuh-oriented JSONL alert pipeline. Wazuh is the intended user-facing monitoring platform; this repository does not add a website or dashboard.

## Repository structure

- `src/multi_domain_ids/ensemble.py` – legacy-inspired soft-voting hybrid network ensemble
- `src/multi_domain_ids/domains.py` – domain-specific detection pipelines
- `src/multi_domain_ids/dataset_loaders.py` – schema-specific dataset readers and preprocessing
- `dataset_manifest.json` – inspected source paths, schemas, labels, domains, and status
- `docs/DATASET_INVENTORY.md` – recursively discovered Downloads datasets and processing limits
- `docs/MODEL_TRAINING_AND_EVALUATION.md` – existing artifact contracts, measured metrics, and limits
- `docs/THREAT_INTELLIGENCE.md` – provider configuration, privacy guard, and verification limits
- `docs/WAZUH_DEPLOYMENT_AND_VALIDATION.md` – local config checks and the blocked end-to-end steps
- `src/multi_domain_ids/threat_intel.py` – deterministic threat intelligence scoring
- `src/multi_domain_ids/threat_intelligence/` – preserved AbuseIPDB, VirusTotal, OTX, and OpenCTI providers, IOC matching, caching, and reputation assessment
- `src/multi_domain_ids/alert_pipeline.py` – normalized alert records, optional TI enrichment, correlation, and JSONL output
- `src/multi_domain_ids/service.py` – inference-to-alert integration for the real network model and actual-data SQLi model
- `wazuh/` – example JSON decoder, rules, and agent JSONL collection configuration
- `docs/BEGINNER_GUIDE.md` – setup, model training, provider configuration, and Wazuh handoff
- `src/multi_domain_ids/cli.py` – training and evaluation entry points
- `src/multi_domain_ids/auth_processing.py` – resumable streaming aggregation for LANL authentication data
- `tests/test_ids.py` and `tests/test_dataset_loaders.py` – core and dataset-loader tests

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
- The legacy network model is not retrained.
- No benchmark claims are introduced beyond measured outputs from the local data/evaluation.
- The host, identity, DNS, and IoT production detector/model acceptance remains incomplete.

## Quick start

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m pytest
python -m multi_domain_ids.cli train-demo
```

`train-demo` is explicitly synthetic/demo behavior. Train the SQLi model using the actual combined CSV with:

```powershell
python -m multi_domain_ids.cli train-sqli `
  --dataset "C:\path\to\Normal &Malicious SQLi.csv" `
  --model-out "models\sqli_model_candidate.joblib"
```

The evaluator uses a group split by exact feature vector and removes vectors with contradictory labels before fitting. It writes a new local artifact; training refuses to replace an existing model unless `--overwrite` is explicitly supplied. Existing models and `*.joblib` artifacts are ignored by Git.

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

## Alert and Wazuh integration

`MultiDomainDetectionService` uses the saved network model's own threshold and can use a locally trained SQLi model for the dataset's 26 numeric feature columns. `AlertProcessor` normalizes model outputs, optionally enriches source/destination IPs using the preserved TI providers, creates deterministic explanations and evidence-based severity, correlates suspicious events sharing an entity, and appends JSONL records through `JsonlAlertSink`.

The SQLi dataset's raw-query feature definitions could not all be verified from source data, so SQLi inference requires the original 26-feature schema; no guessed raw-query feature extractor is included. Only the network and SQLi paths have actual trained models. Other domain pipelines are demo-only.

The local SQLi evaluation used a 20% `GroupShuffleSplit` holdout by exact feature vector. It excluded 136 rows from five feature-vector groups with conflicting labels, leaving 51,106 training rows and 12,930 test rows. Measured on that split: accuracy 0.998685, precision 0.998031, recall 0.999737, F1 0.998883, ROC AUC 0.999984, and average precision 0.999988; confusion matrix (Normal, Malicious) was `[[5309, 15], [2, 7604]]`. These are dataset-specific holdout results, not evidence of real-world generalization. The model artifact is local at `models/sqli_model.joblib` and ignored by Git; evaluation details are in [dataset_manifest.json](dataset_manifest.json).

See [docs/BEGINNER_GUIDE.md](docs/BEGINNER_GUIDE.md) for environment-variable setup, the JSONL event contract, and Wazuh agent/manager configuration steps. Example files are in [wazuh/](wazuh/). The Windows agent service is running, but its protected configuration could not be read and no connection to the manager ports was observed; decoder field extraction, rule matches, and end-to-end delivery remain unverified. A successful JSONL write is not evidence that Wazuh received the event.

The full LANL auth stream can be processed without extracting it:

```powershell
python -m multi_domain_ids.cli dataset-inventory
python -m multi_domain_ids.cli process-auth `
  --dataset "C:\Users\ISHITA DUBEY\Downloads\auth.txt.gz" `
  --redteam "C:\Users\ISHITA DUBEY\Downloads\redteam.txt.gz" `
  --output-dir "D:\projects\Multi-Domain-Hybrid-IDS\artifacts"
```

The command uses chunked reads, a restart checkpoint, and compact aggregate
outputs. Dataset paths and output location can be overridden with environment
variables documented in [`.env.example`](.env.example); that template is not
loaded automatically.

Threat-intelligence keys are read from environment variables (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `OPENCTI_URL`, and `OPENCTI_API_KEY`). Do not put keys in source code, alert records, or Wazuh configuration. Enable live lookups with `THREAT_INTEL_ENABLED=true`; provider enable flags and TTL/timeout options are documented in the beginner guide.

## Dataset guidance

- See [docs/DATASET_INVENTORY.md](docs/DATASET_INVENTORY.md) and [dataset_manifest.json](dataset_manifest.json) for the recursive Downloads inventory, exact source paths, schemas, label distributions, and processing status.
- `load_cicids2017_csv` selects only the legacy model's ordered 17 features and rejects labels outside the CICIDS2017 label set. The located `train_sample.csv` has 200,000 rows, only BENIGN/DDoS labels, and three missing `Flow Bytes/s` values; the loader preserves those values as missing rather than silently replacing them with zero. The full CICIDS2017 corpus was not found.
- The Downloads `train_sample.csv` matches the tracked sample in the old project after line-ending normalization. This establishes local sample lineage, not its original official CICIDS source.
- `load_sqli_csv` reads the combined SQLi file using its own 26 numeric columns, accepts only the observed Normal/Malicious labels, and keeps query text separate from model features. The audited file has 64,172 rows and no missing or non-numeric feature values.
- `iter_ton_iot_csv` reads one ToN-IoT CSV at a time in chunks. Each file retains its own columns; network, IoT, and Linux tables are never merged into one feature schema. The loader excludes `label` and `type`, validates binary labels, checks known type values, and rejects label/type disagreements.
- `iter_lanl_chunks` validates the positional auth, proc, DNS, flows, and redteam schemas against local sample records and maps the documented `?`/blank missing-value markers to nulls. `process-auth` streams `auth.txt.gz`, checkpoints aggregate counts, logs wrong-width rows, and can associate events with red-team annotations using exact user/computer keys and a bounded time window. A full stream must complete before full-file integrity or row counts are claimed.
- All 20 available processed ToN-IoT CSV members inside `OneDrive_2026-11-13.zip` passed byte-size and CRC32 checks against their ZIP data descriptors; the strict loader also matched every member's row, label, and type counts to the manifest. The archive itself has no standard ZIP end-of-central-directory record, Python's `zipfile` rejects it, and Windows `tar.exe` reports a truncated input while scanning it. Thus the verified CSV members are a usable, incomplete subset, not proof that every archive entry is intact.
- Training readiness: SQLi has a measured local holdout model for the 26 numeric feature schema only; the verified ToN-IoT members are conditional candidates that must remain schema-separated; the CICIDS sample is not a substitute for the full dataset and has missing feature values; LANL flows/DNS have no labels, redteam is event annotations only, auth processing is available but a full run must be separately recorded, and no production host/identity/DNS/IoT model is claimed.
- Loaders only parse and preprocess the available datasets; they do not train models or generate synthetic training data. Large datasets and model artifacts remain outside Git.
- The copied provider implementation remains isolated from the old project. Its original failure-isolation and cache behavior are preserved; tests use mocked HTTP responses only.

### Dataset loader example

```python
from multi_domain_ids.dataset_loaders import (
    iter_lanl_chunks,
    iter_ton_iot_csv,
    load_cicids2017_csv,
    load_sqli_csv,
)

cicids = load_cicids2017_csv(r"C:\path\to\train_sample.csv")
sqli = load_sqli_csv(r"C:\path\to\Normal &Malicious SQLi.csv")
for chunk in iter_ton_iot_csv(r"C:\path\to\Network_dataset_1.csv"):
    print(chunk.features.shape, chunk.labels.value_counts().to_dict())
for chunk in iter_lanl_chunks("dns", r"C:\path\to\dns.txt.gz"):
    print(chunk.shape)
```

The CSV and gzip readers use pandas (already required) and Python's standard library. The preserved live threat-intelligence providers use the declared `requests` dependency.

## Notes

This is a production-style starter implementation rather than a claim of benchmark parity with the original pipeline on the full CICIDS2017 corpus. The full evaluation requires the downloaded datasets and a machine with enough memory to train the network ensemble over those data volumes.
