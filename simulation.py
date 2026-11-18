"""Replay existing labeled CSV data through the repository's IDS and alert pipeline.

This reuses the repository's trained network/SQLi models and AlertProcessor.
It writes JSONL events to the Windows path monitored by the Wazuh agent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from itertools import cycle
import os
from pathlib import Path
import signal
import sys
import time

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from multi_domain_ids.alert_pipeline import AlertProcessor, JsonlAlertSink
from multi_domain_ids.dataset_loaders import SQLI_FEATURE_COLUMNS
from multi_domain_ids.feature_extractor import CICIDS_FEATURES
from multi_domain_ids.domains import NetworkSecurityPipeline
from multi_domain_ids.service import MultiDomainDetectionService
from multi_domain_ids.sqli_model import load_sqli_model
from multi_domain_ids.threat_intelligence.factory import (
    build_threat_intelligence_service,
)


DEFAULT_MODEL = PROJECT_ROOT / "models" / "final_model.joblib"
DEFAULT_SQLI_MODEL = PROJECT_ROOT / "models" / "sqli_model.joblib"
DEFAULT_DATA = Path.home() / "Downloads" / "simulation_data.csv"
DEFAULT_OUTPUT = Path(r"C:\ProgramData\MultiDomainIDS\ids_alerts.jsonl")


SCENARIO_FILTERS = {
    "mixed": None,
    "portscan": ("portscan",),
    "ddos": ("ddos",),
    "bruteforce": (
        "ftp-patator",
        "ssh-patator",
        "brute force",
        "web attack - brute force",
    ),
    "dos": (
        "dos ",
        "dos hulk",
        "dos goldeneye",
        "dos slowloris",
        "dos slowhttptest",
    ),
    "attackburst": "__ATTACKS_ONLY__",
    "sqli": "__SQLI__",
}


def normalize_label(value):
    return str(value).strip().lower()


def find_label_column(columns):
    accepted = {"label", "class", "attack", "target", "type attack"}
    return next(
        (column for column in columns if normalize_label(column) in accepted),
        None,
    )


def repeat_frame(frame, limit):
    if frame.empty:
        return frame

    if limit is not None:
        if limit <= 0:
            return frame.head(0)
        if len(frame) >= limit:
            return frame.head(limit)

    source_rows = list(frame.itertuples(index=False, name=None))
    rows = []
    for row in cycle(source_rows):
        rows.append(row)
        if limit is not None and len(rows) >= limit:
            break

    return pd.DataFrame(rows, columns=frame.columns)


def load_demo_rows(data_path, scenario="mixed", limit=None):
    data_path = Path(data_path)
    if not data_path.is_file():
        raise FileNotFoundError(f"Dataset CSV was not found: {data_path}")

    frame = pd.read_csv(data_path)
    frame = frame.rename(
        columns={str(column): str(column).strip() for column in frame.columns}
    )

    if scenario not in SCENARIO_FILTERS:
        raise ValueError(f"Unknown scenario: {scenario}")

    label_column = find_label_column(frame.columns)

    if scenario == "sqli":
        if label_column is None:
            raise ValueError(
                "SQLi scenario requires a label column such as "
                "'Type Attack', 'Label', or 'target'."
            )
        filtered = frame

    elif label_column and SCENARIO_FILTERS[scenario] == "__ATTACKS_ONLY__":
        filtered = frame[
            ~frame[label_column]
            .astype(str)
            .str.strip()
            .str.upper()
            .isin({"BENIGN", "NORMAL"})
        ]
        if filtered.empty:
            raise ValueError(
                "The selected dataset contains no non-benign rows for attackburst."
            )

    elif label_column and SCENARIO_FILTERS[scenario]:
        labels = SCENARIO_FILTERS[scenario]
        filtered = frame[
            frame[label_column]
            .astype(str)
            .str.lower()
            .apply(lambda value: any(label in value for label in labels))
        ]
        if filtered.empty:
            raise ValueError(
                f"No rows matched scenario '{scenario}' in label column "
                f"'{label_column}'."
            )
    else:
        filtered = frame

    filtered = filtered.reset_index(drop=True)
    return repeat_frame(filtered, limit)


def get_ground_truth(row):
    label_column = find_label_column(row.index)
    if label_column is None:
        return "unknown"
    return str(row.get(label_column, "unknown"))


def infer_attack_type(row):
    label = get_ground_truth(row).strip().lower()

    if "portscan" in label or "scanning" in label or "port scan" in label:
        return "port_scan"
    if "patator" in label or "brute force" in label or "bruteforce" in label:
        return "brute_force_login"
    if "sql injection" in label or "sqli" in label or "malicious" in label:
        return "sql_injection"
    if "ddos" in label:
        return "ddos"
    if "dos " in label:
        return "denial_of_service"
    if "benign" in label or "normal" in label:
        return "benign"
    return "suspicious_network_activity"


def resolve_project_path(value):
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def print_banner(scenario, source_path, total_rows, delay, output_path):
    print("+--------------------------------------------------+")
    print("|             LIVE TRAFFIC SIMULATOR               |")
    print("+--------------------------------------------------+")
    print(f"Scenario : {scenario}")
    print(f"Source   : {source_path}")
    print(f"Flows    : {total_rows}")
    print(f"Delay    : {delay} seconds")
    print(f"Wazuh log: {output_path}")
    print("+--------------------------------------------------+")


def run_live_simulation(
    model_path,
    data_path,
    output_path,
    scenario="mixed",
    delay=0.5,
    limit=None,
    threshold=None,
    alerts_only=False,
    overwrite=False,
    target_alerts=None,
):
    model_path = resolve_project_path(model_path)
    data_path = Path(data_path).expanduser()
    output = Path(output_path)

    if not model_path.is_file():
        raise FileNotFoundError(f"Trained network model was not found: {model_path}")
    if delay < 0:
        raise ValueError("--delay cannot be negative.")
    if limit is not None and limit < 0:
        raise ValueError("--limit cannot be negative.")
    if target_alerts is not None and target_alerts <= 0:
        raise ValueError("--target-alerts must be greater than zero.")

    # Ensure the Wazuh agent's monitored directory exists before opening JSONL.
    output.parent.mkdir(parents=True, exist_ok=True)
    if overwrite and output.exists():
        output.unlink()

    processor = AlertProcessor(
        JsonlAlertSink(output),
        threat_intelligence=build_threat_intelligence_service(),
    )

    network = NetworkSecurityPipeline(
        model_path=str(model_path)
    ).load_pretrained_model()

    if threshold is not None:
        network.threshold = float(threshold)

    sqli = None
    sqli_path = DEFAULT_SQLI_MODEL
    if scenario == "sqli" and sqli_path.is_file():
        sqli = load_sqli_model(sqli_path)

    service = MultiDomainDetectionService(
        processor,
        network=network,
        sqli=sqli,
    )

    rows = load_demo_rows(data_path, scenario=scenario, limit=limit)

    if scenario == "sqli" and sqli is None:
        raise RuntimeError(
            "SQLi replay requires the existing model artifact: "
            f"{sqli_path}"
        )

    print_banner(scenario, data_path, len(rows), delay, output)
    print(f"[INFO] Network detector threshold: {network.threshold:.4f}")
    if scenario == "sqli":
        print(f"[INFO] SQLi detector threshold: {sqli.threshold:.4f}")
    print("[INFO] Every evaluated event is passed through the existing alert pipeline.")
    print("[INFO] JSONL output is the file monitored by the Windows Wazuh agent.")

    row_items = list(rows.iterrows())
    if not row_items:
        print("[WARN] No rows available for replay.")
        return

    max_iterations = target_alerts * 10 if target_alerts is not None else len(row_items)
    row_iterator = cycle(row_items) if target_alerts is not None else iter(row_items)

    suspicious_detections = 0
    evaluated_events = 0
    stop_requested = False

    def request_stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True
        print("\n[INFO] Stop requested; finishing the current event...")

    previous_handler = signal.signal(signal.SIGINT, request_stop)

    try:
        for index, (_, row) in enumerate(row_iterator, start=1):
            if stop_requested:
                break

            ground_truth = get_ground_truth(row)
            attack_type = infer_attack_type(row)

            event = {
                "event_id": f"simulation-{index}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_source": "simulation",
                "hostname": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME"),
                "simulation_scenario": scenario,
                "simulation_ground_truth": ground_truth,
                "attack_name": attack_type,
            }

            if "Destination Port" in row.index and pd.notna(row["Destination Port"]):
                event["destination_port"] = int(row["Destination Port"])

            if scenario == "sqli":
                missing = [
                    column
                    for column in SQLI_FEATURE_COLUMNS
                    if column not in row.index
                ]
                if missing:
                    raise RuntimeError(
                        f"SQLi replay is missing supported feature columns: {missing}"
                    )

                features = pd.DataFrame(
                    [[row[column] for column in SQLI_FEATURE_COLUMNS]],
                    columns=SQLI_FEATURE_COLUMNS,
                )
                records = service.detect_sqli_features(
                    event,
                    features,
                    evidence=[
                        {
                            "signal": "actual_sqli_feature_row",
                            "description": (
                                "Actual 26-feature SQLi dataset row; "
                                f"source label was {ground_truth}."
                            ),
                        }
                    ],
                )
            else:
                missing = [
                    column for column in CICIDS_FEATURES if column not in row.index
                ]
                if missing:
                    raise RuntimeError(
                        f"Network replay is missing supported model features: {missing}"
                    )

                features = pd.DataFrame(
                    [[row[column] for column in CICIDS_FEATURES]],
                    columns=CICIDS_FEATURES,
                )
                evidence = [
                    {
                        "signal": "network_model_features",
                        "description": (
                            "Event contains the 17 preserved CICIDS network "
                            "model features."
                        ),
                    }
                ]
                records = service.detect_network(event, features, evidence=evidence)

            evaluated_events += 1

            if not records:
                print(f"[WARN] FLOW #{index:03d}: detector returned no alert record.")
                continue

            record = records[0]
            predicted = record.get("model_prediction", "unknown")
            probability = record.get("attack_probability")
            confidence = record.get("confidence_score")
            severity = record.get("severity", "unknown")

            if predicted == "suspicious":
                suspicious_detections += 1

            # --alerts-only changes console output only. The existing service
            # still processes and writes all evaluated events to JSONL.
            if not alerts_only or predicted == "suspicious":
                print(f"[{time.strftime('%H:%M:%S')}] FLOW #{index:03d}")
                print(f"  Ground truth       : {ground_truth}")
                print(f"  Model prediction   : {predicted}")
                if probability is not None:
                    print(f"  Attack probability : {float(probability):.4f}")
                else:
                    print("  Attack probability : unavailable")
                if confidence is not None:
                    print(f"  Confidence         : {float(confidence):.4f}")
                else:
                    print("  Confidence         : unavailable")
                print(f"  Severity           : {severity}")
                print(f"  Wazuh JSONL        : {output}")

            if target_alerts is not None and suspicious_detections >= target_alerts:
                break

            if (
                target_alerts is not None
                and index >= max_iterations
                and suspicious_detections < target_alerts
            ):
                print(
                    f"[WARN] Reached {index} replayed rows with only "
                    f"{suspicious_detections} suspicious detections."
                )
                break

            if delay > 0:
                time.sleep(delay)

    finally:
        signal.signal(signal.SIGINT, previous_handler)

    print("\n========== SIMULATION SUMMARY ==========")
    print(f"Events evaluated       : {evaluated_events}")
    print(f"Suspicious detections  : {suspicious_detections}")
    print(f"JSONL output file      : {output}")
    if output.exists():
        print(f"JSONL file size        : {output.stat().st_size} bytes")
    print("========================================")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Replay labeled CSV data through the existing IDS and write "
            "JSONL events for Wazuh."
        )
    )
    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL),
        help="Path to the existing trained network model artifact.",
    )
    parser.add_argument(
        "--data",
        default=str(DEFAULT_DATA),
        help="Path to the labeled CICIDS or SQLi CSV.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=(
            "JSONL output file monitored by the Wazuh Windows agent "
            "(default: C:\\ProgramData\\MultiDomainIDS\\ids_alerts.jsonl)."
        ),
    )
    parser.add_argument(
        "--scenario",
        default="mixed",
        choices=sorted(SCENARIO_FILTERS),
        help="Dataset scenario to replay.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between flows in seconds.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional number of dataset rows to replay.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional override for the existing network model threshold.",
    )
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help=(
            "Print only suspicious detections to the console. "
            "All events are still processed and written to JSONL."
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Truncate the JSONL output file before starting.",
    )
    parser.add_argument(
        "--target-alerts",
        type=int,
        default=None,
        help="Stop after the requested number of suspicious detections.",
    )

    args = parser.parse_args()

    run_live_simulation(
        model_path=args.model,
        data_path=args.data,
        output_path=args.output,
        scenario=args.scenario,
        delay=args.delay,
        limit=args.limit,
        threshold=args.threshold,
        alerts_only=args.alerts_only,
        overwrite=args.overwrite,
        target_alerts=args.target_alerts,
    )


if __name__ == "__main__":
    main()
