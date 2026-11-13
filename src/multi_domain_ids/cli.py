from __future__ import annotations

import argparse
import json
from pathlib import Path

from .domains import MultiDomainIDS
from .threat_intel import ThreatIntelScorer


def _demo_record() -> dict:
    return {
        "network": {
            "Flow Duration": 120.0,
            "Total Fwd Packets": 32,
            "Total Backward Packets": 28,
            "Total Length of Fwd Packets": 5000.0,
            "Total Length of Bwd Packets": 6000.0,
            "Fwd Packet Length Max": 100.0,
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": 75.0,
            "Fwd Packet Length Std": 15.0,
            "Bwd Packet Length Max": 90.0,
            "Bwd Packet Length Min": 30.0,
            "Bwd Packet Length Mean": 65.0,
            "Bwd Packet Length Std": 12.0,
            "Flow Bytes/s": 120000.0,
            "Flow Packets/s": 1500.0,
            "Packet Length Mean": 80.0,
            "Packet Length Std": 18.0,
        },
        "sql": "SELECT * FROM users WHERE username='admin' OR 1=1",
        "host": {
            "cpu_usage": 0.91,
            "memory_usage": 0.87,
            "disk_usage": 0.72,
            "network_connections": 190,
            "parent_child_ratio": 2.2,
            "process_entropy": 0.92,
            "privilege_escalation": 1,
            "suspicious_process_count": 9,
        },
        "identity": {
            "failed_logins": 12,
            "successful_logins": 1,
            "new_device_logins": 3,
            "privilege_escalation": 1,
            "user_anomaly_score": 0.93,
            "time_window_lateral_movement": 2,
        },
        "dns": {
            "query_length": 92,
            "label_count": 4,
            "numeric_ratio": 0.7,
            "entropy_score": 0.95,
            "avg_subdomain_depth": 4.4,
            "is_malicious_tld": 1,
            "is_high_entropy": 1,
            "suspicious_dns_pattern": 1,
        },
        "source_ip": "203.0.113.10",
        "destination_ip": "198.51.100.54",
        "protocol": "TCP",
        "severity": "high",
        "suspicious": True,
    }


def train_demo() -> MultiDomainIDS:
    ids = MultiDomainIDS()
    ids.fit_demo()
    return ids


def evaluate_demo() -> dict:
    ids = train_demo()
    alert = ids.generate_alert(_demo_record())
    scorer = ThreatIntelScorer()
    enriched = scorer.assess_alert(alert)
    payload = {
        "alert": alert,
        "intel": enriched,
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Domain Hybrid IDS CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("train-demo", help="Train a demo model across the five domains")
    subparsers.add_parser("evaluate-demo", help="Run a synthetic alert evaluation")

    args = parser.parse_args()

    if args.command == "train-demo":
        ids = train_demo()
        print(json.dumps(ids.predict(_demo_record()), indent=2))
    elif args.command == "evaluate-demo":
        result = evaluate_demo()
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
