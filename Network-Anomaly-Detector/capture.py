"""
Network flow capture and parsing.

Provides flow ingestion from JSON/CSV files and optional live packet
capture using scapy (requires root). For demo purposes, use
simulate_traffic.py instead of live capture.

Usage:
    from capture import load_flows
    flows = load_flows("flows.json")
"""

import json
import csv
from typing import Optional


def load_flows(filepath: str) -> list[dict]:
    """Load flow records from a JSON or CSV file.

    Args:
        filepath: Path to flows.json or flows.csv.

    Returns:
        List of flow dicts.
    """
    if filepath.endswith(".csv"):
        return _load_csv(filepath)
    else:
        return _load_json(filepath)


def _load_json(filepath: str) -> list[dict]:
    """Load flows from a JSON file."""
    with open(filepath, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return []


def _load_csv(filepath: str) -> list[dict]:
    """Load flows from a CSV file."""
    flows = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert numeric fields
            for key in ["src_port", "dst_port", "bytes_sent", "bytes_received", "packets"]:
                if key in row and row[key]:
                    try:
                        row[key] = int(row[key])
                    except ValueError:
                        pass
            if "duration" in row and row["duration"]:
                try:
                    row["duration"] = float(row["duration"])
                except ValueError:
                    pass
            flows.append(row)
    return flows


def get_flow_summary(flows: list[dict]) -> dict:
    """Get summary statistics for a list of flows.

    Args:
        flows: List of flow dicts.

    Returns:
        Summary dict with counts, unique IPs, protocols, etc.
    """
    src_ips = set()
    dst_ips = set()
    protocols = set()
    total_bytes = 0
    labels = {"normal": 0, "anomaly": 0}

    for f in flows:
        src_ips.add(f.get("src_ip", ""))
        dst_ips.add(f.get("dst_ip", ""))
        protocols.add(f.get("protocol", ""))
        total_bytes += f.get("bytes_sent", 0) + f.get("bytes_received", 0)
        label = f.get("label", "normal")
        labels[label] = labels.get(label, 0) + 1

    return {
        "total_flows": len(flows),
        "unique_sources": len(src_ips),
        "unique_destinations": len(dst_ips),
        "protocols": sorted(protocols),
        "total_bytes": total_bytes,
        "normal_count": labels.get("normal", 0),
        "anomaly_count": labels.get("anomaly", 0),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        flows = load_flows(filepath)
        summary = get_flow_summary(flows)
        print(f"=== Flow Summary: {filepath} ===")
        for k, v in summary.items():
            print(f"  {k}: {v}")
    else:
        print("Usage: python capture.py <flows.json|flows.csv>")
