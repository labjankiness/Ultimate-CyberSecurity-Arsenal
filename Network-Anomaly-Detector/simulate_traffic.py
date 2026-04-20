"""
Network traffic simulator for the Anomaly Detector.

Generates realistic network flow records with injected anomalies
for testing and demo purposes. No root/admin privileges required.

Usage:
    python simulate_traffic.py                    # Default: 1000 normal + 80 anomalous
    python simulate_traffic.py --normal 2000 --anomalies 100
    python simulate_traffic.py --output flows.csv --format csv
"""

import argparse
import json
import csv
import random
import time
from datetime import datetime, timedelta
from typing import Optional


# Internal network hosts
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]

# Common external IPs (web, DNS, email)
EXTERNAL_WEB = [
    "142.250.80.46", "104.244.42.65", "151.101.1.140", "13.107.42.14",
    "23.185.0.4", "52.84.150.11", "172.217.14.78", "31.13.65.36",
    "199.232.69.194", "93.184.216.34",
]
EXTERNAL_DNS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222"]
EXTERNAL_EMAIL = ["74.125.195.108", "52.97.128.50"]

# Suspicious external IPs (for anomalies)
C2_SERVERS = ["185.220.101.99", "45.33.32.200", "91.215.85.99"]
EXFIL_TARGETS = ["103.224.182.99", "157.245.33.99"]


def _random_timestamp(base: datetime, hours_range: int = 24) -> str:
    """Generate a random timestamp within a range."""
    offset = timedelta(seconds=random.randint(0, hours_range * 3600))
    return (base + offset).strftime("%Y-%m-%d %H:%M:%S")


def _gen_web_flow(base_time: datetime) -> dict:
    """Generate a normal web browsing flow."""
    src = random.choice(INTERNAL_IPS)
    return {
        "timestamp": _random_timestamp(base_time),
        "src_ip": src,
        "dst_ip": random.choice(EXTERNAL_WEB),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([80, 443, 443, 443, 8080]),
        "protocol": "TCP",
        "bytes_sent": random.randint(200, 5000),
        "bytes_received": random.randint(1000, 50000),
        "duration": round(random.uniform(0.1, 5.0), 2),
        "packets": random.randint(5, 50),
        "flags": "SYN,ACK,FIN",
        "label": "normal",
        "anomaly_type": None,
    }


def _gen_dns_flow(base_time: datetime) -> dict:
    """Generate a normal DNS query flow."""
    return {
        "timestamp": _random_timestamp(base_time),
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(EXTERNAL_DNS),
        "src_port": random.randint(49152, 65535),
        "dst_port": 53,
        "protocol": "UDP",
        "bytes_sent": random.randint(40, 120),
        "bytes_received": random.randint(60, 300),
        "duration": round(random.uniform(0.001, 0.1), 4),
        "packets": random.randint(1, 4),
        "flags": "",
        "label": "normal",
        "anomaly_type": None,
    }


def _gen_email_flow(base_time: datetime) -> dict:
    """Generate a normal email flow."""
    return {
        "timestamp": _random_timestamp(base_time),
        "src_ip": random.choice(INTERNAL_IPS[:5]),
        "dst_ip": random.choice(EXTERNAL_EMAIL),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([25, 465, 587, 993]),
        "protocol": "TCP",
        "bytes_sent": random.randint(500, 10000),
        "bytes_received": random.randint(200, 5000),
        "duration": round(random.uniform(0.5, 10.0), 2),
        "packets": random.randint(10, 40),
        "flags": "SYN,ACK,FIN",
        "label": "normal",
        "anomaly_type": None,
    }


def _gen_internal_flow(base_time: datetime) -> dict:
    """Generate normal internal network communication."""
    src = random.choice(INTERNAL_IPS)
    dst = random.choice([ip for ip in INTERNAL_IPS if ip != src])
    return {
        "timestamp": _random_timestamp(base_time),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([22, 445, 3389, 5432, 3306, 8080]),
        "protocol": "TCP",
        "bytes_sent": random.randint(100, 3000),
        "bytes_received": random.randint(100, 3000),
        "duration": round(random.uniform(0.05, 2.0), 2),
        "packets": random.randint(3, 20),
        "flags": "SYN,ACK,FIN",
        "label": "normal",
        "anomaly_type": None,
    }


def _gen_port_scan(base_time: datetime) -> list[dict]:
    """Generate a port scan anomaly (rapid connections to many ports)."""
    src = random.choice(INTERNAL_IPS)
    target = random.choice(EXTERNAL_WEB)
    ts = base_time + timedelta(seconds=random.randint(0, 86400))
    flows = []
    for port in random.sample(range(1, 1025), random.randint(25, 50)):
        flows.append({
            "timestamp": (ts + timedelta(milliseconds=random.randint(10, 500))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": target,
            "src_port": random.randint(49152, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(0, 60),
            "duration": round(random.uniform(0.001, 0.05), 4),
            "packets": random.randint(1, 3),
            "flags": "SYN",
            "label": "anomaly",
            "anomaly_type": "port_scan",
        })
        ts += timedelta(milliseconds=random.randint(50, 200))
    return flows


def _gen_data_exfiltration(base_time: datetime) -> list[dict]:
    """Generate data exfiltration anomaly (large outbound at odd hours)."""
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXFIL_TARGETS)
    # Odd hours: 1-5 AM
    ts = base_time.replace(hour=random.randint(1, 4), minute=random.randint(0, 59))
    flows = []
    for _ in range(random.randint(5, 10)):
        flows.append({
            "timestamp": (ts + timedelta(seconds=random.randint(0, 300))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([443, 8443, 4443]),
            "protocol": "TCP",
            "bytes_sent": random.randint(500000, 5000000),  # 500KB-5MB per flow
            "bytes_received": random.randint(100, 1000),
            "duration": round(random.uniform(10.0, 120.0), 2),
            "packets": random.randint(500, 5000),
            "flags": "SYN,ACK,PSH,FIN",
            "label": "anomaly",
            "anomaly_type": "data_exfiltration",
        })
        ts += timedelta(seconds=random.randint(30, 120))
    return flows


def _gen_c2_beaconing(base_time: datetime) -> list[dict]:
    """Generate C2 beaconing anomaly (regular interval connections)."""
    src = random.choice(INTERNAL_IPS)
    c2 = random.choice(C2_SERVERS)
    ts = base_time + timedelta(hours=random.randint(0, 12))
    interval = random.choice([30, 60, 120, 300])  # seconds
    flows = []
    for _ in range(random.randint(10, 20)):
        jitter = random.randint(-2, 2)
        flows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": c2,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([443, 8443, 4444]),
            "protocol": "TCP",
            "bytes_sent": random.randint(50, 200),
            "bytes_received": random.randint(50, 500),
            "duration": round(random.uniform(0.1, 1.0), 2),
            "packets": random.randint(2, 6),
            "flags": "SYN,ACK,FIN",
            "label": "anomaly",
            "anomaly_type": "c2_beaconing",
        })
        ts += timedelta(seconds=interval + jitter)
    return flows


def _gen_dns_tunneling(base_time: datetime) -> list[dict]:
    """Generate DNS tunneling anomaly (large/frequent DNS queries)."""
    src = random.choice(INTERNAL_IPS)
    ts = base_time + timedelta(hours=random.randint(0, 20))
    flows = []
    for _ in range(random.randint(15, 25)):
        flows.append({
            "timestamp": (ts + timedelta(seconds=random.randint(1, 10))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": random.choice(EXTERNAL_DNS),
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "protocol": "UDP",
            "bytes_sent": random.randint(200, 500),   # Abnormally large DNS queries
            "bytes_received": random.randint(300, 800),
            "duration": round(random.uniform(0.01, 0.1), 4),
            "packets": random.randint(2, 6),
            "flags": "",
            "label": "anomaly",
            "anomaly_type": "dns_tunneling",
        })
        ts += timedelta(seconds=random.randint(2, 15))
    return flows


def _gen_lateral_movement(base_time: datetime) -> list[dict]:
    """Generate lateral movement anomaly (one host connecting to many internal hosts)."""
    src = random.choice(INTERNAL_IPS)
    targets = [ip for ip in INTERNAL_IPS if ip != src]
    random.shuffle(targets)
    ts = base_time + timedelta(hours=random.randint(0, 20))
    flows = []
    for dst in targets[:random.randint(10, 20)]:
        flows.append({
            "timestamp": (ts + timedelta(seconds=random.randint(1, 30))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([22, 445, 3389]),
            "protocol": "TCP",
            "bytes_sent": random.randint(100, 2000),
            "bytes_received": random.randint(100, 2000),
            "duration": round(random.uniform(0.1, 5.0), 2),
            "packets": random.randint(5, 20),
            "flags": "SYN,ACK,FIN",
            "label": "anomaly",
            "anomaly_type": "lateral_movement",
        })
        ts += timedelta(seconds=random.randint(5, 60))
    return flows


def generate_traffic(
    normal_count: int = 1000,
    anomaly_sets: int = 4,
) -> list[dict]:
    """Generate a mixed dataset of normal and anomalous traffic.

    Args:
        normal_count: Number of normal flows.
        anomaly_sets: Number of each anomaly type to inject.

    Returns:
        List of flow dicts sorted by timestamp.
    """
    base_time = datetime.now() - timedelta(hours=24)
    flows: list[dict] = []

    # Normal traffic (weighted by type)
    generators = [
        (_gen_web_flow, 0.45),
        (_gen_dns_flow, 0.25),
        (_gen_internal_flow, 0.20),
        (_gen_email_flow, 0.10),
    ]
    for _ in range(normal_count):
        r = random.random()
        cumulative = 0.0
        for gen, weight in generators:
            cumulative += weight
            if r <= cumulative:
                flows.append(gen(base_time))
                break

    # Anomalous traffic
    anomaly_generators = [
        _gen_port_scan,
        _gen_data_exfiltration,
        _gen_c2_beaconing,
        _gen_dns_tunneling,
        _gen_lateral_movement,
    ]
    for gen in anomaly_generators:
        for _ in range(anomaly_sets):
            flows.extend(gen(base_time))

    flows.sort(key=lambda f: f["timestamp"])
    return flows


def save_json(flows: list[dict], filepath: str) -> None:
    """Save flows to JSON file."""
    with open(filepath, "w") as f:
        json.dump(flows, f, indent=2)
    print(f"[+] Saved {len(flows)} flows to {filepath}")


def save_csv(flows: list[dict], filepath: str) -> None:
    """Save flows to CSV file."""
    if not flows:
        return
    fieldnames = list(flows[0].keys())
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flows)
    print(f"[+] Saved {len(flows)} flows to {filepath}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Network Traffic Simulator")
    parser.add_argument("--normal", type=int, default=1000, help="Normal flow count (default: 1000)")
    parser.add_argument("--anomalies", type=int, default=4, help="Anomaly sets per type (default: 4)")
    parser.add_argument("--output", "-o", default="flows.json", help="Output file (default: flows.json)")
    parser.add_argument("--format", choices=["json", "csv"], default=None, help="Output format (auto-detected from extension)")
    args = parser.parse_args()

    flows = generate_traffic(args.normal, args.anomalies)

    normal = sum(1 for f in flows if f["label"] == "normal")
    anomaly = sum(1 for f in flows if f["label"] == "anomaly")
    print(f"[*] Generated {len(flows)} flows: {normal} normal, {anomaly} anomalous")

    fmt = args.format or ("csv" if args.output.endswith(".csv") else "json")
    if fmt == "csv":
        save_csv(flows, args.output)
    else:
        save_json(flows, args.output)


if __name__ == "__main__":
    main()
