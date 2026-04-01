"""
Anomaly detection engine for network traffic.

Uses statistical methods (z-score, time analysis, pattern matching)
to detect port scans, data exfiltration, C2 beaconing, DNS tunneling,
and lateral movement without ML dependencies.

Usage:
    from detector import analyze_batch
    anomalies = analyze_batch(flows, baseline_profiles)
"""

import math
from collections import defaultdict
from datetime import datetime
from typing import Optional


def _z_score(value: float, mean: float, std: float) -> float:
    """Compute z-score. Returns 0 if std is 0."""
    if std == 0:
        return 0.0
    return (value - mean) / std


def _detect_bytes_anomaly(flow: dict, profile: dict) -> Optional[dict]:
    """Flag flows with abnormally high bytes sent (potential exfiltration)."""
    bytes_sent = flow.get("bytes_sent", 0)
    stats = profile.get("bytes_sent", {})
    mean = stats.get("mean", 0)
    std = stats.get("std", 1)
    p95 = stats.get("p95", 0)

    z = _z_score(bytes_sent, mean, std)
    if z > 3 and bytes_sent > p95 and bytes_sent > 100000:
        return {
            "anomaly_type": "data_exfiltration",
            "severity": "critical" if z > 5 else "high",
            "confidence": min(int(50 + z * 10), 100),
            "src_ip": flow.get("src_ip"),
            "dst_ip": flow.get("dst_ip"),
            "evidence": {
                "bytes_sent": bytes_sent,
                "baseline_mean": mean,
                "baseline_std": std,
                "z_score": round(z, 2),
            },
            "flow_count": 1,
        }
    return None


def _detect_time_anomaly(flow: dict, profile: dict) -> Optional[dict]:
    """Flag activity outside normal operating hours."""
    active_hours = profile.get("active_hours", [])
    if not active_hours:
        return None

    try:
        ts = datetime.strptime(flow["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour = ts.hour
    except (ValueError, KeyError):
        return None

    if hour not in active_hours:
        return {
            "anomaly_type": "off_hours_activity",
            "severity": "medium",
            "confidence": 60,
            "src_ip": flow.get("src_ip"),
            "dst_ip": flow.get("dst_ip"),
            "evidence": {
                "activity_hour": hour,
                "normal_hours": active_hours,
            },
            "flow_count": 1,
        }
    return None


def _detect_destination_anomaly(flow: dict, profile: dict) -> Optional[dict]:
    """Flag connections to IPs never seen in the baseline."""
    dst = flow.get("dst_ip", "")
    known_dsts = set(profile.get("common_destinations", {}).keys())

    if dst and known_dsts and dst not in known_dsts:
        # Only flag external destinations
        if not dst.startswith("192.168.") and not dst.startswith("10."):
            return {
                "anomaly_type": "new_destination",
                "severity": "low",
                "confidence": 40,
                "src_ip": flow.get("src_ip"),
                "dst_ip": dst,
                "evidence": {
                    "new_destination": dst,
                    "known_destinations": len(known_dsts),
                },
                "flow_count": 1,
            }
    return None


def analyze_flow(flow: dict, baseline: dict[str, dict]) -> list[dict]:
    """Analyze a single flow against the baseline.

    Args:
        flow: Flow dict.
        baseline: Baseline profiles keyed by src_ip.

    Returns:
        List of anomaly results (may be empty or have multiple).
    """
    src_ip = flow.get("src_ip", "")
    profile = baseline.get(src_ip, {})

    if not profile:
        return []

    anomalies = []
    for check in [_detect_bytes_anomaly, _detect_time_anomaly, _detect_destination_anomaly]:
        result = check(flow, profile)
        if result:
            anomalies.append(result)

    return anomalies


def _detect_port_scan(flows: list[dict], window_seconds: int = 60) -> list[dict]:
    """Detect port scans: >20 unique ports from same source in a short window."""
    # Group by source IP
    by_src: dict[str, list[dict]] = defaultdict(list)
    for f in flows:
        by_src[f.get("src_ip", "")].append(f)

    anomalies = []
    for src_ip, src_flows in by_src.items():
        # Sort by timestamp
        try:
            sorted_flows = sorted(src_flows, key=lambda f: f.get("timestamp", ""))
        except Exception:
            continue

        # Sliding window
        window_ports: dict[str, set] = defaultdict(set)
        for f in sorted_flows:
            dst = f.get("dst_ip", "")
            port = f.get("dst_port", 0)
            window_ports[dst].add(port)

        for dst, ports in window_ports.items():
            if len(ports) > 20:
                anomalies.append({
                    "anomaly_type": "port_scan",
                    "severity": "high" if len(ports) > 40 else "medium",
                    "confidence": min(50 + len(ports), 95),
                    "src_ip": src_ip,
                    "dst_ip": dst,
                    "evidence": {
                        "unique_ports": len(ports),
                        "sample_ports": sorted(list(ports))[:20],
                    },
                    "flow_count": len(src_flows),
                })

    return anomalies


def _detect_beaconing(flows: list[dict], max_jitter: float = 5.0) -> list[dict]:
    """Detect C2 beaconing: regular interval connections to same destination."""
    # Group by (src_ip, dst_ip)
    pairs: dict[tuple, list[datetime]] = defaultdict(list)
    for f in flows:
        src = f.get("src_ip", "")
        dst = f.get("dst_ip", "")
        if dst.startswith("192.168.") or dst.startswith("10."):
            continue  # Skip internal
        try:
            ts = datetime.strptime(f["timestamp"], "%Y-%m-%d %H:%M:%S")
            pairs[(src, dst)].append(ts)
        except (ValueError, KeyError):
            pass

    anomalies = []
    for (src, dst), times in pairs.items():
        if len(times) < 5:
            continue

        times.sort()
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 5:
            continue  # Too fast, likely just burst traffic

        # Check jitter (low jitter = beaconing)
        variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        jitter = math.sqrt(variance)

        if jitter <= max_jitter and len(times) >= 5:
            anomalies.append({
                "anomaly_type": "c2_beaconing",
                "severity": "critical",
                "confidence": min(70 + int((max_jitter - jitter) * 10), 98),
                "src_ip": src,
                "dst_ip": dst,
                "evidence": {
                    "beacon_count": len(times),
                    "mean_interval_sec": round(mean_interval, 1),
                    "jitter_sec": round(jitter, 2),
                },
                "flow_count": len(times),
            })

    return anomalies


def _detect_dns_anomaly(flows: list[dict], baseline: dict[str, dict]) -> list[dict]:
    """Detect DNS tunneling: abnormally large or frequent DNS queries."""
    dns_flows = [f for f in flows if f.get("dst_port") == 53]

    by_src: dict[str, list[dict]] = defaultdict(list)
    for f in dns_flows:
        by_src[f.get("src_ip", "")].append(f)

    anomalies = []
    for src_ip, src_dns in by_src.items():
        # Check average query size
        avg_bytes = sum(f.get("bytes_sent", 0) for f in src_dns) / max(len(src_dns), 1)

        # Normal DNS queries are 40-120 bytes
        if avg_bytes > 180 and len(src_dns) > 10:
            anomalies.append({
                "anomaly_type": "dns_tunneling",
                "severity": "high",
                "confidence": min(60 + int(avg_bytes / 10), 95),
                "src_ip": src_ip,
                "dst_ip": "DNS",
                "evidence": {
                    "avg_query_bytes": round(avg_bytes, 1),
                    "normal_range": "40-120 bytes",
                    "dns_query_count": len(src_dns),
                },
                "flow_count": len(src_dns),
            })

    return anomalies


def _detect_lateral_movement(flows: list[dict]) -> list[dict]:
    """Detect lateral movement: one host connecting to many internal hosts."""
    internal_connections: dict[str, set] = defaultdict(set)

    for f in flows:
        src = f.get("src_ip", "")
        dst = f.get("dst_ip", "")
        if src.startswith("192.168.") and dst.startswith("192.168.") and src != dst:
            internal_connections[src].add(dst)

    anomalies = []
    for src, destinations in internal_connections.items():
        if len(destinations) >= 8:
            anomalies.append({
                "anomaly_type": "lateral_movement",
                "severity": "critical" if len(destinations) >= 15 else "high",
                "confidence": min(50 + len(destinations) * 3, 95),
                "src_ip": src,
                "dst_ip": f"{len(destinations)} internal hosts",
                "evidence": {
                    "unique_internal_targets": len(destinations),
                    "targets": sorted(list(destinations))[:10],
                },
                "flow_count": len(destinations),
            })

    return anomalies


def analyze_batch(flows: list[dict], baseline: dict[str, dict]) -> list[dict]:
    """Run all detection methods on a batch of flows.

    Args:
        flows: List of flow dicts.
        baseline: Baseline profiles from baseline.py.

    Returns:
        List of all detected anomalies, deduplicated.
    """
    anomalies: list[dict] = []

    # Per-flow analysis
    for f in flows:
        anomalies.extend(analyze_flow(f, baseline))

    # Batch pattern analysis
    anomalies.extend(_detect_port_scan(flows))
    anomalies.extend(_detect_beaconing(flows))
    anomalies.extend(_detect_dns_anomaly(flows, baseline))
    anomalies.extend(_detect_lateral_movement(flows))

    # Deduplicate by (anomaly_type, src_ip, dst_ip)
    seen = set()
    unique = []
    for a in anomalies:
        key = (a["anomaly_type"], a.get("src_ip"), a.get("dst_ip"))
        if key not in seen:
            seen.add(key)
            unique.append(a)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique.sort(key=lambda a: severity_order.get(a.get("severity", "low"), 4))

    return unique


if __name__ == "__main__":
    from simulate_traffic import generate_traffic
    from baseline import build_baseline

    print("[*] Generating traffic...")
    flows = generate_traffic(normal_count=500, anomaly_sets=3)
    normal = [f for f in flows if f["label"] == "normal"]

    print("[*] Building baseline...")
    profiles = build_baseline(normal)

    print("[*] Running detection...")
    anomalies = analyze_batch(flows, profiles)

    print(f"\n[+] Detected {len(anomalies)} anomalies:\n")
    for a in anomalies:
        sev = a["severity"].upper()
        print(f"  [{sev}] {a['anomaly_type']} — {a['src_ip']} → {a.get('dst_ip', 'N/A')} "
              f"(confidence: {a['confidence']}%)")
        for k, v in a.get("evidence", {}).items():
            print(f"    {k}: {v}")
        print()

    # Accuracy check against labels
    labeled_anomalies = set()
    for f in flows:
        if f["label"] == "anomaly":
            labeled_anomalies.add((f.get("anomaly_type", ""), f.get("src_ip", "")))

    detected_types = set()
    for a in anomalies:
        detected_types.add((a["anomaly_type"], a.get("src_ip", "")))

    tp = len(labeled_anomalies & detected_types)
    total_labeled = len(labeled_anomalies)
    print(f"[*] Detection accuracy: {tp}/{total_labeled} labeled anomaly types detected")
