"""
Behavioral baseline profiling for network traffic.

Builds statistical profiles of "normal" behavior for each internal IP
using rolling statistics: mean, standard deviation, and percentiles.

Usage:
    from baseline import build_baseline, update_baseline
    profile = build_baseline(flows)
"""

import math
from collections import defaultdict
from datetime import datetime
from typing import Optional


def _stats(values: list[float]) -> dict:
    """Compute basic statistics for a list of values."""
    if not values:
        return {"mean": 0.0, "std": 0.0, "p50": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0, "count": 0}

    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / max(n - 1, 1)
    std = math.sqrt(variance)

    sorted_vals = sorted(values)
    p50 = sorted_vals[int(n * 0.50)]
    p95 = sorted_vals[min(int(n * 0.95), n - 1)]

    return {
        "mean": round(mean, 2),
        "std": round(std, 2),
        "p50": round(p50, 2),
        "p95": round(p95, 2),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "count": n,
    }


def build_baseline(flows: list[dict], window_hours: int = 24) -> dict[str, dict]:
    """Build behavioral profiles for each internal source IP.

    Args:
        flows: List of flow dicts (from simulate_traffic or capture).
        window_hours: Only consider flows within this window.

    Returns:
        Dict mapping src_ip to profile dict with: bytes_stats, duration_stats,
        conn_per_hour, common_destinations, common_ports, active_hours.
    """
    # Filter to window
    cutoff = None
    if window_hours:
        now = datetime.now()
        try:
            flow_times = []
            for f in flows:
                try:
                    flow_times.append(datetime.strptime(f["timestamp"], "%Y-%m-%d %H:%M:%S"))
                except (ValueError, KeyError):
                    pass
            if flow_times:
                latest = max(flow_times)
                from datetime import timedelta
                cutoff = latest - timedelta(hours=window_hours)
        except Exception:
            pass

    # Group by source IP
    ip_flows: dict[str, list[dict]] = defaultdict(list)
    for f in flows:
        if f.get("label") == "anomaly":
            continue  # Don't include known anomalies in baseline
        src = f.get("src_ip", "")
        if not src.startswith("192.168.") and not src.startswith("10."):
            continue  # Only profile internal hosts

        if cutoff:
            try:
                ts = datetime.strptime(f["timestamp"], "%Y-%m-%d %H:%M:%S")
                if ts < cutoff:
                    continue
            except (ValueError, KeyError):
                pass

        ip_flows[src].append(f)

    profiles: dict[str, dict] = {}

    for ip, ip_flow_list in ip_flows.items():
        bytes_sent = [f.get("bytes_sent", 0) for f in ip_flow_list]
        bytes_recv = [f.get("bytes_received", 0) for f in ip_flow_list]
        durations = [f.get("duration", 0) for f in ip_flow_list]

        # Common destinations
        dst_counts: dict[str, int] = defaultdict(int)
        port_counts: dict[int, int] = defaultdict(int)
        hours: dict[int, int] = defaultdict(int)

        for f in ip_flow_list:
            dst_counts[f.get("dst_ip", "")] += 1
            port_counts[f.get("dst_port", 0)] += 1
            try:
                ts = datetime.strptime(f["timestamp"], "%Y-%m-%d %H:%M:%S")
                hours[ts.hour] += 1
            except (ValueError, KeyError):
                pass

        # Top destinations and ports
        top_dsts = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:15]

        # Active hours (hours with activity)
        active_hours = sorted(hours.keys())

        # Connections per hour estimate
        if active_hours:
            hour_values = list(hours.values())
            conn_per_hour = _stats(hour_values)
        else:
            conn_per_hour = _stats([])

        profiles[ip] = {
            "bytes_sent": _stats(bytes_sent),
            "bytes_received": _stats(bytes_recv),
            "duration": _stats(durations),
            "conn_per_hour": conn_per_hour,
            "common_destinations": {d: c for d, c in top_dsts},
            "common_ports": {str(p): c for p, c in top_ports},
            "active_hours": active_hours,
            "total_flows": len(ip_flow_list),
        }

    return profiles


def update_baseline(
    existing: dict[str, dict],
    new_flows: list[dict],
) -> dict[str, dict]:
    """Update existing baseline profiles with new flow data.

    Uses exponential moving average to blend old and new statistics.

    Args:
        existing: Current baseline profiles.
        new_flows: New flow data to incorporate.

    Returns:
        Updated baseline profiles.
    """
    new_profiles = build_baseline(new_flows, window_hours=0)
    alpha = 0.3  # Weight for new data

    merged = dict(existing)

    for ip, new_prof in new_profiles.items():
        if ip not in merged:
            merged[ip] = new_prof
            continue

        old = merged[ip]
        # Blend stats with EMA
        for stat_key in ["bytes_sent", "bytes_received", "duration"]:
            if stat_key in old and stat_key in new_prof:
                for k in ["mean", "std", "p50", "p95"]:
                    old_val = old[stat_key].get(k, 0)
                    new_val = new_prof[stat_key].get(k, 0)
                    old[stat_key][k] = round(old_val * (1 - alpha) + new_val * alpha, 2)
                old[stat_key]["count"] = old[stat_key].get("count", 0) + new_prof[stat_key].get("count", 0)

        # Merge destinations
        for dst, cnt in new_prof.get("common_destinations", {}).items():
            old_dsts = old.get("common_destinations", {})
            old_dsts[dst] = old_dsts.get(dst, 0) + cnt
            old["common_destinations"] = old_dsts

        # Merge active hours
        old_hours = set(old.get("active_hours", []))
        new_hours = set(new_prof.get("active_hours", []))
        old["active_hours"] = sorted(old_hours | new_hours)

        old["total_flows"] = old.get("total_flows", 0) + new_prof.get("total_flows", 0)
        merged[ip] = old

    return merged


if __name__ == "__main__":
    import json
    from simulate_traffic import generate_traffic

    print("[*] Generating test traffic...")
    flows = generate_traffic(normal_count=500, anomaly_sets=2)
    normal_flows = [f for f in flows if f["label"] == "normal"]

    print(f"[*] Building baseline from {len(normal_flows)} normal flows...")
    profiles = build_baseline(normal_flows)

    print(f"[+] Profiled {len(profiles)} internal hosts\n")
    for ip, prof in list(profiles.items())[:3]:
        print(f"  {ip}:")
        print(f"    Flows: {prof['total_flows']}")
        print(f"    Bytes sent: mean={prof['bytes_sent']['mean']}, std={prof['bytes_sent']['std']}")
        print(f"    Active hours: {prof['active_hours']}")
        print(f"    Top destinations: {list(prof['common_destinations'].keys())[:5]}")
        print()
