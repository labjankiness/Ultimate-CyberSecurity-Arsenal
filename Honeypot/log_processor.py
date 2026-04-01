"""
Honeypot log processor — parses and structures raw honeypot data.

Provides utility functions for processing connection logs, detecting
patterns, and preparing data for the analytics engine.

Usage:
    from log_processor import process_connections, detect_credential_reuse
"""

from database import get_connections, get_attacker_history, get_credential_stats


def process_connections(limit: int = 500) -> dict:
    """Process recent connections into structured analytics data.

    Args:
        limit: Number of recent connections to process.

    Returns:
        Dict with: connections, total, by_country, by_hour,
        unique_ips, attack_patterns.
    """
    connections = get_connections(limit=limit)

    by_country: dict[str, int] = {}
    by_hour: dict[str, int] = {}
    ips: set[str] = set()

    for conn in connections:
        country = conn.get("geo_country", "Unknown")
        by_country[country] = by_country.get(country, 0) + 1

        ts = conn.get("timestamp", "")
        if len(ts) >= 13:
            hour = ts[11:13]
            by_hour[hour] = by_hour.get(hour, 0) + 1

        ips.add(conn.get("source_ip", ""))

    return {
        "connections": connections,
        "total": len(connections),
        "by_country": dict(sorted(by_country.items(), key=lambda x: x[1], reverse=True)),
        "by_hour": dict(sorted(by_hour.items())),
        "unique_ips": len(ips),
    }


def detect_credential_reuse() -> list[dict]:
    """Detect passwords used by multiple different IPs.

    This indicates a coordinated attack or shared credential list.

    Returns:
        List of dicts with: password, ip_count, ips.
    """
    from database import _get_conn
    conn = _get_conn()
    rows = conn.execute("""
        SELECT password, COUNT(DISTINCT source_ip) as ip_count,
               GROUP_CONCAT(DISTINCT source_ip) as ips
        FROM connections
        WHERE password IS NOT NULL AND password != ''
        GROUP BY password
        HAVING ip_count > 1
        ORDER BY ip_count DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    return [
        {
            "password": r["password"],
            "ip_count": r["ip_count"],
            "ips": r["ips"].split(","),
        }
        for r in rows
    ]


def detect_rapid_attacks(threshold_seconds: int = 5) -> list[dict]:
    """Detect rapid sequential connection attempts (automated tools).

    Args:
        threshold_seconds: Max time between attempts to flag as rapid.

    Returns:
        List of dicts with: source_ip, attempt_count, avg_interval.
    """
    from database import _get_conn
    conn = _get_conn()
    rows = conn.execute("""
        SELECT source_ip, timestamp
        FROM connections
        ORDER BY source_ip, timestamp
    """).fetchall()
    conn.close()

    from datetime import datetime

    ip_times: dict[str, list[datetime]] = {}
    for r in rows:
        ip = r["source_ip"]
        try:
            ts = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if ip not in ip_times:
            ip_times[ip] = []
        ip_times[ip].append(ts)

    results = []
    for ip, times in ip_times.items():
        if len(times) < 3:
            continue
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        rapid_count = sum(1 for i in intervals if i <= threshold_seconds)
        if rapid_count >= 2:
            avg_interval = sum(intervals) / len(intervals)
            results.append({
                "source_ip": ip,
                "attempt_count": len(times),
                "rapid_attempts": rapid_count,
                "avg_interval": round(avg_interval, 1),
            })

    return sorted(results, key=lambda x: x["rapid_attempts"], reverse=True)


if __name__ == "__main__":
    print("=== Log Processor Test ===\n")
    data = process_connections()
    print(f"Total connections: {data['total']}")
    print(f"Unique IPs: {data['unique_ips']}")
    print(f"Countries: {data['by_country']}")
    print(f"\nCredential reuse:")
    for cr in detect_credential_reuse():
        print(f"  Password '{cr['password']}' used by {cr['ip_count']} IPs")
    print(f"\nRapid attacks:")
    for ra in detect_rapid_attacks():
        print(f"  {ra['source_ip']}: {ra['rapid_attempts']} rapid attempts "
              f"(avg {ra['avg_interval']}s interval)")
