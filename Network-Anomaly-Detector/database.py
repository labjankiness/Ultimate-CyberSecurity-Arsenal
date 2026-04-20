"""
SQLite storage layer for the Network Anomaly Detector.

Stores network flows, baselines, and detected anomalies.

Usage:
    from database import init_db, store_flows, store_anomaly
"""

import sqlite3
import json
import time


DB_FILE = "anomaly_detector.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _get_conn()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            duration REAL,
            packets INTEGER,
            flags TEXT,
            label TEXT,
            anomaly_type TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT,
            anomaly_type TEXT,
            severity TEXT,
            confidence INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            evidence TEXT,
            flow_count INTEGER
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT UNIQUE,
            profile TEXT,
            updated_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def store_flows(flows: list[dict]) -> int:
    """Bulk insert flow records. Returns count inserted."""
    conn = _get_conn()
    for f in flows:
        conn.execute("""
            INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port,
                               protocol, bytes_sent, bytes_received, duration,
                               packets, flags, label, anomaly_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            f.get("timestamp"), f.get("src_ip"), f.get("dst_ip"),
            f.get("src_port"), f.get("dst_port"), f.get("protocol"),
            f.get("bytes_sent"), f.get("bytes_received"), f.get("duration"),
            f.get("packets"), f.get("flags"), f.get("label"), f.get("anomaly_type"),
        ))
    conn.commit()
    conn.close()
    return len(flows)


def store_anomaly(anomaly: dict) -> int:
    """Store a detected anomaly. Returns row ID."""
    conn = _get_conn()
    cur = conn.execute("""
        INSERT INTO anomalies (detected_at, anomaly_type, severity, confidence,
                                src_ip, dst_ip, evidence, flow_count)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        time.strftime("%Y-%m-%d %H:%M:%S"),
        anomaly.get("anomaly_type"),
        anomaly.get("severity"),
        anomaly.get("confidence"),
        anomaly.get("src_ip"),
        anomaly.get("dst_ip"),
        json.dumps(anomaly.get("evidence", {})),
        anomaly.get("flow_count", 0),
    ))
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def store_baseline(src_ip: str, profile: dict) -> None:
    """Store or update a baseline profile for an IP."""
    conn = _get_conn()
    conn.execute("""
        INSERT INTO baselines (src_ip, profile, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(src_ip) DO UPDATE SET profile=excluded.profile, updated_at=excluded.updated_at
    """, (src_ip, json.dumps(profile), time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def get_flows(limit: int = 1000, src_ip: str = None) -> list[dict]:
    """Retrieve flows, optionally filtered by source IP."""
    conn = _get_conn()
    if src_ip:
        rows = conn.execute("SELECT * FROM flows WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?", (src_ip, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_anomalies(limit: int = 100) -> list[dict]:
    """Retrieve detected anomalies."""
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM anomalies ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_baselines() -> dict[str, dict]:
    """Retrieve all baseline profiles."""
    conn = _get_conn()
    rows = conn.execute("SELECT src_ip, profile FROM baselines").fetchall()
    conn.close()
    return {r["src_ip"]: json.loads(r["profile"]) for r in rows}


def get_flow_stats() -> dict:
    """Get summary statistics."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    unique_src = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM flows").fetchone()[0]
    unique_dst = conn.execute("SELECT COUNT(DISTINCT dst_ip) FROM flows").fetchone()[0]
    anomaly_count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    conn.close()
    return {
        "total_flows": total,
        "unique_sources": unique_src,
        "unique_destinations": unique_dst,
        "anomalies_detected": anomaly_count,
    }


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
    stats = get_flow_stats()
    print(f"Stats: {stats}")
