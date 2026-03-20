"""
SQLite database layer for the AI-SOC alert storage.

Stores structured triage results from the LLM alongside raw log data.
All alerts are persisted in soc_alerts.db for querying and dashboard display.

Usage:
    from database import init_db, store_alert, get_alerts, get_alert_stats
    init_db()
    store_alert(alert_dict)
"""

import sqlite3
import time
from typing import Optional


DB_FILE = "soc_alerts.db"


def _get_conn() -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the alerts table if it doesn't exist, and migrate if needed."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_log TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            model_used TEXT,
            verdict TEXT,
            threat_level INTEGER,
            category TEXT,
            summary TEXT,
            remediation TEXT,
            source_ip TEXT,
            username TEXT,
            command TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_tactic TEXT,
            mitre_url TEXT,
            abuse_confidence_score INTEGER,
            total_reports INTEGER,
            is_known_malicious INTEGER DEFAULT 0,
            enrichment_source TEXT
        )
    """)
    # Backwards-compatible migration: add MITRE columns if they don't exist
    existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for col in ["mitre_technique_id", "mitre_technique_name", "mitre_tactic", "mitre_url",
                 "abuse_confidence_score", "total_reports", "is_known_malicious", "enrichment_source"]:
        if col not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
    conn.commit()
    conn.close()


def store_alert(alert: dict) -> int:
    """Store an alert dict in the database. Returns the inserted row id.

    Args:
        alert: Dict with keys matching the JSON schema from the LLM
               plus raw_log, timestamp, and model_used.

    Returns:
        The auto-incremented row id of the inserted alert.
    """
    conn = _get_conn()
    iocs = alert.get("iocs", {})
    enrichment = alert.get("enrichment", {})
    cur = conn.execute("""
        INSERT INTO alerts (raw_log, timestamp, model_used, verdict, threat_level,
                            category, summary, remediation, source_ip, username, command,
                            mitre_technique_id, mitre_technique_name, mitre_tactic, mitre_url,
                            abuse_confidence_score, total_reports, is_known_malicious, enrichment_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("raw_log", ""),
        alert.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
        alert.get("model_used", ""),
        alert.get("verdict", ""),
        alert.get("threat_level", 0),
        alert.get("category", ""),
        alert.get("summary", ""),
        alert.get("remediation", ""),
        iocs.get("source_ip") if iocs else alert.get("source_ip"),
        iocs.get("username") if iocs else alert.get("username"),
        iocs.get("command") if iocs else alert.get("command"),
        alert.get("mitre_technique_id", ""),
        alert.get("mitre_technique_name", ""),
        alert.get("mitre_tactic", ""),
        alert.get("mitre_url", ""),
        enrichment.get("abuse_confidence_score"),
        enrichment.get("total_reports"),
        1 if enrichment.get("is_known_malicious") else 0,
        enrichment.get("summary", ""),
    ))
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_alerts(
    limit: int = 50,
    offset: int = 0,
    min_severity: int = 0,
    category_filter: Optional[str] = None,
) -> list[dict]:
    """Retrieve alerts from the database with optional filters.

    Args:
        limit: Max number of results to return.
        offset: Number of rows to skip (for pagination).
        min_severity: Minimum threat_level to include.
        category_filter: If set, only return alerts matching this category.

    Returns:
        List of alert dicts ordered by most recent first.
    """
    conn = _get_conn()
    query = "SELECT * FROM alerts WHERE threat_level >= ?"
    params: list = [min_severity]

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_stats() -> dict:
    """Return aggregate statistics about all stored alerts.

    Returns:
        Dict with: total, true_positives, false_positives, avg_threat_level,
        by_category (dict), by_hour (dict).
    """
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    tp = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict = 'True Positive'").fetchone()[0]
    fp = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict = 'False Positive'").fetchone()[0]
    avg = conn.execute("SELECT AVG(threat_level) FROM alerts").fetchone()[0] or 0.0

    by_category_rows = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM alerts GROUP BY category ORDER BY cnt DESC"
    ).fetchall()
    by_category = {row["category"]: row["cnt"] for row in by_category_rows}

    by_hour_rows = conn.execute(
        "SELECT substr(timestamp, 12, 2) as hour, COUNT(*) as cnt "
        "FROM alerts GROUP BY hour ORDER BY hour"
    ).fetchall()
    by_hour = {row["hour"]: row["cnt"] for row in by_hour_rows}

    conn.close()
    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "avg_threat_level": round(avg, 1),
        "by_category": by_category,
        "by_hour": by_hour,
    }


if __name__ == "__main__":
    init_db()
    conn = _get_conn()
    schema = conn.execute("PRAGMA table_info(alerts)").fetchall()
    print("=== soc_alerts.db schema ===")
    print(f"{'Column':<16} {'Type':<12} {'Nullable':<10} {'PK'}")
    print("-" * 50)
    for col in schema:
        nullable = "YES" if not col["notnull"] else "NO"
        pk = "PK" if col["pk"] else ""
        print(f"{col['name']:<16} {col['type']:<12} {nullable:<10} {pk}")
    conn.close()
    print("\nDatabase initialized successfully.")
