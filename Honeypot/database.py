"""
SQLite storage layer for the SSH Honeypot.

Stores connection attempts, captured commands, and per-IP statistics
for the analytics dashboard.

Usage:
    from database import init_db, store_connection, get_connections
    init_db()
    store_connection({...})
"""

import sqlite3
import time
from typing import Optional


DB_FILE = "honeypot.db"


def _get_conn() -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create all tables if they don't exist."""
    conn = _get_conn()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            username TEXT,
            password TEXT,
            client_banner TEXT,
            geo_country TEXT,
            geo_city TEXT,
            session_duration REAL DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            command_text TEXT NOT NULL,
            FOREIGN KEY (connection_id) REFERENCES connections(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_stats (
            source_ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            total_attempts INTEGER DEFAULT 1,
            unique_usernames INTEGER DEFAULT 1,
            unique_passwords INTEGER DEFAULT 1
        )
    """)

    conn.commit()
    conn.close()


def store_connection(data: dict) -> int:
    """Store a connection attempt. Returns the row ID.

    Args:
        data: Dict with keys: source_ip, source_port, username, password,
              client_banner, geo_country, geo_city, session_duration.
    """
    conn = _get_conn()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    cur = conn.execute("""
        INSERT INTO connections (timestamp, source_ip, source_port, username,
                                 password, client_banner, geo_country, geo_city,
                                 session_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts,
        data.get("source_ip", ""),
        data.get("source_port", 0),
        data.get("username", ""),
        data.get("password", ""),
        data.get("client_banner", ""),
        data.get("geo_country", "Unknown"),
        data.get("geo_city", "Unknown"),
        data.get("session_duration", 0),
    ))
    row_id = cur.lastrowid

    # Update IP stats
    ip = data.get("source_ip", "")
    existing = conn.execute("SELECT * FROM ip_stats WHERE source_ip = ?", (ip,)).fetchone()
    if existing:
        conn.execute("""
            UPDATE ip_stats SET
                last_seen = ?,
                total_attempts = total_attempts + 1,
                unique_usernames = (SELECT COUNT(DISTINCT username) FROM connections WHERE source_ip = ?),
                unique_passwords = (SELECT COUNT(DISTINCT password) FROM connections WHERE source_ip = ?)
            WHERE source_ip = ?
        """, (ts, ip, ip, ip))
    else:
        conn.execute("""
            INSERT INTO ip_stats (source_ip, first_seen, last_seen, total_attempts,
                                   unique_usernames, unique_passwords)
            VALUES (?, ?, ?, 1, 1, 1)
        """, (ip, ts, ts))

    conn.commit()
    conn.close()
    return row_id


def store_command(connection_id: int, command: str) -> int:
    """Store a captured command from a fake shell session.

    Args:
        connection_id: The parent connection row ID.
        command: The command text entered by the attacker.
    """
    conn = _get_conn()
    cur = conn.execute("""
        INSERT INTO commands (connection_id, timestamp, command_text)
        VALUES (?, ?, ?)
    """, (connection_id, time.strftime("%Y-%m-%d %H:%M:%S"), command))
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_connections(limit: int = 100, offset: int = 0) -> list[dict]:
    """Retrieve recent connection attempts.

    Args:
        limit: Max results.
        offset: Pagination offset.
    """
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM connections ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_top_attackers(limit: int = 10) -> list[dict]:
    """Get top attacker IPs by attempt count."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT source_ip, total_attempts, unique_usernames, unique_passwords,
               first_seen, last_seen
        FROM ip_stats
        ORDER BY total_attempts DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_credential_stats() -> dict:
    """Get top attempted usernames and passwords."""
    conn = _get_conn()

    top_users = conn.execute("""
        SELECT username, COUNT(*) as cnt
        FROM connections WHERE username IS NOT NULL AND username != ''
        GROUP BY username ORDER BY cnt DESC LIMIT 15
    """).fetchall()

    top_passwords = conn.execute("""
        SELECT password, COUNT(*) as cnt
        FROM connections WHERE password IS NOT NULL AND password != ''
        GROUP BY password ORDER BY cnt DESC LIMIT 15
    """).fetchall()

    conn.close()
    return {
        "top_usernames": {r["username"]: r["cnt"] for r in top_users},
        "top_passwords": {r["password"]: r["cnt"] for r in top_passwords},
    }


def get_hourly_activity() -> dict[str, int]:
    """Get connection counts grouped by hour of day."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT substr(timestamp, 12, 2) as hour, COUNT(*) as cnt
        FROM connections
        GROUP BY hour ORDER BY hour
    """).fetchall()
    conn.close()
    return {r["hour"]: r["cnt"] for r in rows}


def get_country_stats() -> dict[str, int]:
    """Get connection counts grouped by country."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT geo_country, COUNT(*) as cnt
        FROM connections
        WHERE geo_country IS NOT NULL AND geo_country != 'Unknown'
        GROUP BY geo_country ORDER BY cnt DESC
    """).fetchall()
    conn.close()
    return {r["geo_country"]: r["cnt"] for r in rows}


def get_connection_commands(connection_id: int) -> list[dict]:
    """Get all commands from a specific connection session."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM commands WHERE connection_id = ? ORDER BY id ASC",
        (connection_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_attacker_history(source_ip: str) -> list[dict]:
    """Get all connection attempts from a specific IP."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM connections WHERE source_ip = ? ORDER BY id ASC",
        (source_ip,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_summary_stats() -> dict:
    """Get high-level summary statistics."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM connections").fetchone()[0]
    unique_users = conn.execute("SELECT COUNT(DISTINCT username) FROM connections WHERE username != ''").fetchone()[0]
    unique_passwords = conn.execute("SELECT COUNT(DISTINCT password) FROM connections WHERE password != ''").fetchone()[0]
    unique_countries = conn.execute("SELECT COUNT(DISTINCT geo_country) FROM connections WHERE geo_country != 'Unknown'").fetchone()[0]
    conn.close()
    return {
        "total_connections": total,
        "unique_ips": unique_ips,
        "unique_usernames": unique_users,
        "unique_passwords": unique_passwords,
        "unique_countries": unique_countries,
    }


if __name__ == "__main__":
    init_db()
    conn = _get_conn()
    for table in ["connections", "commands", "ip_stats"]:
        schema = conn.execute(f"PRAGMA table_info({table})").fetchall()
        print(f"=== {table} ===")
        for col in schema:
            print(f"  {col['name']:<20} {col['type']:<12}")
        print()
    conn.close()
    print("Database initialized.")
