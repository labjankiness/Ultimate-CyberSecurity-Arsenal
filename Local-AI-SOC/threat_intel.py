"""
Threat intelligence enrichment module for AI-SOC.

Enriches alerts with threat intelligence from:
1. AbuseIPDB (optional, requires API key)
2. Local threat feed (known_threats.json — always available offline)

Usage:
    from threat_intel import enrich_alert
    enriched = enrich_alert(alert_dict)
"""

import json
import os
import re
import time
import requests
from typing import Optional

from config import ABUSEIPDB_API_KEY, ENRICHMENT_ENABLED, ABUSEIPDB_DAILY_LIMIT


# --- Rate limiter for AbuseIPDB ---
_abuseipdb_calls_today: int = 0
_abuseipdb_day: str = ""


def _rate_limit_ok() -> bool:
    """Check if we're within AbuseIPDB daily rate limit."""
    global _abuseipdb_calls_today, _abuseipdb_day
    today = time.strftime("%Y-%m-%d")
    if today != _abuseipdb_day:
        _abuseipdb_day = today
        _abuseipdb_calls_today = 0
    return _abuseipdb_calls_today < ABUSEIPDB_DAILY_LIMIT


def _increment_rate() -> None:
    """Increment the AbuseIPDB call counter."""
    global _abuseipdb_calls_today
    _abuseipdb_calls_today += 1


# --- Local Threat Feed ---
_local_feed: Optional[dict] = None


def _load_local_feed() -> dict:
    """Load the local threat intelligence feed from known_threats.json."""
    global _local_feed
    if _local_feed is not None:
        return _local_feed

    feed_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_threats.json")
    try:
        with open(feed_path) as f:
            _local_feed = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _local_feed = {"malicious_ips": [], "suspicious_user_agents": [], "attack_signatures": []}

    return _local_feed


def check_ip_reputation(ip_address: str, api_key: Optional[str] = None) -> dict:
    """Check an IP address against AbuseIPDB.

    Args:
        ip_address: The IP address to check.
        api_key: AbuseIPDB API key. If None, returns unavailable status.

    Returns:
        Dict with abuse_confidence_score, total_reports, country, isp,
        is_known_malicious, and source.
    """
    if not api_key or not _rate_limit_ok():
        return {
            "source": "abuseipdb",
            "available": False,
            "reason": "No API key" if not api_key else "Rate limit exceeded",
        }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        _increment_rate()
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return {
            "source": "abuseipdb",
            "available": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_known_malicious": data.get("abuseConfidenceScore", 0) >= 50,
        }
    except requests.RequestException:
        return {"source": "abuseipdb", "available": False, "reason": "Request failed"}


def check_local_feed(ioc_value: str, ioc_type: str = "ip") -> dict:
    """Check an IOC against the local threat intelligence feed.

    Args:
        ioc_value: The indicator value to check (IP, user agent, etc.).
        ioc_type: Type of IOC — "ip", "user_agent", or "signature".

    Returns:
        Dict with match status, threat_type, description, and source.
    """
    feed = _load_local_feed()

    if ioc_type == "ip":
        for entry in feed.get("malicious_ips", []):
            if entry["ip"] == ioc_value:
                return {
                    "source": "local_feed",
                    "match": True,
                    "threat_type": entry["type"],
                    "description": entry["description"],
                }

    elif ioc_type == "signature":
        for entry in feed.get("attack_signatures", []):
            if entry["pattern"].lower() in ioc_value.lower():
                return {
                    "source": "local_feed",
                    "match": True,
                    "threat_type": entry["type"],
                    "description": entry["description"],
                }

    return {"source": "local_feed", "match": False}


def enrich_alert(alert: dict) -> dict:
    """Enrich an alert dict with threat intelligence data.

    Extracts IOCs from the alert, checks them against AbuseIPDB
    (if configured) and the local threat feed, and adds an
    "enrichment" field to the alert.

    Args:
        alert: Alert dict with iocs field containing source_ip, etc.

    Returns:
        The same alert dict with an added "enrichment" field.
    """
    if not ENRICHMENT_ENABLED:
        alert["enrichment"] = {"enabled": False}
        return alert

    enrichment: dict = {"enabled": True, "findings": []}

    # Extract IOCs
    iocs = alert.get("iocs", {})
    source_ip = iocs.get("source_ip") if isinstance(iocs, dict) else None
    raw_log = alert.get("raw_log", "")

    # Check source IP
    if source_ip:
        # Local feed check
        local_result = check_local_feed(source_ip, "ip")
        if local_result.get("match"):
            enrichment["findings"].append(local_result)
            enrichment["is_known_malicious"] = True

        # AbuseIPDB check (optional)
        if ABUSEIPDB_API_KEY:
            abuse_result = check_ip_reputation(source_ip, ABUSEIPDB_API_KEY)
            if abuse_result.get("available"):
                enrichment["findings"].append(abuse_result)
                enrichment["abuse_confidence_score"] = abuse_result.get("abuse_confidence_score", 0)
                enrichment["total_reports"] = abuse_result.get("total_reports", 0)
                if abuse_result.get("is_known_malicious"):
                    enrichment["is_known_malicious"] = True

    # Check raw log against attack signatures
    sig_result = check_local_feed(raw_log, "signature")
    if sig_result.get("match"):
        enrichment["findings"].append(sig_result)

    # Build summary for LLM context
    summaries = []
    for finding in enrichment["findings"]:
        if finding["source"] == "local_feed" and finding.get("match"):
            summaries.append(f"Local intel: {finding.get('description', 'Known threat')}")
        elif finding["source"] == "abuseipdb" and finding.get("available"):
            score = finding.get("abuse_confidence_score", 0)
            reports = finding.get("total_reports", 0)
            summaries.append(f"AbuseIPDB: {score}% confidence, {reports} reports")

    enrichment["summary"] = "; ".join(summaries) if summaries else "No threat intelligence matches"
    enrichment["is_known_malicious"] = enrichment.get("is_known_malicious", False)

    alert["enrichment"] = enrichment
    return alert


if __name__ == "__main__":
    print("=== Threat Intel Module Test ===\n")

    # Test local feed
    test_ips = ["203.0.113.5", "192.168.1.1", "198.51.100.23"]
    for ip in test_ips:
        result = check_local_feed(ip, "ip")
        status = "MATCH" if result.get("match") else "clean"
        print(f"  {ip}: {status}")
        if result.get("match"):
            print(f"    Type: {result['threat_type']}, {result['description']}")

    # Test signature check
    print("\nSignature checks:")
    test_logs = [
        "GET /admin.php?id=1' OR '1'='1'",
        "sudo cat /etc/shadow",
        "normal web request",
    ]
    for log in test_logs:
        result = check_local_feed(log, "signature")
        status = "MATCH" if result.get("match") else "clean"
        print(f"  '{log[:50]}': {status}")
