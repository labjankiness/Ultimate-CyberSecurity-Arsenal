"""
Attacker behavior analysis for the SSH Honeypot.

Provides pattern detection, statistical analysis, and optional
AI-generated threat summaries via Ollama.

Usage:
    from analytics import get_full_analysis
    report = get_full_analysis()
"""

import json
import requests
from typing import Optional

from database import (
    get_summary_stats, get_top_attackers, get_credential_stats,
    get_hourly_activity, get_country_stats,
)
from log_processor import detect_credential_reuse, detect_rapid_attacks


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"


def get_full_analysis() -> dict:
    """Run all analytics and return a comprehensive report.

    Returns:
        Dict with all analysis results: summary, top_attackers,
        credentials, hourly, countries, credential_reuse, rapid_attacks.
    """
    return {
        "summary": get_summary_stats(),
        "top_attackers": get_top_attackers(10),
        "credentials": get_credential_stats(),
        "hourly_activity": get_hourly_activity(),
        "country_stats": get_country_stats(),
        "credential_reuse": detect_credential_reuse(),
        "rapid_attacks": detect_rapid_attacks(),
    }


def generate_ai_summary(analysis: Optional[dict] = None) -> str:
    """Generate an AI threat summary using Ollama.

    Args:
        analysis: Pre-computed analysis dict. If None, runs full analysis.

    Returns:
        AI-generated threat intelligence summary string.
    """
    if analysis is None:
        analysis = get_full_analysis()

    summary = analysis["summary"]
    top_attackers = analysis["top_attackers"][:5]
    creds = analysis["credentials"]
    countries = analysis["country_stats"]
    reuse = analysis["credential_reuse"][:5]
    rapid = analysis["rapid_attacks"][:5]

    prompt = f"""You are a cybersecurity threat intelligence analyst reviewing SSH honeypot data.

Analyze this honeypot data and provide a concise threat intelligence summary:

OVERVIEW:
- Total connections: {summary['total_connections']}
- Unique attacker IPs: {summary['unique_ips']}
- Unique usernames tried: {summary['unique_usernames']}
- Unique passwords tried: {summary['unique_passwords']}
- Countries: {summary['unique_countries']}

TOP ATTACKERS:
{json.dumps(top_attackers, indent=2)}

TOP USERNAMES: {list(creds['top_usernames'].keys())[:10]}
TOP PASSWORDS: {list(creds['top_passwords'].keys())[:10]}
ATTACK ORIGINS: {json.dumps(dict(list(countries.items())[:10]))}

CREDENTIAL REUSE (same password, different IPs — indicates coordinated attacks):
{json.dumps(reuse, indent=2)}

RAPID ATTACKS (automated tool indicators):
{json.dumps(rapid, indent=2)}

Provide:
1. A 2-3 sentence executive summary
2. Key findings (bullet points)
3. Attacker profile assessment (sophistication level, likely motivation)
4. Recommendations

Keep the response under 300 words."""

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        }, timeout=90)
        response.raise_for_status()
        return response.json().get("response", "AI summary unavailable.")
    except requests.RequestException:
        return _generate_offline_summary(analysis)


def _generate_offline_summary(analysis: dict) -> str:
    """Generate a basic summary without AI.

    Args:
        analysis: Full analysis dict.
    """
    s = analysis["summary"]
    top = analysis["top_attackers"]
    countries = analysis["country_stats"]
    reuse = analysis["credential_reuse"]
    rapid = analysis["rapid_attacks"]

    lines = [
        "HONEYPOT THREAT SUMMARY",
        "=" * 40,
        f"Total connections: {s['total_connections']}",
        f"Unique attacker IPs: {s['unique_ips']}",
        f"Unique credentials: {s['unique_usernames']} usernames, {s['unique_passwords']} passwords",
        f"Countries observed: {s['unique_countries']}",
        "",
    ]

    if top:
        lines.append("TOP ATTACKERS:")
        for a in top[:5]:
            lines.append(f"  {a['source_ip']}: {a['total_attempts']} attempts "
                        f"({a['unique_usernames']} users, {a['unique_passwords']} passwords)")
        lines.append("")

    if countries:
        lines.append("TOP COUNTRIES:")
        for country, count in list(countries.items())[:5]:
            lines.append(f"  {country}: {count} connections")
        lines.append("")

    if reuse:
        lines.append(f"CREDENTIAL REUSE: {len(reuse)} passwords shared across multiple IPs "
                     "(possible coordinated attack)")

    if rapid:
        lines.append(f"AUTOMATED ATTACKS: {len(rapid)} IPs showing rapid-fire patterns "
                     "(likely using automated tools)")

    return "\n".join(lines)


if __name__ == "__main__":
    from database import init_db
    init_db()

    analysis = get_full_analysis()
    print("=== Honeypot Analytics ===\n")
    print(f"Summary: {analysis['summary']}")
    print(f"Top attackers: {len(analysis['top_attackers'])}")
    print(f"Credential reuse: {len(analysis['credential_reuse'])} shared passwords")
    print(f"Rapid attacks: {len(analysis['rapid_attacks'])} automated sources")
    print()
    print(_generate_offline_summary(analysis))
