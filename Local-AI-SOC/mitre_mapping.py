"""
MITRE ATT&CK technique mapping for AI-SOC alert categories.

Provides a local (offline) lookup of MITRE ATT&CK technique IDs,
names, tactics, and reference URLs for each attack category.

Usage:
    from mitre_mapping import get_mitre_mapping, get_all_observed_techniques
    mapping = get_mitre_mapping("SSH Brute Force")
"""

from typing import Optional


# Local MITRE ATT&CK mapping — no external API calls needed.
# Easily extendable: just add new entries to this dict.
MITRE_MAP: dict[str, dict] = {
    "SSH Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "Privilege Escalation": {
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "mitre_url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
    },
    "Rogue USB": {
        "technique_id": "T1091",
        "technique_name": "Replication Through Removable Media",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1091/",
    },
    "Reconnaissance": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "mitre_url": "https://attack.mitre.org/techniques/T1595/",
    },
    # Placeholder mappings for future attack types
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
    },
    "Lateral Movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/",
    },
    "Persistence": {
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1053/003/",
    },
}

_DEFAULT_MAPPING = {
    "technique_id": "N/A",
    "technique_name": "Unknown Technique",
    "tactic": "Unknown",
    "mitre_url": "",
}


def get_mitre_mapping(category: str) -> dict:
    """Look up the MITRE ATT&CK mapping for an alert category.

    Args:
        category: Alert category string (e.g., "SSH Brute Force").

    Returns:
        Dict with technique_id, technique_name, tactic, mitre_url.
        Returns a default "Unknown" entry if the category isn't mapped.
    """
    return MITRE_MAP.get(category, _DEFAULT_MAPPING).copy()


def get_all_observed_techniques(alert_list: list[dict]) -> dict[str, dict]:
    """Summarize all MITRE techniques observed across a list of alerts.

    Args:
        alert_list: List of alert dicts, each having a "category" key.

    Returns:
        Dict keyed by technique_id with: technique_name, tactic,
        mitre_url, count, categories (list of categories that mapped here).
    """
    observed: dict[str, dict] = {}

    for alert in alert_list:
        category = alert.get("category", "Other")
        mapping = get_mitre_mapping(category)
        tid = mapping["technique_id"]

        if tid == "N/A":
            continue

        if tid not in observed:
            observed[tid] = {
                "technique_id": tid,
                "technique_name": mapping["technique_name"],
                "tactic": mapping["tactic"],
                "mitre_url": mapping["mitre_url"],
                "count": 0,
                "categories": [],
            }

        observed[tid]["count"] += 1
        if category not in observed[tid]["categories"]:
            observed[tid]["categories"].append(category)

    return observed


if __name__ == "__main__":
    print("=== MITRE ATT&CK Mapping Table ===\n")
    print(f"{'Category':<24} {'Technique ID':<14} {'Technique Name':<45} {'Tactic'}")
    print("-" * 110)
    for cat, m in MITRE_MAP.items():
        print(f"{cat:<24} {m['technique_id']:<14} {m['technique_name']:<45} {m['tactic']}")
