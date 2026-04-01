"""
Automated Response Suggestion Engine for AI-SOC.

Generates actionable remediation commands based on alert category,
severity, and correlation context. Human-in-the-loop design: the system
suggests responses, the analyst reviews and approves before execution.

Usage:
    from response_engine import generate_response
    suggestions = generate_response(alert_dict)
    # suggestions is a list of dicts with action_name, command, risk_level, etc.
"""

from typing import Optional


# Response templates mapped to attack categories.
# Each entry: (action_name, command_template, risk_level, explanation)
RESPONSE_TEMPLATES: dict[str, list[tuple[str, str, str, str]]] = {
    "SSH Brute Force": [
        (
            "Block source IP",
            "sudo iptables -A INPUT -s {source_ip} -j DROP",
            "moderate",
            "Drops all inbound traffic from the attacking IP. May block legitimate users if IP is shared.",
        ),
        (
            "Ban IP via fail2ban",
            "sudo fail2ban-client set sshd banip {source_ip}",
            "safe",
            "Adds the IP to the fail2ban SSH jail. Temporary ban that expires per jail config.",
        ),
        (
            "Disable SSH password auth",
            "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
            "aggressive",
            "Disables password-based SSH login server-wide. Ensure key-based auth is configured first or you may lock yourself out.",
        ),
    ],
    "Privilege Escalation": [
        (
            "Revoke sudo access",
            "sudo deluser {username} sudo",
            "aggressive",
            "Removes the user from the sudo group immediately. They lose all elevated privileges.",
        ),
        (
            "Lock user account",
            "sudo usermod -L {username}",
            "moderate",
            "Locks the account, preventing login. Existing sessions remain active until terminated.",
        ),
        (
            "Audit recent activity",
            "sudo ausearch -ua {username} --start recent",
            "safe",
            "Searches the audit log for recent actions by this user. Read-only, no system changes.",
        ),
    ],
    "SQL Injection": [
        (
            "Block IP at firewall",
            "sudo ufw deny from {source_ip}",
            "moderate",
            "Blocks all traffic from the attacking IP via UFW. Effective immediately.",
        ),
        (
            "Review input validation",
            "grep -rn 'execute\\|raw\\|cursor' /var/www/ --include='*.py' --include='*.php'",
            "safe",
            "Searches web application code for raw SQL usage. Read-only investigation step.",
        ),
        (
            "Enable ModSecurity WAF rules",
            "sudo a2enmod security2 && sudo systemctl restart apache2",
            "moderate",
            "Enables the ModSecurity web application firewall module. May block legitimate requests if rules are too strict.",
        ),
    ],
    "Port Scan": [
        (
            "Rate-limit source IP",
            "sudo iptables -A INPUT -s {source_ip} -m limit --limit 1/s -j ACCEPT && sudo iptables -A INPUT -s {source_ip} -j DROP",
            "moderate",
            "Limits inbound traffic from the scanner to 1 packet/sec, dropping excess. Mitigates scan without full block.",
        ),
        (
            "Log and monitor",
            "sudo iptables -A INPUT -s {source_ip} -j LOG --log-prefix \"PORT_SCAN: \"",
            "safe",
            "Logs all packets from the source IP with a prefix for easy filtering. No traffic is blocked.",
        ),
    ],
    "Rogue USB": [
        (
            "Disable USB ports",
            "echo 0 | sudo tee /sys/bus/usb/devices/*/authorized",
            "aggressive",
            "Deauthorizes all USB devices immediately. Will disconnect keyboards, mice, and storage. Use with caution.",
        ),
        (
            "Check USB device history",
            "sudo dmesg | grep -i usb | tail -20",
            "safe",
            "Reviews recent kernel messages for USB events. Read-only investigation step.",
        ),
    ],
    "Reconnaissance": [
        (
            "Block source IP",
            "sudo iptables -A INPUT -s {source_ip} -j DROP",
            "moderate",
            "Drops all inbound traffic from the reconnaissance source. Prevents further scanning.",
        ),
        (
            "Log and monitor",
            "sudo iptables -A INPUT -s {source_ip} -j LOG --log-prefix \"RECON: \"",
            "safe",
            "Logs packets from this IP for monitoring without blocking. Useful for intelligence gathering.",
        ),
    ],
}

# Escalation responses for correlated incidents / high severity
INCIDENT_PLAYBOOK: list[tuple[str, str, str, str]] = [
    (
        "Isolate host from network",
        "sudo ip link set eth0 down",
        "aggressive",
        "Takes the network interface offline, isolating the host. All network connectivity will be lost.",
    ),
    (
        "Block outbound to C2 server",
        "sudo iptables -A OUTPUT -d {dest_ip} -j DROP",
        "moderate",
        "Blocks outbound traffic to the suspected command-and-control IP. Stops data exfiltration.",
    ),
    (
        "Capture forensic snapshot",
        "sudo tar czf /tmp/forensic_$(date +%Y%m%d_%H%M%S).tar.gz /var/log/ /etc/passwd /etc/shadow /etc/crontab /tmp/",
        "safe",
        "Archives key system files for forensic analysis. Read-only, preserves evidence.",
    ),
    (
        "Kill suspicious processes",
        "sudo ps aux | grep -E '{username}|{source_ip}' | grep -v grep",
        "safe",
        "Lists processes associated with the compromised user or attacker IP. Review before killing.",
    ),
]


def generate_response(alert: dict) -> list[dict]:
    """Generate response suggestions for a triaged alert.

    Args:
        alert: Alert dict from the triage agent with at least:
               verdict, threat_level, category, iocs (or source_ip/username).

    Returns:
        List of suggestion dicts, each with: action_name, command,
        risk_level, explanation, requires_approval, priority.
    """
    verdict = alert.get("verdict", "")
    threat_level = alert.get("threat_level", 0)
    category = alert.get("category", "Other")
    is_correlated = alert.get("is_correlated", False)

    # Extract IOCs for template substitution
    iocs = alert.get("iocs", {})
    if isinstance(iocs, dict):
        source_ip = iocs.get("source_ip") or alert.get("source_ip") or "UNKNOWN_IP"
        username = iocs.get("username") or alert.get("username") or "UNKNOWN_USER"
    else:
        source_ip = alert.get("source_ip") or "UNKNOWN_IP"
        username = alert.get("username") or "UNKNOWN_USER"

    dest_ip = "UNKNOWN_IP"  # For exfiltration scenarios
    raw_log = alert.get("raw_log", "")
    # Try to extract destination IP from firewall logs
    if "DST=" in raw_log:
        parts = raw_log.split("DST=")
        if len(parts) > 1:
            dest_ip = parts[1].split()[0]

    template_vars = {
        "source_ip": source_ip,
        "username": username,
        "dest_ip": dest_ip,
    }

    suggestions: list[dict] = []

    # False positives: only suggest monitoring
    if verdict == "False Positive":
        suggestions.append({
            "action_name": "Log and continue monitoring",
            "command": "# No action required — flagged as False Positive",
            "risk_level": "safe",
            "explanation": "Alert was classified as a false positive. Continue monitoring for recurrence.",
            "requires_approval": False,
            "priority": 1,
        })
        return suggestions

    # Get category-specific templates
    templates = RESPONSE_TEMPLATES.get(category, [])

    # Filter by severity level
    if threat_level <= 4:
        # Low severity: only safe actions
        for name, cmd, risk, explanation in templates:
            if risk == "safe":
                suggestions.append({
                    "action_name": name,
                    "command": cmd.format(**template_vars),
                    "risk_level": risk,
                    "explanation": explanation,
                    "requires_approval": False,
                    "priority": 2,
                })
    elif threat_level <= 7:
        # Medium severity: safe + moderate actions
        for name, cmd, risk, explanation in templates:
            if risk in ("safe", "moderate"):
                suggestions.append({
                    "action_name": name,
                    "command": cmd.format(**template_vars),
                    "risk_level": risk,
                    "explanation": explanation,
                    "requires_approval": risk == "moderate",
                    "priority": 2 if risk == "safe" else 3,
                })
    else:
        # High/critical severity: all actions
        for name, cmd, risk, explanation in templates:
            suggestions.append({
                "action_name": name,
                "command": cmd.format(**template_vars),
                "risk_level": risk,
                "explanation": explanation,
                "requires_approval": risk != "safe",
                "priority": 1 if risk == "aggressive" else 2,
            })

    # Add incident playbook for correlated attacks or critical severity
    if is_correlated or threat_level >= 9:
        for name, cmd, risk, explanation in INCIDENT_PLAYBOOK:
            suggestions.append({
                "action_name": f"[INCIDENT] {name}",
                "command": cmd.format(**template_vars),
                "risk_level": risk,
                "explanation": f"INCIDENT RESPONSE: {explanation}",
                "requires_approval": True,
                "priority": 0,
            })

    # If no templates matched (e.g., category "Other"), add generic suggestions
    if not suggestions:
        suggestions.append({
            "action_name": "Investigate manually",
            "command": f"sudo journalctl --since '1 hour ago' | grep -i '{source_ip}'",
            "risk_level": "safe",
            "explanation": "No automated response template for this category. Review logs manually.",
            "requires_approval": False,
            "priority": 3,
        })
        if threat_level >= 5:
            suggestions.append({
                "action_name": "Block source IP (generic)",
                "command": f"sudo iptables -A INPUT -s {source_ip} -j DROP",
                "risk_level": "moderate",
                "explanation": "Generic IP block as a precautionary measure.",
                "requires_approval": True,
                "priority": 2,
            })

    # Sort by priority (0 = most urgent)
    suggestions.sort(key=lambda s: s["priority"])

    return suggestions


if __name__ == "__main__":
    # Test with sample alerts
    test_alerts = [
        {
            "verdict": "True Positive",
            "threat_level": 9,
            "category": "SSH Brute Force",
            "iocs": {"source_ip": "203.0.113.5", "username": "root", "command": None},
            "is_correlated": True,
            "raw_log": "sshd: Failed password for root from 203.0.113.5 port 22 ssh2",
        },
        {
            "verdict": "True Positive",
            "threat_level": 6,
            "category": "SQL Injection",
            "iocs": {"source_ip": "198.51.100.23", "username": None, "command": None},
            "is_correlated": False,
            "raw_log": "nginx: 198.51.100.23 - - 'GET /search?q=1' OR '1'='1' HTTP/1.1' 200",
        },
        {
            "verdict": "False Positive",
            "threat_level": 2,
            "category": "Other",
            "iocs": {"source_ip": "10.0.0.5", "username": "ryan", "command": None},
            "is_correlated": False,
            "raw_log": "CRON[1234]: (root) CMD (/usr/bin/logrotate)",
        },
    ]

    for alert in test_alerts:
        print(f"\n{'='*60}")
        print(f"Category: {alert['category']} | Severity: {alert['threat_level']}/10 | Verdict: {alert['verdict']}")
        print(f"{'='*60}")
        responses = generate_response(alert)
        for r in responses:
            risk_label = {"safe": "SAFE", "moderate": "MODERATE", "aggressive": "AGGRESSIVE"}[r["risk_level"]]
            approval = "REQUIRES APPROVAL" if r["requires_approval"] else "auto"
            print(f"\n  [{risk_label}] {r['action_name']} ({approval})")
            print(f"    $ {r['command']}")
            print(f"    {r['explanation']}")
