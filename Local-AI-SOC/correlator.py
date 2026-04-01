"""
Alert Correlation Engine for AI-SOC.

Detects multi-step attack chains and groups related alerts by analyzing
patterns across a sliding time window. Provides contextual narratives
that are injected into the LLM prompt for situational awareness.

Correlation rules:
- Same source IP grouping
- Brute force detection (>5 SSH failures from same IP in 5 min)
- Kill chain detection (Recon → Initial Access → Credential Access → Privesc)
- Frequency anomaly (>10 alerts from single IP in time window)

Usage:
    from correlator import Correlator
    engine = Correlator()
    context = engine.correlate(new_alert)
"""

import time
import uuid
from collections import deque
from typing import Optional


# MITRE ATT&CK kill chain ordering (earlier stage = lower number)
KILL_CHAIN_ORDER = {
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Credential Access": 3,
    "Privilege Escalation": 4,
    "Lateral Movement": 5,
    "Exfiltration": 6,
}

# Map alert categories to kill chain stages
CATEGORY_TO_STAGE = {
    "Reconnaissance": "Reconnaissance",
    "Port Scan": "Reconnaissance",
    "SQL Injection": "Initial Access",
    "SSH Brute Force": "Credential Access",
    "Rogue USB": "Initial Access",
    "Privilege Escalation": "Privilege Escalation",
}


class Correlator:
    """In-memory alert correlation engine with sliding window buffer."""

    def __init__(self, buffer_size: int = 100, window_seconds: int = 1800) -> None:
        """Initialize the correlator.

        Args:
            buffer_size: Maximum number of alerts to keep in the buffer.
            window_seconds: Time window in seconds (default 30 minutes).
        """
        self.buffer: deque[dict] = deque(maxlen=buffer_size)
        self.window_seconds = window_seconds
        # Track correlation IDs: source_ip -> correlation_id
        self._ip_correlations: dict[str, str] = {}

    def _now(self) -> float:
        """Current time as epoch seconds."""
        return time.time()

    def _expire_old(self) -> None:
        """Remove alerts older than the time window from the buffer."""
        cutoff = self._now() - self.window_seconds
        while self.buffer and self.buffer[0].get("_epoch", 0) < cutoff:
            self.buffer.popleft()

    def _get_ip_alerts(self, source_ip: str) -> list[dict]:
        """Get all buffered alerts from a specific source IP.

        Args:
            source_ip: The IP address to filter by.

        Returns:
            List of alerts from this IP, oldest first.
        """
        return [a for a in self.buffer if a.get("source_ip") == source_ip]

    def _check_brute_force(self, source_ip: str) -> Optional[dict]:
        """Detect brute force: >5 SSH failures from same IP in 5 minutes.

        Args:
            source_ip: The source IP to check.

        Returns:
            Detection dict if brute force detected, None otherwise.
        """
        five_min_ago = self._now() - 300
        ssh_alerts = [
            a for a in self.buffer
            if a.get("source_ip") == source_ip
            and a.get("category") == "SSH Brute Force"
            and a.get("_epoch", 0) >= five_min_ago
        ]

        if len(ssh_alerts) >= 5:
            duration = self._now() - ssh_alerts[0].get("_epoch", self._now())
            return {
                "type": "brute_force",
                "count": len(ssh_alerts),
                "duration_seconds": int(duration),
                "narrative": (
                    f"BRUTE FORCE IN PROGRESS: {len(ssh_alerts)} failed SSH attempts "
                    f"from {source_ip} in the last {int(duration)} seconds."
                ),
            }
        return None

    def _check_kill_chain(self, source_ip: str) -> Optional[dict]:
        """Detect kill chain progression from the same source IP.

        Looks for sequential MITRE ATT&CK tactic stages from the same IP.

        Args:
            source_ip: The source IP to check.

        Returns:
            Detection dict if kill chain detected, None otherwise.
        """
        ip_alerts = self._get_ip_alerts(source_ip)
        if len(ip_alerts) < 2:
            return None

        # Map alerts to kill chain stages
        stages_seen: dict[str, dict] = {}
        for alert in ip_alerts:
            category = alert.get("category", "")
            stage = CATEGORY_TO_STAGE.get(category)
            if stage and stage not in stages_seen:
                stages_seen[stage] = alert

        if len(stages_seen) < 2:
            return None

        # Sort by kill chain order
        ordered = sorted(stages_seen.keys(), key=lambda s: KILL_CHAIN_ORDER.get(s, 99))
        stage_names = " → ".join(ordered)
        severity = "critical" if len(stages_seen) >= 3 else "high"

        return {
            "type": "kill_chain",
            "stages": ordered,
            "stage_count": len(stages_seen),
            "severity": severity,
            "narrative": (
                f"KILL CHAIN DETECTED from {source_ip}: {stage_names} "
                f"({len(stages_seen)} stages observed). "
                + ("ACTIVE ATTACK CHAIN — CRITICAL SEVERITY." if len(stages_seen) >= 3
                   else "Multi-stage attack in progress.")
            ),
        }

    def _check_frequency_anomaly(self, source_ip: str) -> Optional[dict]:
        """Detect frequency anomaly: >10 alerts from a single IP in the window.

        Args:
            source_ip: The source IP to check.

        Returns:
            Detection dict if anomaly detected, None otherwise.
        """
        ip_alerts = self._get_ip_alerts(source_ip)
        if len(ip_alerts) > 10:
            categories = set(a.get("category", "") for a in ip_alerts)
            return {
                "type": "frequency_anomaly",
                "count": len(ip_alerts),
                "categories": list(categories),
                "narrative": (
                    f"FREQUENCY ANOMALY: {len(ip_alerts)} alerts from {source_ip} "
                    f"in the last {self.window_seconds // 60} minutes. "
                    f"Categories: {', '.join(categories)}."
                ),
            }
        return None

    def _get_correlation_id(self, source_ip: str) -> str:
        """Get or create a correlation ID for a source IP.

        Args:
            source_ip: The source IP address.

        Returns:
            A UUID string grouping all alerts from this IP.
        """
        if source_ip not in self._ip_correlations:
            self._ip_correlations[source_ip] = str(uuid.uuid4())[:8]
        return self._ip_correlations[source_ip]

    def correlate(self, alert: dict) -> dict:
        """Run all correlation rules against a new alert.

        Adds the alert to the sliding window buffer, then checks all
        correlation rules. Returns context to be injected into the LLM prompt.

        Args:
            alert: Alert dict with at least source_ip, category, timestamp.

        Returns:
            Dict with: related_alert_count, correlation_type, chain_stage,
            escalated_severity, narrative, correlation_id, is_correlated.
        """
        self._expire_old()

        # Add epoch timestamp for internal tracking
        alert_copy = dict(alert)
        alert_copy["_epoch"] = self._now()

        # Extract source IP from iocs if nested
        iocs = alert.get("iocs", {})
        source_ip = alert.get("source_ip") or (iocs.get("source_ip") if isinstance(iocs, dict) else None)
        alert_copy["source_ip"] = source_ip

        self.buffer.append(alert_copy)

        # Default result — no correlation
        result: dict = {
            "related_alert_count": 0,
            "correlation_type": None,
            "chain_stage": None,
            "escalated_severity": None,
            "narrative": "",
            "correlation_id": None,
            "is_correlated": False,
        }

        if not source_ip:
            return result

        # Count related alerts
        ip_alerts = self._get_ip_alerts(source_ip)
        result["related_alert_count"] = len(ip_alerts)

        if len(ip_alerts) <= 1:
            return result

        # This alert is correlated with others
        result["is_correlated"] = True
        result["correlation_id"] = self._get_correlation_id(source_ip)

        # Determine current kill chain stage
        category = alert.get("category", "")
        result["chain_stage"] = CATEGORY_TO_STAGE.get(category)

        # Run detection rules (most severe first)
        narratives = []

        kill_chain = self._check_kill_chain(source_ip)
        if kill_chain:
            result["correlation_type"] = "kill_chain"
            if kill_chain["severity"] == "critical":
                result["escalated_severity"] = 10
            else:
                result["escalated_severity"] = 8
            narratives.append(kill_chain["narrative"])

        brute_force = self._check_brute_force(source_ip)
        if brute_force:
            if not result["correlation_type"]:
                result["correlation_type"] = "brute_force"
            result["escalated_severity"] = max(result["escalated_severity"] or 0, 8)
            narratives.append(brute_force["narrative"])

        frequency = self._check_frequency_anomaly(source_ip)
        if frequency:
            if not result["correlation_type"]:
                result["correlation_type"] = "frequency_anomaly"
            result["escalated_severity"] = max(result["escalated_severity"] or 0, 7)
            narratives.append(frequency["narrative"])

        # If no specific pattern but still correlated
        if not result["correlation_type"]:
            result["correlation_type"] = "same_source"
            narratives.append(
                f"This is alert #{len(ip_alerts)} from {source_ip} "
                f"in the last {self.window_seconds // 60} minutes."
            )

        result["narrative"] = " ".join(narratives)
        return result


# Global correlator instance
_correlator = Correlator()


def correlate(alert: dict) -> dict:
    """Module-level convenience function using the global correlator.

    Args:
        alert: Alert dict to correlate.

    Returns:
        Correlation context dict.
    """
    return _correlator.correlate(alert)


def reset() -> None:
    """Reset the global correlator (useful for testing)."""
    global _correlator
    _correlator = Correlator()


if __name__ == "__main__":
    print("=== Correlator Test ===\n")

    engine = Correlator(window_seconds=600)

    # Simulate a brute force attack
    test_alerts = [
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:01"},
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:05"},
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:10"},
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:15"},
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:20"},
        {"source_ip": "203.0.113.5", "category": "SSH Brute Force", "timestamp": "2026-03-30 10:00:25"},
        # Now escalate to privilege escalation — kill chain!
        {"source_ip": "203.0.113.5", "category": "Privilege Escalation", "timestamp": "2026-03-30 10:01:00"},
    ]

    for i, alert in enumerate(test_alerts):
        ctx = engine.correlate(alert)
        corr = "CORRELATED" if ctx["is_correlated"] else "standalone"
        print(f"Alert {i+1}: {alert['category']} [{corr}]")
        if ctx["narrative"]:
            print(f"  -> {ctx['narrative']}")
        if ctx["escalated_severity"]:
            print(f"  -> Escalated severity: {ctx['escalated_severity']}/10")
        print()
