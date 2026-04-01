"""
AI-SOC Triage Agent — LLM-powered security log analysis.

Sends security log entries to a local Ollama instance and returns
structured JSON verdicts with threat classification, IOC extraction,
and remediation guidance.

Usage:
    from triage_agent import analyze_log
    result = analyze_log("sshd: Failed password for root from 203.0.113.5 port 22")
    # result is a Python dict with verdict, threat_level, category, etc.
"""

import json
import time
import requests
from typing import Optional
from mitre_mapping import get_mitre_mapping
from threat_intel import enrich_alert
from correlator import correlate


# Local Ollama endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

SYSTEM_PROMPT = """You are a Senior SOC Analyst. Analyze the provided security log entry for malicious intent.

You MUST respond with ONLY valid JSON — no markdown, no explanation, no extra text. Just the raw JSON object.

Required JSON schema:
{
  "verdict": "True Positive" or "False Positive",
  "threat_level": <integer 1-10>,
  "category": "<one of: SSH Brute Force, Privilege Escalation, SQL Injection, Port Scan, Rogue USB, Reconnaissance, Other>",
  "summary": "<max 2 sentences>",
  "remediation": "<one clear actionable step>",
  "iocs": {
    "source_ip": "<extracted IP address or null>",
    "username": "<extracted username or null>",
    "command": "<extracted command or null>"
  }
}

Rules:
- threat_level 1-3: informational / low risk
- threat_level 4-6: medium risk, needs investigation
- threat_level 7-10: high/critical, immediate action needed
- Extract ALL indicators of compromise (IPs, usernames, commands) from the log
- If unsure about a field, use null instead of guessing
- Respond ONLY with the JSON object, nothing else"""


def _extract_iocs_from_log(log_entry: str) -> dict:
    """Quick regex extraction of IOCs from a raw log line for pre-enrichment.

    Args:
        log_entry: Raw log text.

    Returns:
        Dict with source_ip, username, command (any may be None).
    """
    import re
    # Extract IP addresses (skip common internal/localhost)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_entry)
    source_ip = None
    for ip in ips:
        if not ip.startswith("127.") and not ip.startswith("0."):
            source_ip = ip
            break

    # Extract username from common log patterns
    username = None
    m = re.search(r'(?:for|user[= ])(\w+)', log_entry, re.IGNORECASE)
    if m:
        username = m.group(1)

    return {"source_ip": source_ip, "username": username, "command": None}


def _parse_llm_json(text: str) -> Optional[dict]:
    """Attempt to parse JSON from LLM output, handling common formatting issues.

    Args:
        text: Raw text response from the LLM.

    Returns:
        Parsed dict if valid JSON found, None otherwise.
    """
    text = text.strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strip markdown code fences if present
    if "```" in text:
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                json_lines.append(line)
        try:
            return json.loads("\n".join(json_lines))
        except json.JSONDecodeError:
            pass

    # Try to find JSON object in the text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    return None


def _validate_alert(data: dict) -> dict:
    """Ensure all required fields exist with correct types.

    Args:
        data: Parsed JSON dict from the LLM.

    Returns:
        Cleaned dict with all required fields.
    """
    valid_categories = {
        "SSH Brute Force", "Privilege Escalation", "SQL Injection",
        "Port Scan", "Rogue USB", "Reconnaissance", "Other"
    }

    verdict = data.get("verdict", "")
    if verdict not in ("True Positive", "False Positive"):
        verdict = "True Positive" if "true" in str(verdict).lower() else "False Positive"

    threat_level = data.get("threat_level", 5)
    if not isinstance(threat_level, int):
        try:
            threat_level = int(threat_level)
        except (ValueError, TypeError):
            threat_level = 5
    threat_level = max(1, min(10, threat_level))

    category = data.get("category", "Other")
    if category not in valid_categories:
        category = "Other"

    iocs = data.get("iocs", {})
    if not isinstance(iocs, dict):
        iocs = {}

    return {
        "verdict": verdict,
        "threat_level": threat_level,
        "category": category,
        "summary": str(data.get("summary", "No summary available.")),
        "remediation": str(data.get("remediation", "Investigate further.")),
        "iocs": {
            "source_ip": iocs.get("source_ip"),
            "username": iocs.get("username"),
            "command": iocs.get("command"),
        },
    }


def analyze_log(log_entry: str, max_retries: int = 1) -> dict:
    """Analyze a security log entry using the local LLM.

    Sends the log to Ollama, parses the structured JSON response,
    and returns a validated alert dict. Retries once on parse failure.

    Args:
        log_entry: Raw security log line to analyze.
        max_retries: Number of retry attempts if JSON parsing fails.

    Returns:
        Dict with keys: verdict, threat_level, category, summary,
        remediation, iocs, raw_log, timestamp, model_used.
    """
    # Pre-enrich with threat intelligence to provide LLM context
    pre_alert = {
        "raw_log": log_entry.strip(),
        "iocs": _extract_iocs_from_log(log_entry),
    }
    pre_alert = enrich_alert(pre_alert)
    enrichment_ctx = ""
    enrichment_data = pre_alert.get("enrichment", {})
    if enrichment_data.get("findings"):
        enrichment_ctx = f"\n\nTHREAT INTELLIGENCE: {enrichment_data.get('summary', '')}"
        if enrichment_data.get("is_known_malicious"):
            enrichment_ctx += " [KNOWN MALICIOUS]"

    # Pre-correlate for prompt context (uses raw IOCs before LLM categorization)
    pre_corr = correlate({
        "source_ip": pre_alert["iocs"].get("source_ip"),
        "category": "Other",  # unknown yet, will be set after LLM
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    correlation_ctx = ""
    if pre_corr.get("is_correlated") and pre_corr.get("narrative"):
        prefix = "CRITICAL CONTEXT: " if pre_corr.get("escalated_severity", 0) >= 8 else ""
        correlation_ctx = f"\n\nCORRELATION: {prefix}{pre_corr['narrative']}"

    payload = {
        "model": MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\nLOG DATA: {log_entry.strip()}{enrichment_ctx}{correlation_ctx}",
        "stream": False,
    }

    for attempt in range(1 + max_retries):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=60)
            response.raise_for_status()
            raw_text = response.json().get("response", "")

            parsed = _parse_llm_json(raw_text)
            if parsed:
                alert = _validate_alert(parsed)
                alert["raw_log"] = log_entry.strip()
                alert["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                alert["model_used"] = MODEL
                # Enrich with MITRE ATT&CK mapping
                mitre = get_mitre_mapping(alert["category"])
                alert["mitre_technique_id"] = mitre["technique_id"]
                alert["mitre_technique_name"] = mitre["technique_name"]
                alert["mitre_tactic"] = mitre["tactic"]
                alert["mitre_url"] = mitre["mitre_url"]
                # Attach enrichment data
                alert["enrichment"] = enrichment_data
                # Attach correlation data
                alert["correlation_id"] = pre_corr.get("correlation_id")
                alert["chain_stage"] = pre_corr.get("chain_stage")
                alert["is_correlated"] = pre_corr.get("is_correlated", False)
                alert["correlation_narrative"] = pre_corr.get("narrative", "")
                # Escalate severity if correlator flags it
                if pre_corr.get("escalated_severity"):
                    alert["threat_level"] = max(alert["threat_level"], pre_corr["escalated_severity"])
                return alert

            # If parse failed and we have retries left, add stronger instruction
            if attempt < max_retries:
                payload["prompt"] = (
                    "IMPORTANT: Your previous response was not valid JSON. "
                    "Respond with ONLY a JSON object, no other text.\n\n"
                    + payload["prompt"]
                )

        except requests.RequestException as e:
            return {
                "verdict": "Error",
                "threat_level": 0,
                "category": "Other",
                "summary": f"LLM request failed: {str(e)}",
                "remediation": "Check Ollama connectivity.",
                "iocs": {"source_ip": None, "username": None, "command": None},
                "raw_log": log_entry.strip(),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "model_used": MODEL,
            }

    # All retries exhausted
    return {
        "verdict": "Error",
        "threat_level": 0,
        "category": "Other",
        "summary": "Failed to parse LLM response as JSON after retry.",
        "remediation": "Review raw LLM output manually.",
        "iocs": {"source_ip": None, "username": None, "command": None},
        "raw_log": log_entry.strip(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model_used": MODEL,
    }


if __name__ == "__main__":
    test_log = "Feb 23 14:12:01 republic-poly-vm sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
    print("--- AI TRIAGE REPORT ---")
    result = analyze_log(test_log)
    print(json.dumps(result, indent=2))
