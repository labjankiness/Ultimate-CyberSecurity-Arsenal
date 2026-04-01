"""
Analysis report generator for the Phishing Email Analyzer.

Produces colored terminal reports and optional JSON export from
the combined analysis results (headers, URLs, LLM content analysis).

Usage:
    from report_generator import print_report, export_json
    print_report(analysis_result)
    export_json(analysis_result, "report.json")
"""

import json
import sys
from typing import Optional

# ANSI color codes (no external dependency)
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# MITRE ATT&CK mappings for phishing
MITRE_TECHNIQUES = {
    "Credential Harvesting": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "Malware Delivery": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "Financial Fraud": {
        "id": "T1566.003",
        "name": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/003/",
    },
    "Data Theft": {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1598/",
    },
}


def _severity_color(score: int) -> str:
    """Return ANSI color based on risk score."""
    if score >= 70:
        return RED
    elif score >= 40:
        return YELLOW
    else:
        return GREEN


def _severity_label(score: int) -> str:
    """Return severity label based on risk score."""
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


def _bar(score: int, width: int = 30) -> str:
    """Render a simple ASCII progress bar."""
    filled = int(score / 100 * width)
    color = _severity_color(score)
    return f"{color}{'█' * filled}{'░' * (width - filled)}{RESET} {score}/100"


def print_report(result: dict) -> None:
    """Print a formatted analysis report to the terminal.

    Args:
        result: Combined analysis dict from analyzer.py with keys:
                overall_risk, verdict, header_analysis, url_analysis,
                content_analysis, mitre, red_flags.
    """
    overall = result.get("overall_risk", 0)
    verdict = result.get("verdict", "Unknown")
    color = _severity_color(overall)
    label = _severity_label(overall)

    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  PHISHING EMAIL ANALYSIS REPORT{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")

    # Overall verdict
    print(f"\n  {BOLD}VERDICT:{RESET}  {color}{BOLD}{verdict}{RESET}")
    print(f"  {BOLD}RISK:{RESET}     {_bar(overall)}")
    print(f"  {BOLD}SEVERITY:{RESET} {color}{label}{RESET}")

    # Email info
    headers = result.get("header_analysis", {}).get("headers", {})
    if headers:
        print(f"\n{BOLD}{'─' * 60}{RESET}")
        print(f"  {BOLD}EMAIL INFO{RESET}")
        print(f"  From:    {headers.get('from', 'N/A')}")
        print(f"  To:      {headers.get('to', 'N/A')}")
        print(f"  Subject: {headers.get('subject', 'N/A')}")
        print(f"  Date:    {headers.get('date', 'N/A')}")

    # Header analysis
    header_result = result.get("header_analysis", {})
    header_score = header_result.get("risk_score", 0)
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"  {BOLD}HEADER ANALYSIS{RESET}  {_bar(header_score)}")

    auth = header_result.get("authentication", {})
    if auth:
        spf = auth.get("spf", "N/A")
        dkim = auth.get("dkim", "N/A")
        dmarc = auth.get("dmarc", "N/A")
        spf_c = GREEN if spf == "pass" else RED if spf == "fail" else YELLOW
        dkim_c = GREEN if dkim == "pass" else RED if dkim == "fail" else YELLOW
        dmarc_c = GREEN if dmarc == "pass" else RED if dmarc == "fail" else YELLOW
        print(f"  SPF: {spf_c}{spf}{RESET}  |  DKIM: {dkim_c}{dkim}{RESET}  |  DMARC: {dmarc_c}{dmarc}{RESET}")

    for flag in header_result.get("red_flags", []):
        print(f"  {RED}[!]{RESET} {flag}")

    # URL analysis
    url_result = result.get("url_analysis", {})
    url_score = url_result.get("risk_score", 0)
    total_urls = url_result.get("total_urls", 0)
    suspicious = url_result.get("suspicious_count", 0)
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"  {BOLD}URL ANALYSIS{RESET}  {_bar(url_score)}")
    print(f"  URLs found: {total_urls}  |  Suspicious: {suspicious}")

    for url_info in url_result.get("urls", []):
        risk = url_info["risk_level"]
        rc = RED if risk == "high" else YELLOW if risk == "medium" else GREEN
        print(f"  {rc}[{risk.upper()}]{RESET} {url_info['url']}")
        for finding in url_info.get("findings", []):
            print(f"    {DIM}→ {finding}{RESET}")

    # Content analysis (LLM)
    content = result.get("content_analysis", {})
    phish_prob = content.get("phishing_probability", 0)
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"  {BOLD}CONTENT ANALYSIS{RESET}  {_bar(phish_prob)}")
    print(f"  Model: {content.get('model_used', 'N/A')}")
    print(f"  Confidence: {content.get('confidence', 0)}%")
    print(f"  Target type: {content.get('target_type', 'N/A')}")

    tactics = content.get("tactics_detected", [])
    if tactics:
        print(f"  Tactics detected:")
        for t in tactics:
            print(f"    {YELLOW}→{RESET} {t}")

    reasoning = content.get("reasoning", "")
    if reasoning:
        print(f"  {DIM}Reasoning: {reasoning}{RESET}")

    # MITRE ATT&CK mapping
    mitre = result.get("mitre", {})
    if mitre and mitre.get("id"):
        print(f"\n{BOLD}{'─' * 60}{RESET}")
        print(f"  {BOLD}MITRE ATT&CK{RESET}")
        print(f"  Technique: {mitre['id']} — {mitre['name']}")
        print(f"  Tactic:    {mitre['tactic']}")
        print(f"  Reference: {mitre['url']}")

    # All red flags summary
    all_flags = result.get("red_flags", [])
    if all_flags:
        print(f"\n{BOLD}{'─' * 60}{RESET}")
        print(f"  {BOLD}{RED}RED FLAGS ({len(all_flags)}){RESET}")
        for i, flag in enumerate(all_flags, 1):
            print(f"  {RED}{i}.{RESET} {flag}")

    print(f"\n{BOLD}{'═' * 60}{RESET}\n")


def export_json(result: dict, filepath: str) -> None:
    """Export analysis result to a JSON file.

    Args:
        result: Combined analysis dict.
        filepath: Output file path.
    """
    with open(filepath, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"{GREEN}Report exported to {filepath}{RESET}")


def get_mitre_mapping(target_type: str) -> dict:
    """Get MITRE ATT&CK technique for the detected phishing type.

    Args:
        target_type: The phishing target type from LLM analysis.

    Returns:
        Dict with id, name, tactic, url. Empty strings if no match.
    """
    return MITRE_TECHNIQUES.get(target_type, {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    })


if __name__ == "__main__":
    # Demo with fake result
    demo_result = {
        "overall_risk": 82,
        "verdict": "PHISHING",
        "header_analysis": {
            "headers": {
                "from": "PayPal Security <scammer@evil.com>",
                "to": "victim@example.com",
                "subject": "Your account has been suspended",
                "date": "Mon, 30 Mar 2026 10:00:00 +0000",
            },
            "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            "red_flags": [
                "Display name contains 'paypal' but sender is evil.com",
                "SPF check FAILED",
            ],
            "risk_score": 75,
        },
        "url_analysis": {
            "urls": [
                {
                    "url": "http://paypa1.com/verify",
                    "domain": "paypa1.com",
                    "risk_level": "high",
                    "findings": ["Known bad domain", "Suspicious path: 'verify'"],
                    "risk_score": 80,
                },
            ],
            "total_urls": 1,
            "suspicious_count": 1,
            "risk_score": 80,
        },
        "content_analysis": {
            "phishing_probability": 90,
            "verdict": "Phishing",
            "tactics_detected": ["Urgency", "Authority impersonation", "Credential request"],
            "reasoning": "Email impersonates PayPal and demands immediate action.",
            "confidence": 95,
            "target_type": "Credential Harvesting",
            "model_used": "heuristic (offline)",
        },
        "mitre": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/002/",
        },
        "red_flags": [
            "Display name contains 'paypal' but sender is evil.com",
            "SPF check FAILED",
            "Known bad domain: paypa1.com",
            "Urgency tactics detected",
        ],
    }

    print_report(demo_result)
