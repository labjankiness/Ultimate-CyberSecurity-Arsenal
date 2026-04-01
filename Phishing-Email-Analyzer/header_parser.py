"""
Email header extraction and security validation.

Parses email headers to detect spoofing indicators, authentication
failures, and suspicious routing patterns.

Usage:
    from header_parser import parse_headers
    analysis = parse_headers(email_message)
"""

import re
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional


# Suspicious free email domains often used in phishing
SUSPICIOUS_SENDER_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "dispostable.com", "maildrop.cc",
}

# Legitimate domains often impersonated in phishing
COMMONLY_SPOOFED = {
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "irs.gov",
}


def _extract_domain(email_addr: str) -> str:
    """Extract the domain portion from an email address."""
    _, addr = parseaddr(email_addr)
    if "@" in addr:
        return addr.split("@")[1].lower()
    return ""


def _check_display_name_mismatch(from_header: str) -> Optional[str]:
    """Check if the display name contains a different domain than the actual address.

    Example: 'PayPal Security <attacker@evil.com>' — display mentions PayPal
    but actual address is from evil.com.
    """
    display_name, actual_addr = parseaddr(from_header)
    if not display_name or not actual_addr:
        return None

    actual_domain = _extract_domain(actual_addr)
    display_lower = display_name.lower()

    for legit in COMMONLY_SPOOFED:
        brand = legit.split(".")[0]
        if brand in display_lower and actual_domain != legit:
            return (
                f"Display name contains '{brand}' but actual sender domain "
                f"is '{actual_domain}' (expected '{legit}')"
            )
    return None


def _parse_received_chain(msg: Message) -> list[dict]:
    """Parse Received headers to trace the email routing path.

    Returns a list of hops with from/by/timestamp info, oldest first.
    """
    received_headers = msg.get_all("Received", [])
    hops = []
    for header in reversed(received_headers):  # Reverse: oldest first
        hop: dict = {"raw": header.strip()}
        # Extract 'from' and 'by' fields
        from_match = re.search(r"from\s+(\S+)", header, re.IGNORECASE)
        by_match = re.search(r"by\s+(\S+)", header, re.IGNORECASE)
        if from_match:
            hop["from"] = from_match.group(1)
        if by_match:
            hop["by"] = by_match.group(1)
        # Extract timestamp
        date_match = re.search(r";\s*(.+)$", header)
        if date_match:
            hop["date"] = date_match.group(1).strip()
        hops.append(hop)
    return hops


def _check_authentication(msg: Message) -> dict:
    """Check SPF, DKIM, and DMARC results from Authentication-Results header."""
    auth_header = msg.get("Authentication-Results", "")
    results = {
        "spf": "not found",
        "dkim": "not found",
        "dmarc": "not found",
        "raw": auth_header,
    }

    if not auth_header:
        return results

    auth_lower = auth_header.lower()
    for check in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{check}=(pass|fail|softfail|none|temperror|permerror)", auth_lower)
        if match:
            results[check] = match.group(1)

    return results


def parse_headers(msg: Message) -> dict:
    """Analyze email headers for phishing indicators.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        Dict with: headers (extracted values), authentication (SPF/DKIM/DMARC),
        routing (received chain), red_flags (list of findings),
        risk_score (0-100 header contribution).
    """
    red_flags: list[str] = []
    risk_score = 0

    # Extract key headers
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")
    date_str = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    to_header = msg.get("To", "")

    headers = {
        "from": from_header,
        "to": to_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "date": date_str,
        "message_id": message_id,
    }

    # Check display name mismatch
    mismatch = _check_display_name_mismatch(from_header)
    if mismatch:
        red_flags.append(mismatch)
        risk_score += 30

    # Check Reply-To differs from From
    if reply_to:
        from_domain = _extract_domain(from_header)
        reply_domain = _extract_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            red_flags.append(
                f"Reply-To domain '{reply_domain}' differs from "
                f"From domain '{from_domain}'"
            )
            risk_score += 20

    # Check Return-Path differs from From
    if return_path:
        from_domain = _extract_domain(from_header)
        return_domain = _extract_domain(return_path)
        if from_domain and return_domain and from_domain != return_domain:
            red_flags.append(
                f"Return-Path domain '{return_domain}' differs from "
                f"From domain '{from_domain}'"
            )
            risk_score += 15

    # Check for suspicious sender domain
    sender_domain = _extract_domain(from_header)
    if sender_domain in SUSPICIOUS_SENDER_DOMAINS:
        red_flags.append(f"Sender domain '{sender_domain}' is a known disposable email service")
        risk_score += 25

    # Check authentication results
    auth = _check_authentication(msg)
    if auth["spf"] == "fail":
        red_flags.append("SPF check FAILED — sender IP not authorized for this domain")
        risk_score += 25
    elif auth["spf"] == "softfail":
        red_flags.append("SPF softfail — sender IP may not be authorized")
        risk_score += 10

    if auth["dkim"] == "fail":
        red_flags.append("DKIM check FAILED — email signature invalid")
        risk_score += 25

    if auth["dmarc"] == "fail":
        red_flags.append("DMARC check FAILED — domain alignment failed")
        risk_score += 20

    # Check for missing Message-ID
    if not message_id:
        red_flags.append("Missing Message-ID header (common in automated phishing)")
        risk_score += 10

    # Parse routing chain
    routing = _parse_received_chain(msg)

    return {
        "headers": headers,
        "authentication": auth,
        "routing": routing,
        "red_flags": red_flags,
        "risk_score": min(risk_score, 100),
    }


if __name__ == "__main__":
    from email import message_from_string

    test_email = """From: PayPal Security <scammer@evil-domain.com>
Reply-To: collect@phish.net
To: victim@example.com
Subject: Your account has been suspended
Date: Mon, 30 Mar 2026 10:00:00 +0000
Message-ID: <abc123@evil-domain.com>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.evil-domain.com (1.2.3.4) by mx.example.com; Mon, 30 Mar 2026 10:00:00 +0000

Click here to restore your account."""

    msg = message_from_string(test_email)
    result = parse_headers(msg)
    print("=== Header Analysis ===")
    print(f"From: {result['headers']['from']}")
    print(f"Reply-To: {result['headers']['reply_to']}")
    print(f"Authentication: SPF={result['authentication']['spf']}, "
          f"DKIM={result['authentication']['dkim']}, DMARC={result['authentication']['dmarc']}")
    print(f"\nRed Flags ({len(result['red_flags'])}):")
    for flag in result["red_flags"]:
        print(f"  [!] {flag}")
    print(f"\nHeader Risk Score: {result['risk_score']}/100")
