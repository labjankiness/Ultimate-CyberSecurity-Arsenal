"""
URL extraction and reputation analysis for phishing detection.

Extracts URLs from email bodies (HTML and plain text), checks for
deceptive patterns, homograph attacks, and known-bad domains.

Usage:
    from url_scanner import scan_urls
    results = scan_urls(email_body_text, email_body_html)
"""

import os
import re
import json
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlparse


# Known malicious/phishing domains (local reputation list)
KNOWN_BAD_DOMAINS = {
    # Generic phishing domains
    "secure-login-update.com", "account-verify-now.com", "login-security-alert.com",
    "verify-your-identity.net", "update-billing-info.com", "confirm-account-now.org",
    "reset-password-secure.com", "urgent-action-required.net", "paypa1.com",
    "amaz0n-login.com", "micros0ft-update.com", "g00gle-verify.com",
    # URL shortener abuse
    "bit.do", "t.ly", "is.gd", "v.gd", "qr.ae",
    # Known phishing infrastructure
    "evil-domain.com", "phish.net", "steal-creds.com", "fake-bank.com",
    "credential-harvest.com", "malware-download.com", "c2-server.net",
    "botnet-control.com", "ransomware-pay.com", "crypto-scam.com",
    # Typosquatting examples
    "paypa1.com", "arnazon.com", "micr0soft.com", "faceb00k.com",
    "lnstagram.com", "linkedln.com", "g0ogle.com", "app1e.com",
    "netf1ix.com", "chasebank-login.com", "wellsfarg0.com",
    # Recently registered suspicious TLDs
    "free-iphone.xyz", "winner-prize.top", "urgent-update.club",
    "security-alert.buzz", "verify-now.click", "login-here.info",
    "reset-account.site", "update-payment.online", "confirm-id.space",
    "billing-update.store",
}

# URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "db.tt",
    "qr.ae", "u.to", "cutt.ly", "rebrand.ly", "bl.ink", "short.io",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".buzz", ".click", ".info", ".site",
    ".online", ".space", ".store", ".fun", ".icu", ".work", ".loan",
    ".racing", ".download", ".win", ".bid", ".stream", ".gdn",
}

# Unicode homograph characters that look like ASCII
HOMOGRAPH_MAP = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
}


class _LinkExtractor(HTMLParser):
    """HTML parser that extracts href values and their display text."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, display_text)
        self._current_href: Optional[str] = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self._current_href = value
                    self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            display = "".join(self._current_text).strip()
            self.links.append((self._current_href, display))
            self._current_href = None
            self._current_text = []


def _extract_urls_text(text: str) -> list[str]:
    """Extract URLs from plain text using regex."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+|'
        r'www\.[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def _extract_urls_html(html: str) -> list[tuple[str, str]]:
    """Extract URLs and display text from HTML content."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.links


def _check_homograph(domain: str) -> Optional[str]:
    """Check if a domain contains unicode homograph characters."""
    for char, ascii_equiv in HOMOGRAPH_MAP.items():
        if char in domain:
            clean = domain
            for c, a in HOMOGRAPH_MAP.items():
                clean = clean.replace(c, a)
            return f"Homograph attack: '{domain}' contains unicode characters resembling '{clean}'"
    return None


def _check_display_mismatch(href: str, display_text: str) -> Optional[str]:
    """Check if link display text shows a different domain than the actual href."""
    if not display_text:
        return None

    # Check if display text looks like a URL
    display_urls = re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_text)
    if not display_urls:
        return None

    display_domain = display_urls[0].lower()
    try:
        href_domain = urlparse(href).netloc.lower()
    except Exception:
        return None

    if display_domain and href_domain and display_domain not in href_domain:
        return (
            f"Display text shows '{display_domain}' but link goes to "
            f"'{href_domain}' — possible deceptive link"
        )
    return None


def _analyze_url(url: str, display_text: str = "") -> dict:
    """Analyze a single URL for phishing indicators.

    Args:
        url: The URL to analyze.
        display_text: The display text for this link (from HTML).

    Returns:
        Dict with: url, domain, risk_level, findings (list), risk_score.
    """
    findings: list[str] = []
    risk_score = 0

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc.lower()
    except Exception:
        return {
            "url": url,
            "domain": "parse_error",
            "risk_level": "high",
            "findings": ["Failed to parse URL"],
            "risk_score": 50,
        }

    # Check known bad domains
    base_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain
    if base_domain in KNOWN_BAD_DOMAINS or domain in KNOWN_BAD_DOMAINS:
        findings.append(f"Domain '{domain}' is on the known-bad list")
        risk_score += 40

    # Check URL shortener
    if base_domain in URL_SHORTENERS:
        findings.append(f"URL shortener detected: {base_domain} (hides actual destination)")
        risk_score += 15

    # Check suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append(f"Suspicious TLD: {tld}")
            risk_score += 10
            break

    # Check IP-based URL
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
        findings.append("IP address used instead of domain name")
        risk_score += 25

    # Check homograph attack
    homograph = _check_homograph(domain)
    if homograph:
        findings.append(homograph)
        risk_score += 35

    # Check display text mismatch
    mismatch = _check_display_mismatch(url, display_text)
    if mismatch:
        findings.append(mismatch)
        risk_score += 30

    # Check for credential-harvesting path patterns
    path = parsed.path.lower()
    sus_paths = ["login", "signin", "verify", "confirm", "secure", "update", "reset", "account"]
    for pattern in sus_paths:
        if pattern in path:
            findings.append(f"Suspicious path keyword: '{pattern}'")
            risk_score += 5
            break

    # Check for data URI
    if url.startswith("data:"):
        findings.append("Data URI detected — can embed malicious content")
        risk_score += 30

    risk_score = min(risk_score, 100)
    if risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "url": url,
        "domain": domain,
        "risk_level": risk_level,
        "findings": findings,
        "risk_score": risk_score,
    }


def scan_urls(plain_text: str = "", html_text: str = "") -> dict:
    """Scan all URLs found in an email for phishing indicators.

    Args:
        plain_text: Plain text email body.
        html_text: HTML email body.

    Returns:
        Dict with: urls (list of analysis dicts), total_urls, suspicious_count,
        red_flags (aggregated), risk_score (0-100 URL contribution).
    """
    all_urls: dict[str, str] = {}  # url -> display_text

    # Extract from plain text
    for url in _extract_urls_text(plain_text):
        if url not in all_urls:
            all_urls[url] = ""

    # Extract from HTML (with display text)
    for href, display in _extract_urls_html(html_text):
        if href.startswith("mailto:") or href.startswith("#"):
            continue
        if href not in all_urls:
            all_urls[href] = display
        elif display and not all_urls[href]:
            all_urls[href] = display

    # Analyze each URL
    url_results = []
    red_flags: list[str] = []
    max_risk = 0

    for url, display in all_urls.items():
        analysis = _analyze_url(url, display)
        url_results.append(analysis)
        red_flags.extend(analysis["findings"])
        max_risk = max(max_risk, analysis["risk_score"])

    suspicious_count = sum(1 for u in url_results if u["risk_level"] in ("high", "medium"))

    # Overall URL risk: weighted by worst URL and count
    risk_score = max_risk
    if suspicious_count > 1:
        risk_score = min(risk_score + suspicious_count * 5, 100)

    return {
        "urls": url_results,
        "total_urls": len(url_results),
        "suspicious_count": suspicious_count,
        "red_flags": red_flags,
        "risk_score": risk_score,
    }


if __name__ == "__main__":
    test_html = """
    <html><body>
    <p>Click <a href="http://paypa1.com/login/verify">PayPal.com</a> to verify your account.</p>
    <p>Or visit <a href="https://bit.ly/abc123">this secure link</a>.</p>
    <p>Normal link: <a href="https://example.com">Example</a></p>
    </body></html>
    """

    test_text = "Visit http://192.168.1.1/admin/login or https://evil-domain.com/reset-password"

    result = scan_urls(plain_text=test_text, html_text=test_html)
    print("=== URL Scan Results ===")
    print(f"Total URLs: {result['total_urls']}")
    print(f"Suspicious: {result['suspicious_count']}")
    print(f"URL Risk Score: {result['risk_score']}/100")
    print()
    for url_info in result["urls"]:
        print(f"  [{url_info['risk_level'].upper()}] {url_info['url']}")
        for finding in url_info["findings"]:
            print(f"    [!] {finding}")
