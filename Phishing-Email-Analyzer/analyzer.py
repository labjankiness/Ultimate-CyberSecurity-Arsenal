"""
Phishing Email Analyzer — Main orchestrator.

Accepts an .eml file or raw email text and runs it through the full
analysis pipeline: header parsing, URL scanning, LLM content analysis,
and report generation.

Usage:
    python analyzer.py --email sample_emails/phishing_invoice.eml
    python analyzer.py --email sample_emails/phishing_invoice.eml --json report.json
    python analyzer.py --email sample_emails/phishing_invoice.eml --offline
"""

import argparse
import json
import sys
from email import policy
from email.parser import BytesParser, Parser
from email.message import Message
from typing import Optional

from header_parser import parse_headers
from url_scanner import scan_urls
from llm_analyzer import analyze_content, analyze_content_offline
from report_generator import print_report, export_json, get_mitre_mapping


def _extract_body(msg: Message) -> tuple[str, str]:
    """Extract plain text and HTML body from an email message.

    Handles MIME multipart messages by walking all parts.

    Args:
        msg: Parsed email Message object.

    Returns:
        Tuple of (plain_text, html_text).
    """
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if content_type == "text/plain" and not plain_text:
                plain_text = text
            elif content_type == "text/html" and not html_text:
                html_text = text
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    html_text = text
                else:
                    plain_text = text
        except Exception:
            plain_text = str(msg.get_payload())

    return plain_text, html_text


def _compute_overall_risk(
    header_score: int,
    url_score: int,
    content_score: int,
) -> int:
    """Compute weighted overall risk score.

    Weights: content analysis 40%, URL analysis 35%, header analysis 25%.
    """
    weighted = (content_score * 0.40) + (url_score * 0.35) + (header_score * 0.25)
    return min(int(weighted), 100)


def _determine_verdict(overall_risk: int) -> str:
    """Map overall risk to a human-readable verdict."""
    if overall_risk >= 70:
        return "PHISHING"
    elif overall_risk >= 40:
        return "SUSPICIOUS"
    else:
        return "LEGITIMATE"


def analyze_email(
    msg: Message,
    use_llm: bool = True,
) -> dict:
    """Run the full analysis pipeline on a parsed email message.

    Args:
        msg: Parsed email Message object.
        use_llm: If True, use Ollama LLM. If False, use offline heuristics.

    Returns:
        Combined analysis dict with overall_risk, verdict, and all
        sub-analysis results.
    """
    # Step 1: Header analysis
    header_result = parse_headers(msg)

    # Step 2: Extract body content
    plain_text, html_text = _extract_body(msg)
    subject = msg.get("Subject", "")

    # Step 3: URL scanning
    url_result = scan_urls(plain_text=plain_text, html_text=html_text)

    # Step 4: Content analysis
    body_for_analysis = plain_text or html_text
    if use_llm:
        content_result = analyze_content(subject, body_for_analysis)
    else:
        content_result = analyze_content_offline(subject, body_for_analysis)

    # Step 5: Compute overall risk
    overall_risk = _compute_overall_risk(
        header_result["risk_score"],
        url_result["risk_score"],
        content_result["phishing_probability"],
    )
    verdict = _determine_verdict(overall_risk)

    # Step 6: MITRE mapping
    target_type = content_result.get("target_type", "Unknown")
    mitre = get_mitre_mapping(target_type) if verdict != "LEGITIMATE" else {
        "id": "", "name": "", "tactic": "", "url": ""
    }

    # Aggregate all red flags
    all_flags = []
    all_flags.extend(header_result.get("red_flags", []))
    all_flags.extend(url_result.get("red_flags", []))
    for tactic in content_result.get("tactics_detected", []):
        all_flags.append(f"Content tactic: {tactic}")

    return {
        "overall_risk": overall_risk,
        "verdict": verdict,
        "header_analysis": header_result,
        "url_analysis": url_result,
        "content_analysis": content_result,
        "mitre": mitre,
        "red_flags": all_flags,
        "email_subject": subject,
        "body_preview": body_for_analysis[:200] if body_for_analysis else "",
    }


def analyze_file(filepath: str, use_llm: bool = True) -> dict:
    """Analyze an .eml file.

    Args:
        filepath: Path to the .eml file.
        use_llm: If True, use Ollama LLM for content analysis.

    Returns:
        Combined analysis dict.
    """
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return analyze_email(msg, use_llm=use_llm)


def analyze_text(raw_email: str, use_llm: bool = True) -> dict:
    """Analyze raw email text.

    Args:
        raw_email: Raw email string including headers.
        use_llm: If True, use Ollama LLM for content analysis.

    Returns:
        Combined analysis dict.
    """
    msg = Parser(policy=policy.default).parsestr(raw_email)
    return analyze_email(msg, use_llm=use_llm)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer — Detect phishing with AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python analyzer.py --email sample_emails/phishing_invoice.eml
  python analyzer.py --email sample_emails/phishing_invoice.eml --offline
  python analyzer.py --email sample_emails/phishing_invoice.eml --json report.json
""",
    )
    parser.add_argument(
        "--email", "-e", required=True,
        help="Path to .eml file to analyze",
    )
    parser.add_argument(
        "--json", "-j", default=None,
        help="Export results to JSON file",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Use offline heuristics instead of LLM",
    )

    args = parser.parse_args()

    try:
        result = analyze_file(args.email, use_llm=not args.offline)
    except FileNotFoundError:
        print(f"Error: File not found: {args.email}")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing email: {e}")
        sys.exit(1)

    print_report(result)

    if args.json:
        export_json(result, args.json)


if __name__ == "__main__":
    main()
