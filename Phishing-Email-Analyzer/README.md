# Phishing Email Analyzer

An AI-powered phishing email detection tool that combines header analysis, URL scanning, and local LLM content analysis to identify phishing attempts. Uses Ollama with Llama 3.1 for privacy-first analysis — all processing happens locally.

## The Problem

Phishing remains the #1 attack vector, responsible for over 90% of data breaches. Traditional email filters catch bulk spam but miss targeted spear-phishing and business email compromise (BEC) attacks. This tool provides deep analysis that goes beyond simple pattern matching.

## Architecture

```
.eml file
    │
    ├── header_parser.py ──── SPF/DKIM/DMARC validation
    │                         Sender spoofing detection
    │                         Reply-To mismatch checks
    │
    ├── url_scanner.py ────── URL extraction (HTML + text)
    │                         Known-bad domain matching
    │                         Homograph attack detection
    │                         Display text mismatch detection
    │
    ├── llm_analyzer.py ───── Ollama (Llama 3.1) content analysis
    │                         Social engineering tactic detection
    │                         Phishing intent classification
    │                         Offline heuristic fallback
    │
    └── report_generator.py ─ Colored terminal report
                              JSON export
                              MITRE ATT&CK mapping
```

## Features

- **Header Analysis**: SPF, DKIM, DMARC validation; sender spoofing detection; Reply-To mismatch checks; routing path analysis
- **URL Scanning**: Extracts URLs from HTML and plain text; checks against 50+ known-bad domains; detects homograph attacks, URL shorteners, IP-based URLs, and deceptive display text
- **LLM Content Analysis**: Uses Ollama (Llama 3.1:8b) to detect urgency tactics, authority impersonation, credential requests, financial fraud patterns, and emotional manipulation
- **Offline Mode**: Built-in heuristic analyzer works without Ollama for environments without GPU
- **MITRE ATT&CK Mapping**: Maps findings to T1566 (Phishing) sub-techniques
- **Colored Reports**: Terminal output with risk scores, severity badges, and red flag summaries

## Setup

```bash
# Clone the repository
git clone https://github.com/labjankiness/CyberSecurity-Portfolio-WIP.git
cd CyberSecurity-Portfolio-WIP/Phishing-Email-Analyzer

# Install dependencies
pip install -r requirements.txt

# (Optional) Install Ollama for LLM analysis
# https://ollama.ai/download
ollama pull llama3.1:8b
```

## Usage

```bash
# Analyze a phishing email (with LLM)
python analyzer.py --email sample_emails/phishing_password_reset.eml

# Analyze without LLM (offline heuristics only)
python analyzer.py --email sample_emails/phishing_invoice.eml --offline

# Export results to JSON
python analyzer.py --email sample_emails/spear_phishing_ceo.eml --json report.json
```

## Demo Output

```
══════════════════════════════════════════════════════════════
  PHISHING EMAIL ANALYSIS REPORT
══════════════════════════════════════════════════════════════

  VERDICT:  PHISHING
  RISK:     ████████████████████████░░░░░░ 82/100
  SEVERITY: HIGH RISK

──────────────────────────────────────────────────────────────
  HEADER ANALYSIS  ██████████████████████░░░░░░░░ 75/100
  SPF: fail  |  DKIM: fail  |  DMARC: fail
  [!] Display name contains 'microsoft' but sender is micros0ft-update.com
  [!] Reply-To domain differs from From domain

──────────────────────────────────────────────────────────────
  URL ANALYSIS  ████████████████████████░░░░░░ 80/100
  URLs found: 1  |  Suspicious: 1
  [HIGH] http://micros0ft-update.com/password-reset/verify
    → Domain 'micros0ft-update.com' is on the known-bad list
    → Suspicious path keyword: 'verify'

──────────────────────────────────────────────────────────────
  CONTENT ANALYSIS  ███████████████████████████░░░ 90/100
  Tactics detected:
    → Urgency: 'expire'
    → Authority impersonation: 'security team'
    → Credential request: 'password'

──────────────────────────────────────────────────────────────
  MITRE ATT&CK
  Technique: T1566.002 — Phishing: Spearphishing Link
  Tactic:    Initial Access
══════════════════════════════════════════════════════════════
```

## Sample Emails

| File | Type | Techniques |
|------|------|------------|
| `legitimate_01.eml` | Legitimate | Normal business email |
| `legitimate_newsletter.eml` | Legitimate | Newsletter with unsubscribe |
| `phishing_password_reset.eml` | Phishing | Urgency + credential harvesting |
| `phishing_invoice.eml` | Phishing | Authority + financial fraud |
| `spear_phishing_ceo.eml` | Phishing | CEO fraud / BEC |
| `phishing_urgent_action.eml` | Phishing | Fear + account suspension |

## Adding Custom Detection Rules

**Bad domains**: Add entries to `KNOWN_BAD_DOMAINS` in `url_scanner.py`

**Header checks**: Add validation logic to `parse_headers()` in `header_parser.py`

**Content patterns**: Add keywords to the detection lists in `analyze_content_offline()` in `llm_analyzer.py`

## Tech Stack

- Python 3.10+ (standard library `email` module for MIME parsing)
- Ollama + Llama 3.1:8b (local LLM, optional)
- No external API calls required for core functionality
