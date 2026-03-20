# AI-SOC: Autonomous SIEM Alert Triage Agent

An AI-powered Security Operations Center (SOC) assistant that uses a locally hosted LLM to triage security alerts in real time — reducing alert fatigue by automating first-pass investigation of SIEM log data. Features **structured JSON output**, **SQLite persistence**, **MITRE ATT&CK mapping**, **threat intelligence enrichment**, and both a live web dashboard and a Streamlit analytics dashboard.

> **The Problem:** SOC analysts spend ~80% of their time investigating false positives. This project builds an autonomous triage agent that sits between raw security logs and the analyst, providing instant threat classification, severity scoring, IOC extraction, MITRE technique mapping, and remediation guidance.

---

## Demo

```
[*] Monitoring mock_security.log for threats...
[*] Alerts stored in soc_alerts.db

[!] New Alert Detected. Consulting AI...
[+] Alert #12 stored in database.
    Verdict:  True Positive
    Severity: 8/10 [CRITICAL]
    Category: SSH Brute Force
    Summary:  Brute-force SSH login attempt targeting root from external IP
              203.0.113.5. Multiple failed authentication attempts detected.
```

---

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  simulate_attack  │────>│   log_watcher    │────>│   triage_agent   │
│  (Log Generator)  │     │  (File Monitor)  │     │ (LLM via Ollama) │
└──────────────────┘     └────────┬─────────┘     └────────┬─────────┘
                                  │                         │
                          ┌───────┴───────┐         ┌───────┴───────┐
                          │               │         │               │
                          v               v         v               v
                   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
                   │ dashboard  │  │ soc_dash   │  │  mitre     │  │threat_intel│
                   │ (HTTP:5050)│  │ (Streamlit)│  │  mapping   │  │(enrichment)│
                   └────────────┘  └────────────┘  └────────────┘  └────────────┘
                                          │
                                          v
                                   ┌────────────┐
                                   │  database  │
                                   │  (SQLite)  │
                                   └────────────┘
```

1. **Ingestion** — `log_watcher.py` tail-follows a log file for new entries.
2. **Enrichment** — `threat_intel.py` checks IOCs against local threat feed and AbuseIPDB (optional).
3. **Inference** — `triage_agent.py` sends the enriched log to Ollama, forcing structured JSON output with validation and retry.
4. **MITRE Mapping** — `mitre_mapping.py` tags each alert with the corresponding ATT&CK technique ID and tactic.
5. **Storage** — `database.py` persists everything in SQLite (`soc_alerts.db`).
6. **Dashboards** — Live HTTP dashboard at `:5050` and Streamlit analytics dashboard with charts, filters, and MITRE heatmap.

---

## Why Local LLM?

This project uses **Ollama** to run inference entirely on-device. Security logs contain sensitive internal data (IPs, usernames, system paths) that should never leave the local network. Running Llama 3.1 locally means:

- **Zero data exfiltration risk** — no API calls to external services
- **Context-aware reasoning** — the LLM distinguishes between a mistyped password and a brute-force campaign, unlike regex-based rules
- **Low latency** — responses in seconds on consumer GPU hardware

---

## Project Structure

```
Local-AI-SOC/
├── triage_agent.py        # LLM orchestration — structured JSON output with validation
├── log_watcher.py         # Real-time log monitor → SQLite + dashboards
├── simulate_attack.py     # Severity-weighted attack generator (6 attack types)
├── dashboard.py           # Live web dashboard (localhost:5050)
├── soc_dashboard.py       # Streamlit analytics dashboard with charts and filters
├── database.py            # SQLite backend (alerts table with MITRE + enrichment columns)
├── mitre_mapping.py       # Local MITRE ATT&CK technique lookup (9 techniques)
├── threat_intel.py        # Threat intel enrichment (AbuseIPDB + local feed)
├── config.py              # Environment-based configuration (.env support)
├── known_threats.json     # Local threat feed (20 IPs, 10 user agents, 10 signatures)
├── .env.example           # Template for API keys and settings
├── .gitignore             # Excludes .env, database, logs, pycache
├── requirements.txt       # Dependencies: requests, streamlit, plotly, pandas
└── README.md
```

---

## Features

### Structured JSON Triage
The LLM returns validated JSON for every alert:
```json
{
  "verdict": "True Positive",
  "threat_level": 8,
  "category": "SSH Brute Force",
  "summary": "Brute-force SSH login attempt targeting root.",
  "remediation": "Block source IP at firewall, enforce key-based auth.",
  "iocs": { "source_ip": "203.0.113.5", "username": "root", "command": null }
}
```

### MITRE ATT&CK Mapping
Every alert is tagged with the corresponding MITRE technique:

| Category | Technique | Tactic |
|:---|:---|:---|
| SSH Brute Force | T1110.001 — Password Guessing | Credential Access |
| Privilege Escalation | T1548.003 — Sudo Abuse | Privilege Escalation |
| SQL Injection | T1190 — Exploit Public-Facing App | Initial Access |
| Port Scan | T1046 — Network Service Scanning | Discovery |
| Rogue USB | T1091 — Removable Media | Lateral Movement |
| Reconnaissance | T1595 — Active Scanning | Reconnaissance |

### Threat Intelligence Enrichment
- **Local threat feed** (always available offline): 20 known-malicious IPs, 10 attack signatures
- **AbuseIPDB** (optional, free tier): IP reputation scores, abuse confidence, report counts
- Enrichment context is injected into the LLM prompt for better-informed verdicts

### Streamlit Analytics Dashboard
Run `streamlit run soc_dashboard.py` for:
- Metric cards (Total Alerts, True Positives, False Positives, Avg Threat Level)
- Threat level distribution bar chart (color-coded by severity)
- Category breakdown donut chart
- Alerts-over-time area chart
- MITRE ATT&CK technique treemap heatmap
- Filterable alert feed with expandable details (IOCs, MITRE info, remediation)
- Sidebar filters: threat level, verdict, category, IP search
- Auto-refresh toggle (5-second polling)

---

## Prerequisites

- **Python** 3.10+
- **Ollama** — [Install here](https://ollama.com/)
- **Hardware** — Any machine with 8GB+ RAM. A dedicated GPU significantly improves inference speed but is not required.

```bash
ollama pull llama3.1:8b
pip install -r requirements.txt
```

Optional — copy `.env.example` to `.env` and add your AbuseIPDB API key for threat intel enrichment.

---

## Quick Start

**Terminal 1 — Start the attack simulator:**
```bash
python simulate_attack.py
```

**Terminal 2 — Start the log watcher:**
```bash
python log_watcher.py
```

**Terminal 3 (optional) — Start the Streamlit dashboard:**
```bash
streamlit run soc_dashboard.py
```

The live web dashboard also starts automatically at `http://localhost:5050` when running `log_watcher.py`.

---

## Simulated Attack Types

| Attack | Severity | Example Log Entry |
|:---|:---|:---|
| SSH Brute Force | High | `sshd: Failed password for invalid user admin from 203.0.113.5` |
| Privilege Escalation | High | `sudo: ryan : USER=root ; COMMAND=/usr/bin/cat /etc/shadow` |
| SQL Injection | High | `nginx: GET /admin.php?id=1' OR '1'='1' HTTP/1.1` |
| Port Scan | Medium | `iptables: SYN flood detected from 10.0.0.99` |
| Rogue USB Device | Medium | `kernel: usb 1-1: New USB device found (Rubber Ducky?)` |
| Failed sudo | Low | `sudo: pam_unix: auth failure; user=intern` |

---

## Tech Stack

| Component | Technology |
|:---|:---|
| Language | Python 3.10+ |
| AI Engine | [Ollama](https://ollama.com/) — Llama 3.1 8B |
| Database | SQLite (soc_alerts.db) |
| Dashboards | Built-in HTTP server + Streamlit + Plotly |
| Threat Intel | AbuseIPDB (optional) + local threat feed |
| Framework | MITRE ATT&CK technique mapping |

---

## License

This project is open source under the [MIT License](LICENSE).
