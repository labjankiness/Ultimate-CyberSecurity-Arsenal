# AI-SOC: Autonomous SIEM Alert Triage Agent

An AI-powered Security Operations Center (SOC) assistant that uses a locally hosted LLM to triage security alerts in real time — reducing alert fatigue by automating first-pass investigation of SIEM log data. Includes a **live web dashboard** for monitoring alerts in the browser.

> **The Problem:** SOC analysts spend ~80% of their time investigating false positives. This project builds an autonomous triage agent that sits between raw security logs and the analyst, providing instant threat classification, severity scoring, and remediation guidance.

---

## Demo

```
[*] Monitoring mock_security.log for threats...
[*] Dashboard running at http://localhost:5050

[!] New Alert Detected. Consulting AI...

--- AI TRIAGE REPORT ---
VERDICT: True Positive
THREAT LEVEL: 8/10
SUMMARY: Brute-force SSH login attempt targeting the root account from an
         external IP. Multiple failed authentication attempts indicate
         credential stuffing or dictionary attack.
REMEDIATION: Block source IP 192.168.1.50 at the firewall and enforce
             key-based SSH authentication.
```

---

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  simulate_attack  │────>│   log_watcher    │────>│   triage_agent   │
│  (Log Generator)  │     │  (File Monitor)  │     │ (LLM via Ollama) │
└──────────────────┘     └────────┬─────────┘     └────────┬─────────┘
                                  │                         │
                                  v                         v
                         ┌──────────────────┐     ┌──────────────────┐
                         │    dashboard.py   │     │ threat_dashboard  │
                         │ (Web UI :5050)    │     │    (.md report)   │
                         └──────────────────┘     └──────────────────┘
```

1. **Ingestion** — `log_watcher.py` tail-follows a log file for new entries.
2. **Orchestration** — `triage_agent.py` extracts metadata (IP, user, command) and constructs a structured prompt.
3. **Inference** — A local Llama 3.1 model (via Ollama) analyzes intent using a Senior SOC Analyst system prompt.
4. **Reporting** — Results are appended to `threat_dashboard.md` and pushed to the live web dashboard.
5. **Dashboard** — `dashboard.py` serves a live-updating HTML dashboard at `http://localhost:5050` with alert cards, severity counts, and auto-refresh.

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
├── triage_agent.py        # Core LLM orchestration and prompt engineering
├── log_watcher.py         # Real-time log file monitor (with dashboard callback)
├── simulate_attack.py     # Severity-weighted attack generator (SSH, SQLi, privesc, USB)
├── dashboard.py           # Live web dashboard (localhost:5050)
├── requirements.txt       # Python dependency: requests
├── threat_dashboard.md    # Auto-generated triage report (created at runtime)
├── mock_security.log      # Simulated SIEM feed (created at runtime)
└── README.md
```

---

## Prerequisites

- **Python** 3.10+
- **Ollama** — [Install here](https://ollama.com/)
- **Hardware** — Any machine with 8GB+ RAM. A dedicated GPU (e.g., NVIDIA RTX series) significantly improves inference speed but is not required.

Pull the model:

```bash
ollama pull llama3.1:8b
```

Install the Python dependency:

```bash
pip install -r requirements.txt
```

---

## Quick Start

You'll need **two terminal windows** running simultaneously.

**Terminal 1 — Start the attack simulator:**

```bash
python simulate_attack.py
```

This writes severity-weighted synthetic alerts to `mock_security.log` at randomized intervals. Attack types include failed SSH logins (high), suspicious sudo commands (high), SQL injection attempts (high), port scans (medium), rogue USB devices (medium), and failed sudo attempts (low).

**Terminal 2 — Start the log watcher:**

```bash
python log_watcher.py
```

This tail-follows the log file, sends each new entry to the local LLM for analysis, and automatically starts the web dashboard at `http://localhost:5050`. Triage reports are printed to the console and appended to `threat_dashboard.md`.

---

## Web Dashboard

Open `http://localhost:5050` in your browser to see:
- **Total Alerts** count
- **Severity breakdown** (High / Medium / Low)
- **Alert cards** with timestamp, raw log, verdict, and severity badge
- **Auto-refresh** every 10 seconds

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

## Customization

**Swap the model** — Edit `MODEL` in `triage_agent.py`:

```python
MODEL = "llama3.1:8b"           # Default
MODEL = "mistral:7b"            # Alternative
MODEL = "mranv/siem-llama-3.1"  # Security-tuned variant
```

**Adjust alert frequency** — Change the sleep intervals in `simulate_attack.py`.

**Add custom attack patterns** — Extend the attack lists in `simulate_attack.py` with your own log formats and severity weights.

---

## Tech Stack

| Component | Technology |
|:---|:---|
| Language | Python 3.10+ |
| AI Engine | [Ollama](https://ollama.com/) — Llama 3.1 8B |
| Inference | Local GPU / CPU |
| Dashboard | Built-in Python HTTP server |
| Architecture | File-based log streaming with LLM orchestration |

---

## License

This project is open source under the [MIT License](LICENSE).
