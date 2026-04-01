# Cybersecurity Portfolio

A collection of cybersecurity tools and projects demonstrating offensive security concepts, network analysis, AI-driven threat detection, and defensive security.

## Projects

### Local-AI-SOC
An AI-powered Security Operations Center that uses locally-hosted LLMs (Ollama + Llama 3.1) to triage SIEM alerts in real-time. Features **structured JSON output**, **SQLite persistence**, **MITRE ATT&CK mapping**, **threat intelligence enrichment**, **alert correlation engine** (kill chain detection, brute force grouping, frequency anomaly), **automated response suggestions**, and a **Streamlit analytics dashboard** with Incidents tab, response playbooks, and MITRE heatmaps. Includes an advanced attack simulator with 27 attack types across all MITRE tactics.

**Tech:** Python, Ollama, Llama 3.1 8B, SQLite, Streamlit, Plotly

**Key files:**
- `triage_agent.py` — LLM orchestration with structured JSON, validation, correlation context injection
- `correlator.py` — Alert correlation engine (sliding window, kill chain, brute force, frequency anomaly)
- `response_engine.py` — Automated response suggestions mapped to attack categories with severity escalation
- `database.py` — SQLite backend with alerts, responses, MITRE, enrichment, and correlation columns
- `soc_dashboard.py` — Streamlit dashboard (Alerts + Incidents tabs, response suggestion cards)
- `simulate_attack.py` — Advanced attack simulator (27 types, 3 attack chains, configurable rates)
- `mitre_mapping.py` — Local MITRE ATT&CK technique lookup
- `threat_intel.py` — Threat intelligence enrichment (AbuseIPDB + local feed)
- `log_watcher.py` — Real-time log monitor with correlation and response output

### Phishing Email Analyzer
An AI-powered phishing detection tool combining email header validation (SPF/DKIM/DMARC), URL reputation scanning with homograph attack detection, and LLM-based content analysis. Produces colored terminal reports with risk scores and MITRE ATT&CK mapping. Includes 6 sample .eml files (2 legitimate, 4 phishing) and an offline heuristic fallback.

**Tech:** Python, Ollama, email module, requests

### SSH Honeypot with Analytics
A fake SSH server that captures connection attempts, credentials, and attacker commands. Features IP geolocation, credential reuse detection, automated attack pattern analysis, rate limiting, and a Streamlit real-time analytics dashboard with country charts, heatmaps, and attacker drill-down.

**Tech:** Python, socket, threading, SQLite, Streamlit, Plotly

### Network Traffic Anomaly Detector
A statistical anomaly detection engine for network traffic. Builds behavioral baselines using z-scores and flags deviations without machine learning. Detects port scans, C2 beaconing, data exfiltration, DNS tunneling, and lateral movement. Includes traffic simulator with labeled anomalies and Streamlit dashboard.

**Tech:** Python, pandas, Streamlit, Plotly, SQLite

### Port Scanner Suite
The same concurrent TCP port scanner implemented in **4 languages** to compare concurrency models, performance, and developer experience:

| Language | Concurrency Model | Key Feature |
|----------|-------------------|-------------|
| **Python** | ThreadPoolExecutor | Comma-separated port lists, banner grabbing |
| **C** | pthreads + select() | Nonblocking sockets, minimal overhead |
| **Go** | Goroutines + channels | Worker pool, dual-phase banner detection |
| **Rust** | tokio async + Semaphore | Zero-cost abstractions, memory safety |

### Port Scanner Benchmark Suite
Cross-language benchmark tool that auto-compiles and runs all 4 port scanner implementations, measures scan time across multiple runs, and generates comparative analysis reports with tradeoff discussion.

**Tech:** Python (subprocess, time, statistics)

### Packet Sniffer (Rust)
A CLI network packet sniffer built in Rust using the `pnet` crate. Captures and parses TCP, UDP, ICMP, ARP, IPv4, and IPv6 packets with protocol/port filtering, hex dump mode, color-coded output, and packet count limits.

**Tech:** Rust, pnet, clap, chrono, colored

### Password Cracker (Python)
An educational password cracking tool supporting dictionary attacks and brute-force with rule-based mutations (leet speak, capitalization, number/symbol append). Supports MD5, SHA1, SHA256, SHA512.

### Keylogger Detector (Python)
A Linux security scanner with 8 detection checks for keyloggers including process signatures, LD_PRELOAD hijacking, kernel modules, and persistence mechanisms.

## Project Count: 10

| Category | Projects |
|----------|----------|
| AI-Powered Security | AI-SOC, Phishing Analyzer |
| Network Security | Packet Sniffer, Anomaly Detector, Honeypot |
| Offensive Tools | Port Scanners (4 langs), Password Cracker, Benchmark Suite |
| Defensive Tools | Keylogger Detector |

## License

MIT
