# Cybersecurity Portfolio

A collection of cybersecurity tools and projects demonstrating offensive security concepts, network analysis, AI-driven threat detection, and defensive security.

## Projects

### Local-AI-SOC
An AI-powered Security Operations Center that uses locally-hosted LLMs (Ollama + Llama 3.1) to triage SIEM alerts in real-time. Features **structured JSON output** from the LLM, **SQLite persistence**, **MITRE ATT&CK technique mapping**, **threat intelligence enrichment** (AbuseIPDB + local threat feed), a live web dashboard (localhost:5050), and a **Streamlit analytics dashboard** with charts, filters, and MITRE heatmaps. All inference runs locally with zero data exfiltration.

**Tech:** Python, Ollama, Llama 3.1 8B, SQLite, Streamlit, Plotly

**Key files:**
- `triage_agent.py` — LLM orchestration with structured JSON output, validation, and retry
- `database.py` — SQLite backend with alerts, MITRE, and enrichment columns
- `soc_dashboard.py` — Streamlit analytics dashboard (metrics, charts, MITRE heatmap)
- `mitre_mapping.py` — Local MITRE ATT&CK technique lookup (9 techniques)
- `threat_intel.py` — Threat intelligence enrichment (AbuseIPDB + local feed)
- `config.py` — Environment-based configuration with .env support
- `log_watcher.py` — Real-time log file monitor with dashboard callback
- `simulate_attack.py` — Severity-weighted attack generator (6 attack types)
- `dashboard.py` — Live web dashboard served at localhost:5050

### Port Scanner Suite
The same concurrent TCP port scanner implemented in **4 languages** to compare concurrency models, performance, and developer experience:

| Language | Concurrency Model | Key Feature |
|----------|-------------------|-------------|
| **Python** | ThreadPoolExecutor | Comma-separated port lists, banner grabbing |
| **C** | pthreads + select() | Nonblocking sockets, minimal overhead |
| **Go** | Goroutines + channels | Worker pool, dual-phase banner detection |
| **Rust** | tokio async + Semaphore | Zero-cost abstractions, memory safety |

Each implementation progresses through 4 versions: basic scanning > concurrency > CLI interface > service banner grabbing.

### Packet Sniffer (Rust)
A CLI network packet sniffer built in Rust using the `pnet` crate. Captures and parses TCP, UDP, ICMP, ARP, IPv4, and IPv6 packets with protocol/port filtering, hex dump mode, color-coded output, interface listing, and packet count limits. Requires root/sudo for packet capture.

**Tech:** Rust, pnet, clap, chrono, colored

### Password Cracker (Python)
An educational password cracking tool supporting dictionary attacks and brute-force with rule-based mutations (leet speak, capitalization, number/symbol append). Supports MD5, SHA1, SHA256, SHA512. Includes 100 built-in common passwords, hash type auto-identification, and both interactive and CLI modes. Pure Python, no external deps.

### Keylogger Detector (Python)
A Linux security scanner that runs 8 checks: input device listeners, known keylogger process signatures, suspicious scripts accessing /dev/input, LD_PRELOAD hijacking, suspicious kernel modules, /dev/input permissions, cron/startup persistence, and keystroke log file detection. Includes safe-lists for Snap/Firefox and GNOME to avoid false positives. Requires sudo for full scan.

## Why Multiple Languages?

The port scanner suite isn't about finding the "best" language — it's about understanding trade-offs:
- **Python** is fastest to write but slowest to run
- **C** gives maximum control but requires manual memory management
- **Go** hits the sweet spot of simplicity and performance
- **Rust** enforces safety at compile time with zero runtime cost

## License

MIT
