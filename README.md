# Ultimate CyberSecurity Arsenal

A comprehensive collection of 16 cybersecurity tools and resources spanning AI-driven threat detection, network security, offensive tooling, defensive hardening, and CTF research.

## Projects

### AI & Threat Intelligence

| Project | Description | Tech |
|---------|-------------|------|
| [Local-AI-SOC](Local-AI-SOC/) | AI-powered Security Operations Center with real-time SIEM alert triage, MITRE ATT&CK mapping, alert correlation, and Streamlit dashboard | Python, Ollama, Llama 3.1, SQLite, Streamlit |
| [AI-Phishing-Sentinel](AI-Phishing-Sentinel/) | AI-powered phishing and social engineering detection with batch CSV processing and structured JSON reports | Python, Ollama, Llama 3 |
| [Phishing-Email-Analyzer](Phishing-Email-Analyzer/) | Email header validation (SPF/DKIM/DMARC), URL reputation scanning, homograph attack detection, and LLM content analysis | Python, Ollama |
| [Guardian-Log-Analyzer](Guardian-Log-Analyzer/) | AI-powered security log parser with SSH auth log analysis, SQLite persistence, and JSON export | Python, Ollama, Llama 2, SQLite |

### Network Security

| Project | Description | Tech |
|---------|-------------|------|
| [Network-Anomaly-Detector](Network-Anomaly-Detector/) | Statistical anomaly detection for network traffic using z-scores — detects port scans, C2 beaconing, DNS tunneling, and lateral movement | Python, pandas, Streamlit, SQLite |
| [IoT-Network-Honeypot](IoT-Network-Honeypot/) | Lightweight IoT honeypot monitoring attacks on common ports (80, 8080, 554, 23) with Streamlit visualization dashboard | Python, SQLite, Streamlit |
| [Honeypot](Honeypot/) | Fake SSH server capturing credentials, client banners, and commands with IP geolocation and attacker analytics | Python, socket, SQLite, Streamlit |
| [Network-Monitor](Network-Monitor/) | Real-time network traffic visualization with Flask backend | Python, Flask, psutil |
| [packet-sniffer](packet-sniffer/) | CLI network packet sniffer — captures and parses TCP, UDP, ICMP, ARP, IPv4, IPv6 with protocol filtering and hex dump | Rust, pnet, clap |

### Offensive Tools

| Project | Description | Tech |
|---------|-------------|------|
| Port Scanner Suite ([C](Port%20Scanner%20(C)/), [Go](Port%20Scanner%20(Go-Golang)/), [Python](Port%20Scanner%20(Python)/), [Rust](Port%20Scanner%20(Rust)/)) | Concurrent TCP port scanner in 4 languages comparing concurrency models and performance | C, Go, Python, Rust |
| [Port-Scanner-Benchmark](Port-Scanner-Benchmark/) | Cross-language benchmark tool — auto-compiles and compares all 4 scanner implementations | Python |
| [password-cracker](password-cracker/) | Dictionary + brute-force password cracker with rule-based mutations (leet speak, capitalization) supporting MD5/SHA1/SHA256/SHA512 | Python |

### Defensive Tools

| Project | Description | Tech |
|---------|-------------|------|
| [Linux-Hardening-Basics](Linux-Hardening-Basics/) | Automated Ubuntu/Debian hardening script — UFW firewall, Fail2Ban, SSH hardening, debloating, with audit mode | Bash |
| [keylogger-detector](keylogger-detector/) | Linux security scanner with 8 detection checks for keyloggers including process signatures, LD_PRELOAD hijacking, and kernel modules | Python |

### Research & Education

| Project | Description | Tech |
|---------|-------------|------|
| [CTF-Writeups-and-Security-Research](CTF-Writeups-and-Security-Research/) | Documented CTF challenge solutions and security research across Web, Forensics, Pwn, and Crypto categories | Markdown |

## Project Count: 16

| Category | Count | Projects |
|----------|-------|----------|
| AI & Threat Intelligence | 4 | AI-SOC, AI-Phishing-Sentinel, Phishing Analyzer, Guardian Log Analyzer |
| Network Security | 5 | Anomaly Detector, IoT Honeypot, SSH Honeypot, Network Monitor, Packet Sniffer |
| Offensive Tools | 3 | Port Scanner Suite (4 langs), Benchmark Suite, Password Cracker |
| Defensive Tools | 2 | Linux Hardening, Keylogger Detector |
| Research & Education | 1 | CTF Writeups |

## License

MIT
