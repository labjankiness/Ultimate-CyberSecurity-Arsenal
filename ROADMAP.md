# CyberSecurity Portfolio Development Roadmap

## Completed

### Local-AI-SOC
- [x] Core triage agent with Ollama + Llama 3.1 8B
- [x] Structured JSON output with validation and retry logic
- [x] SQLite persistence with alerts, enrichment, and correlation columns
- [x] MITRE ATT&CK technique mapping (9 techniques)
- [x] Threat intelligence enrichment (AbuseIPDB + local known_threats.json)
- [x] Streamlit analytics dashboard (metrics, charts, MITRE heatmap, filters)
- [x] Alert correlation engine (kill chain, brute force, frequency anomaly detection)
- [x] Automated response suggestions (category-mapped commands, severity escalation, incident playbook)
- [x] Dashboard Incidents tab with correlated alert groups
- [x] Advanced attack simulator (27 attack types across all MITRE ATT&CK tactics)
- [x] 3 scripted attack chains (External Compromise, Insider Threat, Web App Attack)
- [x] Real-time log file monitoring with correlation and response output
- [x] Environment-based configuration with .env support

### Phishing Email Analyzer
- [x] Email header parsing and validation (SPF, DKIM, DMARC)
- [x] URL extraction and reputation scanning (50+ known-bad domains)
- [x] Homograph attack detection (unicode character analysis)
- [x] Display text mismatch detection (deceptive links)
- [x] LLM-based content analysis via Ollama with offline heuristic fallback
- [x] Colored terminal reports with risk scores
- [x] MITRE ATT&CK mapping (T1566 sub-techniques)
- [x] 6 sample .eml files (2 legitimate, 4 phishing techniques)

### SSH Honeypot with Analytics
- [x] Fake SSH server on configurable port (default 2222)
- [x] Credential capture and client banner logging
- [x] Optional fake shell with command recording
- [x] Offline IP geolocation with country/city mapping
- [x] Credential reuse detection (coordinated attack identification)
- [x] Rapid attack pattern detection (automated tool identification)
- [x] Rate limiting and concurrent connection handling
- [x] Streamlit dashboard (overview, credentials, attackers, live feed)
- [x] Attacker simulator for demo data generation

### Network Traffic Anomaly Detector
- [x] Traffic simulator (1000+ normal flows, 5 anomaly types)
- [x] Behavioral baseline profiling (per-IP statistics, EMA updates)
- [x] Statistical detection: z-score, time analysis, destination anomaly
- [x] Pattern detection: port scan, C2 beaconing, DNS tunneling, lateral movement
- [x] SQLite storage for flows, anomalies, and baselines
- [x] Streamlit dashboard (overview, anomaly feed, baseline viewer, host detail)

### Port Scanner Suite
- [x] Python scanner — ThreadPoolExecutor, comma-separated ports, banner grabbing
- [x] C scanner — pthreads + select(), nonblocking sockets
- [x] Go scanner — goroutines + channels, worker pool, dual-phase banner detection
- [x] Rust scanner — tokio async + Semaphore, zero-cost abstractions
- [x] All 4 languages: 4 progressive versions (basic -> concurrent -> CLI -> banners)

### Port Scanner Benchmark Suite
- [x] Auto-compilation for C (make), Go (go build), Rust (cargo build)
- [x] Multi-run timing with mean/std deviation statistics
- [x] Benchmark target server for reproducible results
- [x] Comparison report generator (terminal table + BENCHMARK.md)
- [x] Language tradeoff analysis

### Other Tools
- [x] Packet Sniffer (Rust) — TCP/UDP/ICMP/ARP capture with filtering
- [x] Password Cracker (Python) — Dictionary + brute-force with mutations
- [x] Keylogger Detector (Python) — 8 Linux security checks

## Upcoming

### Local-AI-SOC Enhancements
- [ ] Syslog/CEF format ingestion (real SIEM compatibility)
- [ ] Dashboard: export to PDF, trend analysis
- [ ] ML-based alert classification (complement heuristic approach)

### New Tools
- [ ] Vulnerability scanner — Service enumeration + CVE lookup
- [ ] Log aggregator — Multi-source collection, normalize, feed to AI-SOC
- [ ] Wireless network analyzer — WiFi probe detection and deauth monitoring

### Port Scanner Suite
- [ ] UDP scanning support
- [ ] OS fingerprinting via TCP window size / TTL analysis
