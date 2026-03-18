# CyberSecurity Portfolio Development Roadmap

## Completed

### Local-AI-SOC
- [x] Core triage agent with Ollama + Llama 3.1 8B
- [x] Structured Senior SOC Analyst system prompt
- [x] Real-time log file monitoring (tail-follow)
- [x] Severity-weighted attack simulator (6 attack types: SSH brute force, SQL injection, privilege escalation, port scan, rogue USB, failed sudo)
- [x] Live web dashboard at localhost:5050 with alert cards, severity counts, auto-refresh
- [x] Markdown threat report generation

### Port Scanner Suite
- [x] Python scanner — ThreadPoolExecutor, comma-separated ports, banner grabbing
- [x] C scanner — pthreads + select(), nonblocking sockets
- [x] Go scanner — goroutines + channels, worker pool, dual-phase banner detection
- [x] Rust scanner — tokio async + Semaphore, zero-cost abstractions
- [x] All 4 languages: 4 progressive versions (basic → concurrent → CLI → banners)

## Upcoming

### Local-AI-SOC Enhancements
- [ ] MITRE ATT&CK technique tagging in triage reports
- [ ] Alert correlation (group related alerts by IP/timeframe)
- [ ] IOC extraction (IPs, domains, hashes) with automatic enrichment
- [ ] Syslog/CEF format ingestion (real SIEM compatibility)
- [ ] Historical alert database (SQLite) with search and filtering
- [ ] Dashboard: timeline view, severity trends over time, export to PDF

### New Tools
- [ ] Packet analyzer — Python-based pcap parser with AI-assisted anomaly detection
- [ ] Vulnerability scanner — Service enumeration + CVE lookup
- [ ] Log aggregator — Collect from multiple sources, normalize, feed to AI-SOC

### Port Scanner Suite
- [ ] Benchmarking comparison page (runtime, memory, lines of code across all 4 languages)
- [ ] UDP scanning support
- [ ] OS fingerprinting via TCP window size / TTL analysis
