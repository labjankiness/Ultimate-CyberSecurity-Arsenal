# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A monorepo of 16 independent cybersecurity tools organized by category. Each tool lives in its own subfolder with its own dependencies and entry point — there is no shared runtime or build system across tools.

## Running Tools

Each Python tool has its own `requirements.txt`. Install and run per-tool:
```bash
cd <tool-folder>
pip install -r requirements.txt
python <main-script>.py
```

Streamlit dashboards (Honeypot, IoT-Network-Honeypot, Network-Anomaly-Detector, Local-AI-SOC):
```bash
streamlit run dashboard.py
```

Rust tools (packet-sniffer):
```bash
cargo build --release
sudo ./target/release/packet-sniffer --interface eth0
```

Port Scanner Suite — each language has 4 versions (basic → concurrent → CLI → banners):
```bash
# Python
python "Port Scanner (Python)/Python/scanner_v4.py" <target> <start_port> <end_port>
# Go
cd "Port Scanner (Go-Golang)/Go" && go run scanner_v4.go <target>
# C
cd "Port Scanner (C)/C" && gcc -o scanner scanner_v4.c -lpthread && ./scanner <target>
# Rust
cd "Port Scanner (Rust)/Rust" && cargo run --release -- <target>
```

Benchmark all scanners:
```bash
cd Port-Scanner-Benchmark && python benchmark.py
```

Linux hardening (run as root on Ubuntu/Debian):
```bash
bash Linux-Hardening-Basics/harden.sh        # full hardening
bash Linux-Hardening-Basics/harden.sh --audit  # audit mode only
```

## Architecture

**AI tools all follow the same pattern:** Ollama runs locally on `http://localhost:11434`, model `llama3.1:8b` (Guardian-Log-Analyzer uses `llama2`). Tools call Ollama directly via HTTP — no LangChain or agent framework.

**Local-AI-SOC** is the most complex tool. Its pipeline is:
`log_watcher.py` → `triage_agent.py` (Ollama) → `correlator.py` → `mitre_mapping.py` / `threat_intel.py` → `response_engine.py` → `database.py` (SQLite) → `soc_dashboard.py` (Streamlit)

**Network tools** that require raw packet access (`packet-sniffer`, `Network-Anomaly-Detector/capture.py`, `Honeypot`) need `sudo` or equivalent privileges.

**SQLite** is the persistence layer across all stateful tools (Honeypot, IoT-Network-Honeypot, Network-Anomaly-Detector, Guardian-Log-Analyzer, Local-AI-SOC). DB files are written locally in each tool's directory — not committed.

**Ransomware-Simulation-Lab** operates only on files inside its `sandbox/` directory. Never point `lab.py` at real files.

## Key Dependency: Ollama

All AI tools require Ollama running locally. Check/start:
```bash
ollama serve
ollama pull llama3.1:8b   # most tools
ollama pull llama2        # Guardian-Log-Analyzer
```

## No Tests

No test suite exists across any tool. Simulation scripts (e.g. `simulate_attack.py`, `simulate_attacker.py`, `simulate_traffic.py`) serve as functional validation.
