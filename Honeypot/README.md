# SSH Honeypot with Real-Time Analytics

A Python-based SSH honeypot that captures connection attempts, credentials, and attacker commands, with a Streamlit analytics dashboard for real-time threat intelligence visualization.

## What is a Honeypot?

A honeypot is a decoy system designed to attract attackers. By monitoring what attackers try — which credentials they use, what commands they run, where they come from — defenders gain valuable threat intelligence without risking production systems. This data reveals:

- **Popular attack credentials** (what passwords are being brute-forced globally)
- **Attacker origins** (geographic distribution of threat actors)
- **Attack patterns** (automated vs. manual, coordinated campaigns)
- **Attacker behavior** (what they do after gaining "access")

## Architecture

```
Attacker → TCP:2222 → honeypot.py ──→ database.py (SQLite)
                          │                  │
                          │              geo_lookup.py
                          │                  │
                          └── fake shell ──→ commands table
                                             │
                              analytics.py ←─┘
                                  │
                              dashboard.py (Streamlit)
```

## Features

- **Fake SSH Server**: Listens on port 2222, captures credentials and client banners
- **Fake Shell Mode**: Optional interactive shell that records attacker commands
- **IP Geolocation**: Offline country/city lookup for attack origin mapping
- **Credential Analysis**: Top usernames, passwords, and reuse detection
- **Pattern Detection**: Automated attack identification, coordinated campaign detection
- **Rate Limiting**: Built-in protection against DoS of the honeypot itself
- **Streamlit Dashboard**: Real-time metrics, heatmaps, country charts, attacker drill-down
- **AI Summary**: Optional Ollama-powered threat intelligence reports

## Setup

```bash
# Clone the repository
git clone https://github.com/labjankiness/CyberSecurity-Portfolio-WIP.git
cd CyberSecurity-Portfolio-WIP/Honeypot

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Start the honeypot (listens on port 2222)
python honeypot.py

# Start with fake shell recording
python honeypot.py --shell

# Custom port
python honeypot.py --port 2223

# Generate demo data (no real attackers needed)
python simulate_attacker.py              # 50 random connections
python simulate_attacker.py --count 200  # 200 connections
python simulate_attacker.py --brute      # Brute force simulation
python simulate_attacker.py --coordinated  # Coordinated attack sim

# Launch the analytics dashboard
streamlit run dashboard.py

# View analytics in terminal
python analytics.py
```

## Dashboard

The Streamlit dashboard provides:

- **Overview**: Metrics, country chart, hourly activity, day/hour heatmap, pattern detection
- **Credentials**: Top usernames and passwords bar charts
- **Attackers**: Top attacker table with drill-down by IP
- **Live Feed**: Recent connections with full metadata

## Legal Disclaimer

This tool is for **educational and authorized security research only**. Deploy only on networks you own or have explicit written permission to monitor. Unauthorized deployment of honeypots may violate local laws and regulations. The authors are not responsible for misuse.

## Tech Stack

- Python 3.10+ (socket, threading for honeypot server)
- SQLite (connection and command storage)
- Streamlit + Plotly (analytics dashboard)
- Ollama + Llama 3.1 (optional AI threat summaries)
