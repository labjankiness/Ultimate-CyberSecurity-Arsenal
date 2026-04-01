# Network Traffic Anomaly Detector

A statistical anomaly detection engine for network traffic that builds behavioral baselines and flags deviations without machine learning. Detects port scans, data exfiltration, C2 beaconing, DNS tunneling, and lateral movement using z-scores, time analysis, and pattern matching.

## Why Statistical Detection?

This project intentionally uses statistical methods rather than ML. Statistical anomaly detection is:

- **Explainable**: Every alert includes the exact statistical evidence (z-scores, thresholds, baseline values)
- **Lightweight**: Runs on any machine, no GPU or training data required
- **Transparent**: No black-box model — you can audit exactly why something was flagged
- **Immediate**: No training phase, starts detecting from the first baseline window

Signature-based detection catches known attacks. ML catches patterns in training data. Statistical detection catches anything that deviates from normal — including novel, zero-day threats.

## Architecture

```
simulate_traffic.py ──→ flows.json
                            │
capture.py ────────────────→│
                            ▼
                      baseline.py ──→ Normal behavior profiles
                            │
                      detector.py ──→ Anomalies detected
                            │
                      database.py ──→ SQLite storage
                            │
                      dashboard.py ──→ Streamlit visualization
```

## Detection Methods

| Method | Detects | How |
|--------|---------|-----|
| Z-Score | Data exfiltration | Bytes sent > 3 std deviations from baseline |
| Time Analysis | Off-hours activity | Connections outside normal operating hours |
| Destination Anomaly | New/unknown targets | Connections to IPs not in baseline |
| Port Sweep | Port scans | >20 unique ports from same source in short window |
| Interval Analysis | C2 beaconing | Regular-interval connections with low jitter |
| DNS Size Analysis | DNS tunneling | DNS queries 3x larger than normal |
| Internal Fan-out | Lateral movement | One host connecting to 8+ internal hosts |

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# 1. Generate simulated traffic (1000 normal + anomalies)
python simulate_traffic.py

# 2. Run the detector
python detector.py

# 3. Launch the dashboard
streamlit run dashboard.py
```

## Sample Detection Output

```
[CRITICAL] c2_beaconing — 192.168.1.23 → 185.220.101.99 (confidence: 92%)
    beacon_count: 15
    mean_interval_sec: 60.1
    jitter_sec: 1.8

[HIGH] port_scan — 192.168.1.35 → 142.250.80.46 (confidence: 85%)
    unique_ports: 35
    sample_ports: [22, 53, 80, 110, 143, 443, ...]

[HIGH] data_exfiltration — 192.168.1.14 → 103.224.182.99 (confidence: 78%)
    bytes_sent: 2450000
    baseline_mean: 3200
    z_score: 8.4
```

## Limitations and Future Work

- **No real-time capture**: Currently works with simulated/imported flow data. Future: integrate scapy for live packet capture
- **No ML models**: Statistical methods have higher false-positive rates on complex traffic. Future: add isolation forest or autoencoder anomaly detection
- **Single-host baselines**: Each IP is profiled independently. Future: model inter-host relationships for better lateral movement detection

## Tech Stack

- Python 3.10+ (standard library math for statistics)
- Pandas (data manipulation)
- Streamlit + Plotly (dashboard)
- SQLite (storage)
