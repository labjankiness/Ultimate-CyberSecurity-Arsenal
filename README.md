# Cybersecurity Portfolio

A collection of cybersecurity tools and projects demonstrating offensive security concepts, network analysis, and AI-driven threat detection.

## Projects

### Local-AI-SOC
An AI-powered Security Operations Center that uses locally-hosted LLMs (Ollama + Llama 3.1) to triage SIEM alerts in real-time. Features a **live web dashboard** (localhost:5050) with alert cards, severity stats, and auto-refresh — alongside automated log monitoring and structured threat analysis. All inference runs locally with zero data exfiltration.

**Tech:** Python, Ollama, Llama 3.1 8B, built-in HTTP dashboard

**Key files:**
- `triage_agent.py` — LLM orchestration and prompt engineering
- `log_watcher.py` — Real-time log file monitor with dashboard callback
- `simulate_attack.py` — Severity-weighted attack generator (high/medium/low) with randomized intervals
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

## Why Multiple Languages?

The port scanner suite isn't about finding the "best" language — it's about understanding trade-offs:
- **Python** is fastest to write but slowest to run
- **C** gives maximum control but requires manual memory management
- **Go** hits the sweet spot of simplicity and performance
- **Rust** enforces safety at compile time with zero runtime cost

## License

MIT
