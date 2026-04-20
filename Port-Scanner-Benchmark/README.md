# Port Scanner Benchmark Suite

A cross-language benchmarking tool that compares port scanner implementations in Python, C, Go, and Rust. Measures scan time, ports discovered, and generates comparative analysis reports.

## Overview

The cybersecurity portfolio includes a TCP port scanner implemented in 4 languages. This benchmark suite:

1. Compiles all scanners (C via `make`, Go via `go build`, Rust via `cargo build`)
2. Runs each against the same target with identical parameters
3. Measures execution time across multiple runs
4. Generates comparison reports with analysis

## Usage

```bash
# Start the benchmark target server (provides consistent open ports)
python setup_benchmark_target.py &

# Run the benchmark (3 runs per scanner by default)
python benchmark.py

# Generate comparison report
python compare.py

# Custom configuration
python benchmark.py --target 127.0.0.1 --ports 1-1024 --runs 5
python compare.py --markdown BENCHMARK.md
```

## Benchmark Results

See [BENCHMARK.md](BENCHMARK.md) for the latest comparison results.

### Quick Summary

| Language | Strengths | Weaknesses |
|----------|-----------|------------|
| **C** | Fastest raw performance, minimal overhead | Manual memory management, harder to maintain |
| **Rust** | Near-C speed with memory safety | Steeper learning curve, longer compile times |
| **Go** | Fast, excellent concurrency, easy to read | Slight goroutine scheduling overhead |
| **Python** | Fastest to write, most readable | GIL limits parallelism, slowest runtime |

## Architecture

```
setup_benchmark_target.py  →  Opens known ports on localhost
         │
benchmark.py  →  Compiles & runs each scanner, measures time
         │
benchmark_results.json  →  Raw timing data
         │
compare.py  →  Terminal report + BENCHMARK.md
```

## Requirements

- Python 3.10+
- GCC/Make (for C scanner)
- Go 1.19+ (for Go scanner)
- Rust/Cargo (for Rust scanner)
- Missing languages are gracefully skipped
