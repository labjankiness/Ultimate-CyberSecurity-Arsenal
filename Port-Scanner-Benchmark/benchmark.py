"""
Port Scanner Benchmark Orchestrator.

Compiles and runs each language's port scanner against localhost,
measuring execution time, memory usage, and ports found.
Results are saved to benchmark_results.json.

Usage:
    python benchmark.py                    # Benchmark all available scanners
    python benchmark.py --target 127.0.0.1 --ports 1-1024
    python benchmark.py --runs 5           # 5 runs per scanner
"""

import argparse
import json
import os
import resource
import subprocess
import statistics
import sys
import time
from typing import Optional


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORTFOLIO_DIR = os.path.dirname(BASE_DIR)

# Scanner paths relative to portfolio root
SCANNERS = {
    "Python": {
        "dir": os.path.join(PORTFOLIO_DIR, "Port Scanner (Python)", "Python"),
        "build_cmd": None,
        "run_cmd": ["python3", "port_scanner.py"],
    },
    "C": {
        "dir": os.path.join(PORTFOLIO_DIR, "Port Scanner (C)", "C"),
        "build_cmd": ["make", "-B"],
        "run_cmd": ["./port_scanner"],
    },
    "Go": {
        "dir": os.path.join(PORTFOLIO_DIR, "Port Scanner (Go-Golang)", "Go"),
        "build_cmd": ["go", "build", "-o", "port_scanner", "."],
        "run_cmd": ["./port_scanner"],
    },
    "Rust": {
        "dir": os.path.join(PORTFOLIO_DIR, "Port Scanner (Rust)", "Rust"),
        "build_cmd": ["cargo", "build", "--release"],
        "run_cmd": None,  # Determined after build
    },
}


def _find_rust_binary(rust_dir: str) -> Optional[str]:
    """Find the Rust binary after cargo build."""
    target_dir = os.path.join(rust_dir, "target", "release")
    if os.path.isdir(target_dir):
        for f in os.listdir(target_dir):
            path = os.path.join(target_dir, f)
            if os.path.isfile(path) and os.access(path, os.X_OK) and not f.endswith(".d"):
                return path
    return None


def _check_tool(tool: str) -> bool:
    """Check if a build tool is available."""
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def build_scanner(name: str, config: dict) -> bool:
    """Compile a scanner if needed.

    Args:
        name: Scanner language name.
        config: Scanner configuration dict.

    Returns:
        True if build succeeded or not needed.
    """
    build_cmd = config.get("build_cmd")
    if not build_cmd:
        return True

    scanner_dir = config["dir"]
    if not os.path.isdir(scanner_dir):
        print(f"  [SKIP] {name}: directory not found ({scanner_dir})")
        return False

    print(f"  [BUILD] {name}: {' '.join(build_cmd)}")
    try:
        result = subprocess.run(
            build_cmd, cwd=scanner_dir,
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  [FAIL] {name} build failed: {result.stderr[:200]}")
            return False
        print(f"  [OK] {name} built successfully")
        return True
    except FileNotFoundError:
        tool = build_cmd[0]
        print(f"  [SKIP] {name}: '{tool}' not installed")
        return False
    except subprocess.TimeoutExpired:
        print(f"  [FAIL] {name}: build timed out")
        return False


def run_scanner(name: str, config: dict, target: str, port_range: str) -> Optional[dict]:
    """Run a scanner once and measure performance.

    Args:
        name: Scanner language name.
        config: Scanner configuration dict.
        target: Target IP/hostname.
        port_range: Port range string (e.g., "1-1024").

    Returns:
        Dict with: time_sec, output, return_code. None on failure.
    """
    scanner_dir = config["dir"]
    run_cmd = config.get("run_cmd")

    if name == "Rust" and not run_cmd:
        binary = _find_rust_binary(scanner_dir)
        if binary:
            run_cmd = [binary]
        else:
            return None

    if not run_cmd:
        return None

    # Build full command with target and port args
    cmd = list(run_cmd) + [target, port_range]

    try:
        start = time.perf_counter()
        result = subprocess.run(
            cmd, cwd=scanner_dir,
            capture_output=True, text=True, timeout=300,
        )
        elapsed = time.perf_counter() - start

        return {
            "time_sec": round(elapsed, 3),
            "output": result.stdout[:5000],
            "stderr": result.stderr[:1000],
            "return_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"time_sec": 300.0, "output": "TIMEOUT", "stderr": "", "return_code": -1}
    except FileNotFoundError:
        return None


def count_ports_found(output: str) -> int:
    """Estimate the number of open ports found from scanner output."""
    count = 0
    for line in output.split("\n"):
        lower = line.lower()
        if "open" in lower or "port" in lower:
            count += 1
    return max(count - 1, 0)  # Subtract header line


def benchmark(target: str = "127.0.0.1", port_range: str = "1-1024", runs: int = 3) -> dict:
    """Run the full benchmark suite.

    Args:
        target: Scan target.
        port_range: Port range.
        runs: Number of runs per scanner.

    Returns:
        Results dict with per-language metrics.
    """
    results = {}

    print(f"[*] Benchmark Configuration:")
    print(f"    Target: {target}")
    print(f"    Ports:  {port_range}")
    print(f"    Runs:   {runs}")
    print()

    # Build phase
    print("[*] Building scanners...")
    available = {}
    for name, config in SCANNERS.items():
        if build_scanner(name, config):
            available[name] = config
    print()

    if not available:
        print("[!] No scanners available. Check installations.")
        return results

    # Benchmark phase
    for name, config in available.items():
        print(f"[*] Benchmarking {name} ({runs} runs)...")
        run_times = []
        ports_found = []

        for i in range(runs):
            result = run_scanner(name, config, target, port_range)
            if result is None:
                print(f"  [SKIP] {name}: failed to run")
                break
            run_times.append(result["time_sec"])
            pf = count_ports_found(result["output"])
            ports_found.append(pf)
            print(f"  Run {i+1}/{runs}: {result['time_sec']:.3f}s, {pf} ports found")

        if run_times:
            results[name] = {
                "times": run_times,
                "mean_time": round(statistics.mean(run_times), 3),
                "std_time": round(statistics.stdev(run_times), 3) if len(run_times) > 1 else 0,
                "min_time": round(min(run_times), 3),
                "max_time": round(max(run_times), 3),
                "ports_found": ports_found[-1] if ports_found else 0,
                "runs": len(run_times),
            }
        print()

    # Save results
    output = {
        "config": {"target": target, "port_range": port_range, "runs": runs},
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
    }

    output_file = os.path.join(BASE_DIR, "benchmark_results.json")
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Results saved to {output_file}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Port Scanner Benchmark")
    parser.add_argument("--target", default="127.0.0.1", help="Scan target (default: 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--runs", type=int, default=3, help="Runs per scanner (default: 3)")
    args = parser.parse_args()

    benchmark(target=args.target, port_range=args.ports, runs=args.runs)


if __name__ == "__main__":
    main()
