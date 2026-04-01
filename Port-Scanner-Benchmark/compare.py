"""
Benchmark comparison report generator.

Reads benchmark_results.json and generates terminal tables,
markdown reports, and analysis of language performance tradeoffs.

Usage:
    python compare.py                           # Terminal report
    python compare.py --markdown BENCHMARK.md   # Generate markdown report
"""

import argparse
import json
import os
import sys


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Language analysis notes
LANGUAGE_NOTES = {
    "Python": "Interpreted language with GIL limiting true parallelism. Uses threading for concurrency but still bound by the GIL for CPU tasks. Slowest runtime but fastest development speed.",
    "C": "Compiled to native code with direct syscall access. Minimal runtime overhead. Fastest raw performance but manual memory management increases bug risk.",
    "Go": "Compiled with goroutines for lightweight concurrency. Goroutine scheduling adds slight overhead vs raw threads. Excellent balance of speed and safety.",
    "Rust": "Compiled with zero-cost abstractions and memory safety without GC. Async runtime adds minimal overhead. Near-C performance with compile-time safety guarantees.",
}


def load_results(filepath: str = None) -> dict:
    """Load benchmark results from JSON.

    Args:
        filepath: Path to benchmark_results.json.
    """
    if filepath is None:
        filepath = os.path.join(BASE_DIR, "benchmark_results.json")

    with open(filepath, "r") as f:
        return json.load(f)


def print_terminal_report(data: dict) -> None:
    """Print a formatted comparison table to the terminal."""
    config = data.get("config", {})
    results = data.get("results", {})
    timestamp = data.get("timestamp", "N/A")

    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  PORT SCANNER BENCHMARK COMPARISON{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}")
    print(f"  Target: {config.get('target', 'N/A')}  |  "
          f"Ports: {config.get('port_range', 'N/A')}  |  "
          f"Runs: {config.get('runs', 'N/A')}  |  Date: {timestamp}")
    print()

    if not results:
        print("  No results available.")
        return

    # Find the fastest
    fastest = min(results.items(), key=lambda x: x[1]["mean_time"])

    # Table header
    print(f"  {'Language':<12} {'Mean Time':<14} {'Std Dev':<12} {'Min':<10} {'Max':<10} {'Ports':<8} {'Rank'}")
    print(f"  {'-' * 78}")

    # Sort by mean time
    sorted_results = sorted(results.items(), key=lambda x: x[1]["mean_time"])
    for rank, (lang, r) in enumerate(sorted_results, 1):
        color = GREEN if rank == 1 else YELLOW if rank == 2 else RESET
        medal = " (fastest)" if rank == 1 else ""
        speedup = ""
        if rank > 1:
            ratio = r["mean_time"] / fastest[1]["mean_time"]
            speedup = f" ({ratio:.1f}x slower)"

        print(f"  {color}{lang:<12} {r['mean_time']:<14.3f} {r['std_time']:<12.3f} "
              f"{r['min_time']:<10.3f} {r['max_time']:<10.3f} {r['ports_found']:<8}{RESET}"
              f"{medal}{speedup}")

    print(f"\n  {DIM}Times in seconds. Lower is better.{RESET}")

    # ASCII bar chart
    print(f"\n{BOLD}  Scan Time Comparison:{RESET}\n")
    max_time = max(r["mean_time"] for r in results.values())
    for lang, r in sorted_results:
        bar_len = int(r["mean_time"] / max_time * 40)
        color = GREEN if r["mean_time"] == fastest[1]["mean_time"] else YELLOW
        print(f"  {lang:<8} {color}{'█' * bar_len}{RESET} {r['mean_time']:.3f}s")

    print(f"\n{BOLD}{'=' * 70}{RESET}\n")


def generate_markdown(data: dict, filepath: str) -> None:
    """Generate a markdown benchmark report.

    Args:
        data: Benchmark results dict.
        filepath: Output file path.
    """
    config = data.get("config", {})
    results = data.get("results", {})
    timestamp = data.get("timestamp", "N/A")

    sorted_results = sorted(results.items(), key=lambda x: x[1]["mean_time"])
    fastest_lang = sorted_results[0][0] if sorted_results else "N/A"
    fastest_time = sorted_results[0][1]["mean_time"] if sorted_results else 0

    lines = [
        "# Port Scanner Benchmark Results",
        "",
        f"**Date:** {timestamp}",
        f"**Target:** {config.get('target', 'N/A')}",
        f"**Port Range:** {config.get('port_range', 'N/A')}",
        f"**Runs per scanner:** {config.get('runs', 'N/A')}",
        "",
        "## Performance Comparison",
        "",
        "| Rank | Language | Mean Time (s) | Std Dev (s) | Min (s) | Max (s) | Ports Found |",
        "|------|----------|--------------|-------------|---------|---------|-------------|",
    ]

    for rank, (lang, r) in enumerate(sorted_results, 1):
        medal = " **" if rank == 1 else ""
        medal_end = "**" if rank == 1 else ""
        lines.append(
            f"| {rank} | {medal}{lang}{medal_end} | {r['mean_time']:.3f} | "
            f"{r['std_time']:.3f} | {r['min_time']:.3f} | {r['max_time']:.3f} | "
            f"{r['ports_found']} |"
        )

    lines.extend([
        "",
        f"**Winner: {fastest_lang}** with a mean scan time of {fastest_time:.3f}s",
        "",
        "## Relative Performance",
        "",
    ])

    for lang, r in sorted_results:
        ratio = r["mean_time"] / fastest_time if fastest_time > 0 else 0
        bar = "█" * int(ratio * 20)
        lines.append(f"- **{lang}**: {bar} {r['mean_time']:.3f}s ({ratio:.1f}x)")

    lines.extend([
        "",
        "## Analysis",
        "",
    ])

    for lang, _ in sorted_results:
        note = LANGUAGE_NOTES.get(lang, "")
        if note:
            lines.append(f"### {lang}")
            lines.append(f"{note}")
            lines.append("")

    lines.extend([
        "## Tradeoffs",
        "",
        "| Factor | Python | C | Go | Rust |",
        "|--------|--------|---|----|----|",
        "| Runtime Speed | Slow | Fastest | Fast | Very Fast |",
        "| Development Speed | Fastest | Slow | Moderate | Moderate |",
        "| Memory Safety | GC | Manual | GC | Compile-time |",
        "| Concurrency Model | GIL + threads | pthreads | Goroutines | async/tokio |",
        "| Lines of Code | Fewest | Most | Moderate | Moderate |",
        "| Error Handling | Exceptions | Manual | Error values | Result type |",
        "",
        "## Methodology",
        "",
        "Each scanner was compiled (where applicable) and run against the same target.",
        "A test server with known open ports was used to ensure reproducible results.",
        "Each scanner ran the concurrent version (V2) for fair comparison.",
        "Timing was measured using Python's `time.perf_counter()` around `subprocess.run()`.",
        "",
        "---",
        "*Generated by Port Scanner Benchmark Suite*",
    ])

    with open(filepath, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown report saved to {filepath}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Comparison Report")
    parser.add_argument("--results", default=None, help="Path to benchmark_results.json")
    parser.add_argument("--markdown", "-m", default=None, help="Generate markdown report to file")
    args = parser.parse_args()

    try:
        data = load_results(args.results)
    except FileNotFoundError:
        print("[!] No benchmark_results.json found. Run benchmark.py first.")
        sys.exit(1)

    print_terminal_report(data)

    if args.markdown:
        generate_markdown(data, args.markdown)
    else:
        # Auto-generate BENCHMARK.md
        md_path = os.path.join(BASE_DIR, "BENCHMARK.md")
        generate_markdown(data, md_path)


if __name__ == "__main__":
    main()
