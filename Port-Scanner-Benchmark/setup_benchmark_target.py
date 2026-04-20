"""
Benchmark target server — opens known ports for consistent scan results.

Starts simple TCP listeners on standard ports so benchmarks produce
reproducible results regardless of what services are actually running.

Usage:
    python setup_benchmark_target.py          # Start listeners
    python setup_benchmark_target.py --stop   # (Ctrl+C to stop)
"""

import argparse
import socket
import threading
import signal
import sys


# Ports to listen on for benchmark targets
TARGET_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 9090, 6379, 27017]
# Use high ports that don't need root
OFFSET = 0  # Set to e.g. 10000 if running without root (port + offset)

servers: list[socket.socket] = []
running = True


def _listener(port: int) -> None:
    """Run a simple TCP listener on a port."""
    global running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind(("127.0.0.1", port))
        sock.listen(128)
        servers.append(sock)

        while running:
            try:
                client, addr = sock.accept()
                # Send a banner and close
                try:
                    banner = f"BENCHMARK-TARGET port={port}\r\n"
                    client.send(banner.encode())
                except Exception:
                    pass
                client.close()
            except socket.timeout:
                continue
    except OSError as e:
        print(f"  [!] Port {port}: {e}")
    except Exception:
        pass


def start_targets(ports: list[int]) -> None:
    """Start TCP listeners on all target ports.

    Args:
        ports: List of ports to listen on.
    """
    global running
    running = True
    threads = []

    print(f"[*] Starting {len(ports)} benchmark target listeners...")
    for port in ports:
        t = threading.Thread(target=_listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)
        print(f"  [+] Listening on 127.0.0.1:{port}")

    print(f"\n[*] All targets ready. Press Ctrl+C to stop.\n")

    try:
        while running:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down targets...")
        running = False
        for sock in servers:
            try:
                sock.close()
            except Exception:
                pass
        print("[*] Done.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Target Server")
    parser.add_argument("--offset", type=int, default=0,
                        help="Port offset (e.g., 10000 to avoid needing root)")
    args = parser.parse_args()

    ports = [p + args.offset for p in TARGET_PORTS]
    start_targets(ports)


if __name__ == "__main__":
    main()
