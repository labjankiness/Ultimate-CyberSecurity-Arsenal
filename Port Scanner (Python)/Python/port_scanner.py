import socket
import argparse
import concurrent.futures
import time
import sys
from datetime import datetime

def grab_banner(s):
    """
    Attempts to grab the service banner by sending a dummy HTTP request 
    and listening for a response.
    """
    try:
        # Send a generic request to trigger a response from some services (e.g., HTTP)
        s.send(b"GET / HTTP/1.1\r\n\r\n")
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        # Clean up the banner for display (return first line or up to 60 chars)
        if banner:
            return banner.split('\n')[0][:60]
    except Exception:
        pass
    return "Unknown Service"

def scan_port(ip, port, timeout):
    """
    Core scanning function. Attempts to connect to a specific TCP port.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP (Version 1.0 Core Functionality)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 if the connection succeeds (port is open)
            result = s.connect_ex((ip, port))
            if result == 0:
                # Version 4.0 Feature: Banner Grabbing
                banner = grab_banner(s)
                return port, True, banner
            return port, False, None
    except OSError:
        return port, False, None

def print_result(port, is_open, banner):
    """
    Helper function to cleanly print discovered open ports.
    """
    if is_open:
        banner_info = f" -> {banner}" if banner and banner != "Unknown Service" else ""
        print(f"[+] Port {port:5d} is OPEN{banner_info}")

def main():
    # Version 3.0 Feature: Command Line Interface (CLI) arguments
    parser = argparse.ArgumentParser(
        description="Advanced Python Port Scanner (v4.0)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n  python port_scanner.py example.com\n  python port_scanner.py 192.168.1.1 -p 1-1000 -t 200\n  python port_scanner.py 10.0.0.1 -p 22,80,443,8080"
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g., 1-1024 or 22,80,443)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    
    args = parser.parse_args()
    target = args.target

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{target}'.")
        sys.exit(1)

    # Parse ports into an iterable list/range
    ports_to_scan = []
    try:
        if '-' in args.ports:
            start_p, end_p = map(int, args.ports.split('-'))
            ports_to_scan = range(start_p, end_p + 1)
        elif ',' in args.ports:
            ports_to_scan = [int(p) for p in args.ports.split(',')]
        else:
            ports_to_scan = [int(args.ports)]
    except ValueError:
        print("[-] Error: Invalid port format. Use '1-1000', '22,80,443', or '80'.")
        sys.exit(1)

    # Print scan header
    print("-" * 60)
    print(f"Scanning Target : {target_ip} ({target})")
    print(f"Time Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Threads Target  : {args.threads}")
    print("-" * 60)

    start_time = time.time()
    open_ports = 0

    # Version 2.0 Feature: Multithreading for Speed
    try:
        # ThreadPoolExecutor efficiently manages a pool of worker threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Submit all port scanning tasks to the executor
            futures = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports_to_scan}
            
            # Process tasks as they complete
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports += 1
                    print_result(port, is_open, banner)

    except KeyboardInterrupt:
        print("\n[-] Scan cancelled by user (Ctrl+C). Exiting...")
        sys.exit(1)
        
    end_time = time.time()
    
    # Print scan footer
    print("-" * 60)
    print(f"Scan Completed in {end_time - start_time:.2f} seconds.")
    print(f"Total Open Ports: {open_ports}")

if __name__ == "__main__":
    main()
