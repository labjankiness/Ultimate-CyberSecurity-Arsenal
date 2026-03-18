# Rust TCP Port Scanner

A safe, low-level, and incredibly fast TCP port scanner written in Rust.

This scanner implements features incrementally across versions according to the initial specifications:
- **Version 1.0 (Core)**: Uses basic connection scanning (`tokio::net::TcpStream` enabling high-performance standard async capabilities outperforming blocking std::net).
- **Version 2.0 (Speed)**: Uses the powerful `tokio` asynchronous runtime with a worker limit (semaphore) to safely and rapidly scan massive ranges of ports concurrently.
- **Version 3.0 (CLI Usability)**: Uses the `clap` crate for a dynamic Command Line Interface to seamlessly accept target IPs/hostnames, port ranges, concurrency ranges (worker limits), and connection timeouts.
- **Version 4.0 (Advanced)**: Basic TCP Banner Grabbing to identify running services. When a port is opened, it negotiates a small read to grab the service signature (e.g. SSH, FTP banner) and sends an arbitrary active probe if the service does not print a banner upfront.

## Prerequisites

- [Rust Toolchain](https://rustup.rs/) (Cargo & rustc). Use rustup to install if needed.

## Directory Navigation

1. Open your terminal.
2. Navigate to this project directory:
   ```bash
   cd "l:/Vibe Coding Project/CyberSecurity Portfolio/Port Scanner (Rust)/Rust"
   ```

## Build

Compile the project for release to ensure maximum performance across many threads:

```bash
cargo build --release
```

## Quickstart Examples

Run the scanner directly with Cargo using the help flag to see all options:

```bash
cargo run --release -- --help
```

### 1. Basic Scan
Scan localhost on the top 1000 ports:
```bash
cargo run --release -- --target localhost
```

### 2. High Concurrency Port Range Scan
Scan a remote server (or local network), checking ports `1` to `65535` with 5000 concurrent tasks and a tighter connection timeout of 200ms:
```bash
cargo run --release -- --target scanme.nmap.org -s 1 -e 65535 -w 5000 -t 200
```

### 3. Basic Banner Grabbing Test
Scan an SSH or HTTP port to see the banner automatically negotiated and displayed alongside the opened port condition:
```bash
cargo run --release -- --target scanme.nmap.org -s 22 -e 22
```

## Disclaimer
This project is for educational and authorized network testing purposes only. Do not use this tool on servers or networks without permission.
