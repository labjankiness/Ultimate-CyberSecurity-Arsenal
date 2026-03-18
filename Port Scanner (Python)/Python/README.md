# Python Advanced Port Scanner

A highly concurrent, versatile TCP port scanner written in Python. This project was developed as part of a Cybersecurity Portfolio to demonstrate proficiency in Python networking, socket programming, and concurrency.

## Features Let's track our iterative progress:

- **Version 1.0 (Core):** Basic TCP connect scanner using Python's `socket` library.
- **Version 2.0 (Speed):** Implemented `concurrent.futures.ThreadPoolExecutor` to scan massive port ranges concurrently, dropping scan times from hours to seconds.
- **Version 3.0 (Usability):** Integrated Python's `argparse` for a robust CLI interface allowing custom thread counts, timeouts, and customized port targets. 
- **Version 4.0 (Advanced):** Added Service **Banner Grabbing**. When an open port is discovered, the scanner negotiates with the service to identify exactly what is running behind the port.

## Installation

This script utilizes standard Python libraries and requires no external dependencies! It works on Windows, Linux, and macOS.

1. Ensure you have Python 3.7+ installed.
2. Clone this repository.

## Usage

You can scan a target hostname or IP address directly from the terminal. 

First, navigate to the correct directory where the script is located:
```bash
cd "l:\Vibe Coding Project\CyberSecurity Portfolio\Port Scanner\Python"
```

**Quickstart Example:**
```bash
python port_scanner.py scanme.nmap.org -p 80,443,22 -t 50
```

### Advanced Examples

```bash
# Basic scan (default ports 1-1024)
python port_scanner.py scanme.nmap.org

# Scan a specific port range
python port_scanner.py 192.168.1.1 -p 1-65535

# Scan a comma-separated list of common ports
python port_scanner.py google.com -p 21,22,80,443,8080

# Increase threads for a faster scan and modify timeout
python port_scanner.py example.com -p 1-10000 -t 500 -T 0.5
```

## CLI Arguments

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `target` | | The IP address or hostname to safely scan. | **Required** |
| `--ports` | `-p` | Port range (e.g., `1-1000`) or list (e.g., `22,80`) | `1-1024` |
| `--threads` | `-t` | Number of concurrent worker threads. | `100` |
| `--timeout` | `-T` | Socket connection timeout in seconds. | `1.0` |

## Alternative Language Prompts

If you would like to build this project in other languages to showcase versatility in your portfolio, you can use the following prompts in separate AI chats:

**For Go (Golang):**
> "I want to build a highly concurrent and fast port scanner in **Go (Golang)** for my cybersecurity portfolio. Please write the scanner in a new folder called `Go`. The scanner should use Go's native `net` package for TCP connection scanning. I want to fully utilize goroutines and channels to create a worker pool for maximum concurrency (V2.0). It should also include a CLI interface using the `flag` package (V3.0) and basic service banner grabbing (V4.0). Please also generate a professional `README.md` and `go.mod` file."

**For Rust:**
> "I want to build a safe, low-level, and incredibly fast port scanner in **Rust** for my cybersecurity portfolio. Please write the project in a new folder called `Rust`. The scanner should use standard Rust threading or `tokio` for high concurrency (V2.0), the `clap` crate for a professional CLI interface (V3.0), and include basic TCP service banner grabbing (V4.0). Please also create a professional `README.md` and the `Cargo.toml` file."

**For C:**
> "I want to build a bare-metal, low-level port scanner in **C** for my cybersecurity portfolio. Please write it in a new folder called `C`. The scanner should use POSIX sockets (or Winsock if targeting Windows) for the core connectivity (V1.0). I want to use `pthreads` to add multi-threading concurrency (V2.0) and parse standard `argc`/`argv` for CLI usability (V3.0). Please also generate a basic `Makefile` and a professional `README.md`."

## Disclaimer
This tool is built for educational purposes and authorized network auditing. Please do not use this to scan target networks without explicitly obtaining permission from the owner first.
