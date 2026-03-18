# Bare-Metal TCP Port Scanner (C)

A highly concurrent, low-level TCP port scanner written in C for my cybersecurity portfolio. This tool utilizes pure POSIX sockets, pthreads for speed, and implements bare-metal service banner grabbing.

## Features

- **Version 1.0 (Core)**: Uses POSIX `<sys/socket.h>` for pure bare-metal network TCP connectivity without external libraries.
- **Version 2.0 (Speed)**: Implements `<pthread.h>` for multithreading, allowing rapid concurrent port validation across the specified port band.
- **Version 3.0 (Usability)**: Complete CLI usage with standard `getopt` to define the target IP, port range, concurrent thread limits, and socket connecting/reading timeouts.
- **Version 4.0 (Advanced)**: Service banner grabbing to identify the service listening on an open port by sending an active byte array probe (`HEAD / HTTP/1.0`) and reading the response raw via `recv()`.

## Prerequisites

This scanner relies heavily on the POSIX runtime environment. It is designed to be compiled and run on:
- Linux
- macOS
- Windows Subsystem for Linux (WSL)
- MSYS2/Cygwin (on Windows)

You will need:
- `gcc` or `clang` compiler
- `make`
- `pthreads` library (standard on POSIX systems)

## Build Instructions

### Native POSIX (Linux/macOS)
To compile the source code, simply navigate to the build directory and run:

```bash
make
```

### Windows (via WSL)
Since this program uses POSIX networking APIs, it must be run in a Linux environment. On Windows, you can use the Windows Subsystem for Linux (WSL).

1. Open PowerShell as Administrator and run: `wsl --install`
2. Restart your computer if required, and open the new "Ubuntu" (or default Linux) terminal from your start menu.
3. Install the compilation tools inside WSL:
   ```bash
   sudo apt update && sudo apt install build-essential
   ```
4. Navigate to your project directory (WSL automatically mounts your Windows drives under `/mnt/`):
   ```bash
   cd "/mnt/l/Vibe Coding Project/CyberSecurity Portfolio/Port Scanner (C)/C"
   ```
5. Compile the project:
   ```bash
   make
   ```

This will produce the binary executable `port_scanner`.

## Usage Instructions

```bash
./port_scanner -t <IP> -p <start_port-end_port> [-c threads] [-w timeout_ms]
```

### Options

| Flag | Argument | Description | Example |
|---|---|---|---|
| `-t` | `<IP>` | Target IP address to scan | `-t 192.168.1.1` |
| `-p` | `<start>-<end>`| Port range to scan | `-p 1-1024` |
| `-c` | `<threads>` | (Optional) Number of concurrent pthreads | `-c 50` (Default: 1) |
| `-w` | `<timeout>` | (Optional) Socket timeout in ms | `-w 500` (Default: 1000) |

### Example Scan

Scan a local web server (ports 1 to 1000) using 100 threads with a 500ms timeout:

```bash
./port_scanner -t 127.0.0.1 -p 1-1000 -c 100 -w 500
```

*Note: Since the program actively attempts to perform bare-metal interactions with network ports, running it on certain systems or ports may require elevated privileges.*
