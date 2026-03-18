# High-Performance TCP Port Scanner

A highly concurrent and fast TCP port scanner written in Go (Golang) for cybersecurity discovery and footprinting. This tool iteratively implements core network scanning principles culminating in advanced service banner grabbing.

## Features Built
- **Version 1.0 (Core):** Implements connection-oriented TCP scanning using Go's native `net` package.
- **Version 2.0 (Speed):** Features a high-performance worker pool utilizing goroutines, channels, and a wait group for concurrent operations.
- **Version 3.0 (Usability):** Provides a robust Command Line Interface (CLI) using the `flag` package, allowing complete customization of scan parameters including target endpoints, customized port ranges, threads allocation, and connection timeouts.
- **Version 4.0 (Advanced):** Includes Service Banner Grabbing. Upon identifying an open port, the scanner captures and prints the underlying service identity natively (and dynamically sends a fallback payload query for services that require a request like HTTP).

## Prerequisites
- [Go 1.18+](https://go.dev/) installed.

## Usage Instructions

1. **Navigate to the Project Directory:**
   ```bash
   cd Go
   ```

2. **Run the Scanner temporarily (`go run`):**
   ```bash
   go run main.go [flags]
   ```
   Or better, **build an optimized binary** for max scanning speed:
   ```bash
   go build -o portscanner main.go
   ./portscanner [flags]
   ```

## Available CLI Flags
- `-target`: Target IP address or hostname to scan (default: "127.0.0.1")
- `-start`: Starting port number (default: 1)
- `-end`: Ending port number (default: 1024)
- `-threads`: Number of concurrent workers/goroutines (default: 100)
- `-timeout`: Timeout limit for each connection initialization attempt in milliseconds (default: 1000)

## Quickstart Examples

Scan your local machine's standard ports (1 to 1024) with default baseline settings:
```bash
go run main.go -target 127.0.0.1 -start 1 -end 1024
```

Perform an aggressive scan probing the entire standard port range against a specific server utilizing `500` threads and a fast `500ms` connection timeout:
```bash
go run main.go -target scanme.nmap.org -start 1 -end 65535 -threads 500 -timeout 500
```
