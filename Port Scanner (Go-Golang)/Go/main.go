package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult holds the result of a port scan including an optional banner.
type ScanResult struct {
	Port   int
	Banner string
}

func main() {
	// Version 3.0 (Usability): CLI Flags
	var target string
	var startPort, endPort int
	var concurrency int
	var timeoutMs int

	flag.StringVar(&target, "target", "127.0.0.1", "Target IP address or hostname to scan")
	flag.IntVar(&startPort, "start", 1, "Starting port number")
	flag.IntVar(&endPort, "end", 1024, "Ending port number")
	flag.IntVar(&concurrency, "threads", 100, "Number of concurrent scanners (goroutines)")
	flag.IntVar(&timeoutMs, "timeout", 1000, "Timeout for port connection in milliseconds")

	flag.Parse()

	if startPort > endPort || startPort < 1 || endPort > 65535 {
		fmt.Println("Error: Invalid port range. Ensure start <= end and ports are between 1 and 65535.")
		return
	}

	fmt.Printf("Starting TCP port scan on %s (Ports: %d - %d)...\n", target, startPort, endPort)
	fmt.Printf("Concurrency: %d threads | Timeout: %dms\n\n", concurrency, timeoutMs)

	startTime := time.Now()

	// Version 2.0 (Speed): Channels for worker pool
	ports := make(chan int, concurrency)
	results := make(chan ScanResult)
	var openPorts []ScanResult

	var wg sync.WaitGroup

	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Start worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(target, ports, results, timeout, &wg)
	}

	// Background thread to collect results
	go func() {
		for result := range results {
			openPorts = append(openPorts, result)
		}
	}()

	// Distribute work to workers
	for p := startPort; p <= endPort; p++ {
		ports <- p
	}

	// Close channels and wait for workers to finish
	close(ports)
	wg.Wait()
	close(results)

	// Sort results for clean output
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	// Output summary
	fmt.Printf("\nScan completed in %s\n", time.Since(startTime))
	fmt.Printf("Found %d open ports:\n", len(openPorts))

	for _, res := range openPorts {
		if res.Banner != "" {
			fmt.Printf("  [+] Port %d: OPEN - Service Banner: %s\n", res.Port, res.Banner)
		} else {
			fmt.Printf("  [+] Port %d: OPEN\n", res.Port)
		}
	}
}

// worker processes ports from the ports channel and reports results.
func worker(target string, ports <-chan int, results chan<- ScanResult, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		
		// Version 1.0 (Core): tcp connect
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			// Port is closed or filtered
			continue
		}

		// Version 4.0 (Advanced): Service Banner Grabbing
		banner := grabBanner(conn, timeout)
		conn.Close()

		results <- ScanResult{
			Port:   port,
			Banner: banner,
		}
	}
}

// grabBanner attempts to read the service identity after connection.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	// Set read deadline to avoid freezing on silent ports
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	if err != nil {
		// Try sending a generic HTTP probe for services expecting client to speak first
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err = conn.Read(buffer)
		if err != nil || n == 0 {
			return ""
		}
	}

	// Process banner string (normalize newlines, trim space)
	banner := string(buffer[:n])
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.TrimSpace(banner)
	
	// Prettify by truncating massive banners
	if len(banner) > 80 {
		banner = banner[:77] + "..."
	}

	return banner
}
