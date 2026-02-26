package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ScanResult struct {
	Port    int
	State   string
	Service string
}

// TCPConnectScan performs a TCP connect scan on the specified target and ports
// Returns a slice of ScanResult for open ports
func TCPConnectScan(target string, ports []int, timeout time.Duration) ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	_, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %v", err)
	}

	if timeout == 0 {
		timeout = 2 * time.Second
	}

	maxConcurrency := 100
	sem := make(chan struct{}, maxConcurrency)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

			conn, err := net.DialTimeout("tcp", address, timeout)

			if err != nil {
				// Connection failed - port is likely closed or filtered -> can add more
				return
			}
			defer conn.Close()

			mu.Lock()
			results = append(results, ScanResult{
				Port:    port,
				State:   "open",
				Service: getServiceName(port),
			})
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	close(sem)

	return results, nil
}

// ConnectScanCommon scans the most common ports with specific method
func ConnectScanCommon(target string, method string, timeout time.Duration) ([]ScanResult, error) {
	commonPorts := commonPorts()

	handlers := map[string]func(target string, ports []int, timeout time.Duration) ([]ScanResult, error){
		"udp": UDPScan,
		"tcp": TCPConnectScan,
	}

	if handler, ok := handlers[method]; ok {
		return handler(target, commonPorts, timeout)
	}

	return nil, fmt.Errorf("invalid method: %s", method)
}

// UDPScan performs a UDP scan on the specified target and ports (Similar to Nmap -sU)
func UDPScan(target string, ports []int, timeout time.Duration) ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	_, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %v", err)
	}

	if timeout == 0 {
		timeout = 2 * time.Second
	}

	maxConcurrency := 100
	sem := make(chan struct{}, maxConcurrency)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

			conn, err := net.DialTimeout("udp", address, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(timeout))
			_, err = conn.Write([]byte("\x0D\x0A\x00\x00\x00\x00\x00\x00"))

			buffer := make([]byte, 1024)
			_, err = conn.Read(buffer)

			state := "open|filtered"
			if err == nil {
				state = "open"
			}

			mu.Lock()
			results = append(results, ScanResult{
				Port:    port,
				State:   state + " (UDP)",
				Service: getServiceName(port),
			})
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	close(sem)

	return results, nil
}


