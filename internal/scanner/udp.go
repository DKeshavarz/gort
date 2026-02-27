package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

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
			n, err := conn.Read(buffer)

			if err != nil || n <= 0 {
				return
			}

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
