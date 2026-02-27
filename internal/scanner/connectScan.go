package scanner

import (
	"fmt"
	"net"
	"sync"
)

type ScanResult struct {
	Port    int
	State   string
	Service string
}

type TCPConnect struct{}

func (b *Scaner) TCPConnect() *Scaner {
	b.strategy = &TCPConnect{}
	return b
}

// TCPConnectScan performs a TCP connect scan on the specified target and ports
// Returns a slice of ScanResult for open ports
func (c *TCPConnect) Scan(req *ScanRequest) ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	if req.Target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	_, err := net.ResolveIPAddr("ip", req.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %v", err)
	}

	if req.Timeout <= 0 {
		return nil, fmt.Errorf("invalid time out")
	}

	maxConcurrency := 100
	sem := make(chan struct{}, maxConcurrency)

	for _, port := range req.Ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(req.Target, fmt.Sprintf("%d", port))

			conn, err := net.DialTimeout("tcp", address, req.Timeout)

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
func (c *TCPConnect) Name() string { return "TCP Connect" }
