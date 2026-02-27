package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type UDP struct{}

func (b *Scaner) UDP() *Scaner {
	b.strategy = &UDP{}
	return b
}

// UDPScan performs a UDP scan on the specified target and ports
// Returns a slice of ScanResult for ports that respond
func (u *UDP) Scan(req *ScanRequest) ([]ScanResult, error) {
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
		return nil, fmt.Errorf("invalid timeout")
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

			conn, err := net.DialTimeout("udp", address, req.Timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			// Set deadline and send probe
			conn.SetDeadline(time.Now().Add(req.Timeout))
			probe := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			_, err = conn.Write(probe)
			if err != nil {
				return
			}

			// Wait for response
			buffer := make([]byte, 1024)
			_, err = conn.Read(buffer)
			if err != nil {
				return // No response = filtered
			}

			// Got response - port is open
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

func (u *UDP) Name() string { return "UDP" }