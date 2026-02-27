package scanner

import (
	"fmt"
	"time"
)


type ScanStrategy interface {
	Scan(req *ScanRequest) ([]ScanResult, error)
	Name() string
}

type ScanRequest struct {
	Target  string
	Ports   []int
	Timeout time.Duration
}

// Scaner builds scan requests
type Scaner struct {
	request *ScanRequest
	strategy ScanStrategy
	errors  []error
}

func NewScaner() *Scaner {
	return &Scaner{
		request: &ScanRequest{
			Ports:   commonPorts(),
			Timeout: 2 * time.Second,
		},
		strategy: &TCPConnect{},
	}
}

func (b *Scaner) Target(target string) *Scaner {
	if target == "" {
		b.errors = append(b.errors, fmt.Errorf("target cannot be empty"))
		return b
	}
	b.request.Target = target
	return b
}

func (b *Scaner) Ports(ports []int) *Scaner {
	if len(ports) == 0 {
		b.errors = append(b.errors, fmt.Errorf("ports cannot be empty"))
		return b
	}

	// Validate ports
	for _, p := range ports {
		if p < 1 || p > 65535 {
			b.errors = append(b.errors, fmt.Errorf("invalid port number: %d", p))
			return b
		}
	}

	b.request.Ports = ports
	return b
}

func (b *Scaner) PortRange(start, end int) *Scaner {
	if start < 1 || end > 65535 || start > end {
		b.errors = append(b.errors, fmt.Errorf("invalid port range: %d-%d", start, end))
		return b
	}

	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}

	b.request.Ports = ports
	return b
}

func (b *Scaner) Timeout(timeout time.Duration) *Scaner {
	if timeout <= 0 {
		b.errors = append(b.errors, fmt.Errorf("timeout must be positive"))
		return b
	}
	b.request.Timeout = timeout
	return b
}

func (b *Scaner) Do() ([]ScanResult, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("validation errors: %v", b.errors)
	}

	if b.request.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	
	return b.strategy.Scan(b.request)
}