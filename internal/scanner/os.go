package scanner

import (
	"fmt"
	"net"
	"time"
)

type OSResult struct {
	OS           string
	Confidence   string
	TTL          int
	WindowSize   int
	ResponseType string
}

type OSFingerprint struct{}

func (b *Scaner) OS() *Scaner {
	b.strategy = &OSFingerprint{}
	return b
}

func (o *OSFingerprint) Name() string {
	return "OS Detection"
}

type ProbeResponse struct {
	OpenPorts    []int
	TTL          int
	WindowSize   int
	Flags        string
	ResponseType string
}

func (o *OSFingerprint) Scan(req *ScanRequest) ([]ScanResult, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	ipAddr, err := net.ResolveIPAddr("ip", req.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %v", err)
	}

	probes := []probe{
		{name: "SYN", port: 80, flags: "S"},
		{name: "SYN", port: 22, flags: "S"},
		{name: "FIN", port: 80, flags: "F"},
		{name: "XMAS", port: 80, flags: "FPU"},
		{name: "NULL", port: 80, flags: ""},
	}

	var responses []ProbeResponse
	for _, probe := range probes {
		resp := sendProbe(ipAddr.String(), probe.port, probe.flags, req.Timeout)
		resp.ResponseType = probe.name
		responses = append(responses, resp)
	}

	os := fingerprintOS(responses)

	return []ScanResult{
		{
			Port:    0,
			State:   os.OS,
			Service: os.Confidence,
		},
	}, nil
}

type probe struct {
	name  string
	port  int
	flags string
}

func sendProbe(target string, port int, flags string, timeout time.Duration) ProbeResponse {
	resp := ProbeResponse{}

	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return resp
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	_ = localAddr
	_ = remoteAddr

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if ra, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			resp.TTL = 64
			_ = ra
		}
	}

	openPorts := []int{port}
	resp.OpenPorts = openPorts
	resp.WindowSize = 65535

	return resp
}

func fingerprintOS(responses []ProbeResponse) OSResult {
	os := OSResult{
		OS:         "Unknown",
		Confidence: "Low",
		TTL:        64,
	}

	hasOpenPorts := false
	for _, resp := range responses {
		if len(resp.OpenPorts) > 0 {
			hasOpenPorts = true
			os.TTL = resp.TTL
			os.WindowSize = resp.WindowSize
			break
		}
	}

	if !hasOpenPorts {
		os.OS = "Unknown (no open ports detected)"
		os.Confidence = "Cannot determine"
		return os
	}

	switch {
	case os.WindowSize >= 64000:
		if os.TTL <= 64 {
			os.OS = "Linux/Unix (Kernel 2.4+)"
			os.Confidence = "High"
		} else if os.TTL <= 128 {
			os.OS = "Windows XP/2000/2003"
			os.Confidence = "Medium"
		} else {
			os.OS = "Windows Vista/7/8/10/11 or Linux"
			os.Confidence = "Medium"
		}
	case os.WindowSize >= 4000 && os.WindowSize < 64000:
		if os.TTL <= 64 {
			os.OS = "Linux/Cisco/Solaris"
			os.Confidence = "Medium"
		} else if os.TTL <= 128 {
			os.OS = "Windows Server 2008+ or FreeBSD"
			os.Confidence = "Medium"
		} else {
			os.OS = "macOS or older Linux"
			os.Confidence = "Low"
		}
	case os.WindowSize < 4000:
		os.OS = "Embedded/IoT device or Firewall"
		os.Confidence = "Low"
	default:
		os.OS = "Linux/Unix"
		os.Confidence = "Medium"
	}

	if len(responses) > 0 {
		openCount := 0
		for _, resp := range responses {
			if len(resp.OpenPorts) > 0 {
				openCount++
			}
		}

		if openCount >= 3 {
			os.Confidence = "High"
			if os.OS == "Linux/Unix (Kernel 2.4+)" {
				os.OS = "Linux (likely Debian/Ubuntu/CentOS)"
			}
		}
	}

	return os
}

func detectOSByService(openPorts []int) string {
	serviceOS := map[int]string{
		22:   "Linux/Unix (SSH)",
		23:   "Linux/Unix or Network Device (Telnet)",
		80:   "Any (HTTP)",
		443:  "Any (HTTPS)",
		3389: "Windows (RDP)",
		445:  "Windows (SMB)",
		3306: "Linux (MySQL)",
		5432: "Linux (PostgreSQL)",
		6379: "Linux (Redis)",
		8080: "Linux/Unix (Proxy/Java)",
	}

	osVotes := make(map[string]int)

	for _, port := range openPorts {
		if os, ok := serviceOS[port]; ok {
			osVotes[os]++
		}
	}

	maxVotes := 0
	detectedOS := ""
	for os, votes := range osVotes {
		if votes > maxVotes {
			maxVotes = votes
			detectedOS = os
		}
	}

	if detectedOS != "" && maxVotes >= 1 {
		return detectedOS
	}

	return ""
}
