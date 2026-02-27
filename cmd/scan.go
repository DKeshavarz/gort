package cmd

import (
	"fmt"

	"github.com/DKeshavarz/gort/internal/scanner"
)

func scan(args []string) {
	target := args[0]

	if osDetect {
		detectOS(target)
		return
	}

	var results []scanner.ScanResult
	var err error

	switch {
	case tcpScan:
		results, err = scanner.NewScaner().Target(target).TCPConnect().Do()
	case udpScan:
		results, err = scanner.NewScaner().UDP().Target(target).Do()
	case synScan:
		results, err = scanner.NewScaner().SYN().Target(target).Do()
	// case finScan:
	// 	scanType = "FIN"
	// case xmasScan:
	// 	scanType = "XMAS"
	default:

		fmt.Println("Error: No scan type specified")
		return
	}

	if err != nil {
		showErr(err)
		return
	}
	show(results)
}

func detectOS(target string) {
	fmt.Printf("Running OS detection on %s...\n\n", target)

	portResults, err := scanner.NewScaner().Target(target).TCPConnect().Do()
	if err != nil {
		showErr(err)
		return
	}

	var openPorts []int
	for _, r := range portResults {
		openPorts = append(openPorts, r.Port)
	}

	if len(openPorts) == 0 {
		fmt.Println("No open ports found. Cannot determine OS.")
		return
	}

	fmt.Println("Detected open ports:")
	for _, p := range openPorts {
		fmt.Printf("  - %d\n", p)
	}
	fmt.Println()

	os := detectOSByService(openPorts)
	if os != "" {
		fmt.Printf("Operating System: %s\n", os)
	} else {
		fmt.Println("Operating System: Unknown (no matching signatures)")
		fmt.Println("Try scanning with -T flag for more ports to improve detection")
	}
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

func show(results []scanner.ScanResult) {

	if len(results) == 0 {
		fmt.Println("No open ports found")
		return
	}

	fmt.Println("Open ports:")
	for _, result := range results {
		fmt.Printf("%d/%s\t%s\n", result.Port, result.State, result.Service)
	}
}

func showErr(err error) {
	if err == nil {
		return
	}
	fmt.Println(err.Error())
}
