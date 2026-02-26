package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func scan(cmd *cobra.Command, args []string) {
	target := args[0]

	// Determine scan type
	var scanType string
	switch {
	case tcpScan:
		scanType = "TCP connect"
	case udpScan:
		scanType = "UDP"
	case synScan:
		scanType = "SYN stealth"
	case finScan:
		scanType = "FIN"
	case xmasScan:
		scanType = "XMAS"
	default:
		
		fmt.Println("Error: No scan type specified")
		return
	}

	fmt.Printf("Starting %s scan on %s\n", scanType, target)

}
