package cmd

import (
	"fmt"

	"github.com/DKeshavarz/gort/internal/scanner"
)

func scan(args []string) {
	target := args[0]

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
