package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/DKeshavarz/gort/internal/scanner"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gort [ip/host]",
	Short: "Gort - Fast network port scanner and OS fingerprinting tool",
	Long: `Gort (Go + Port) is a high-performance network reconnaissance tool that scans
for open ports, identifies running services, and fingerprints operating systems.

Features:
  • Nothing

For more information, use 'gort [command] --help'`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		method := args[1]
		fmt.Printf("Scanning target: %s\n", target)

		results, err := scanner.ConnectScanCommon(target, method, 2*time.Second)

		if err != nil {
			fmt.Printf("Scan failed: %v\n", err)
			return
		}

		if len(results) == 0 {
			fmt.Println("No open ports found")
			return
		}

		fmt.Println("\nOpen ports:")
		for _, result := range results {
			fmt.Printf("%d/%s\t%s\n", result.Port, result.State, result.Service)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
