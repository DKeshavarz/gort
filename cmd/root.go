package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gort",
	Short: "Gort - Fast network port scanner and OS fingerprinting tool",
	Long: `Gort (Go + Port) is a high-performance network reconnaissance tool that scans
for open ports, identifies running services, and fingerprints operating systems.

Features:
  • Nothing

For more information, use 'gort [command] --help'`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		scan(args)
		// target := args[0]
		// fmt.Printf("Scanning target: %s\n", target)

		// results, err := scanner.ConnectScanCommon(target, "tcp", 2*time.Second)

		// if err != nil {
		// 	fmt.Printf("Scan failed: %v\n", err)
		// 	return
		// }

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&tcpScan, "tcp", "T", false, "Completes full TCP handshake")
	rootCmd.Flags().BoolVarP(&udpScan, "udp", "U", false, "UDP scan")
	rootCmd.Flags().BoolVarP(&synScan, "syn", "S", false, "SYN stealth scan")
	rootCmd.Flags().BoolVarP(&finScan, "fin", "F", false, "FIN scan")
	rootCmd.Flags().BoolVarP(&xmasScan, "xmas", "X", false, "XMAS scan")
	rootCmd.Flags().BoolVarP(&scaning, "scan", "s", false, "scan")

	// Mark as mutually exclusive
	rootCmd.MarkFlagsOneRequired("scan")
	rootCmd.MarkFlagsMutuallyExclusive("tcp", "udp", "syn", "fin", "xmas")
	rootCmd.MarkFlagsOneRequired("tcp", "udp", "syn", "fin", "xmas")
}
