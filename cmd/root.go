package cmd

import (
	"os"

	"github.com/rumsystem/ip-cert/pkg/log"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ip-cert",
	Short: "Generate a SSL Certificate for an IP Address",
	Long:  `Currently get a SSL Certificate from ZeroSSL`,
}

var logger = log.GetLogger()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
