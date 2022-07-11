package cmd

import (
	"github.com/rumsystem/ip-cert/internal/pkg/zerossl"
	"github.com/spf13/cobra"
)

var ( // flags
	certDir   string
	ip        string
	accessKey string
)

// issueCmd represents the issue command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue Certificate for an IP Address",
	Run: func(cmd *cobra.Command, args []string) {
		_, _, err := zerossl.IssueIPCert(certDir, ip, accessKey)
		if err != nil {
			logger.Fatal(err)
		}
	},
}

func init() {
	issueCmd.Flags().StringVarP(&certDir, "dir", "d", "", "the directory for saving SSL certificate")
	issueCmd.Flags().StringVarP(&ip, "ip", "i", "", "ip address")
	issueCmd.Flags().StringVarP(&accessKey, "key", "k", "", "zerossl access key, get from: https://app.zerossl.com/developer")

	if err := issueCmd.MarkFlagRequired("dir"); err != nil {
		logger.Fatal(err)
	}
	if err := issueCmd.MarkFlagRequired("ip"); err != nil {
		logger.Fatal(err)
	}
	if err := issueCmd.MarkFlagRequired("key"); err != nil {
		logger.Fatal(err)
	}

	rootCmd.AddCommand(issueCmd)
}
