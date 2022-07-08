/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/rumsystem/ip-cert/internal/pkg/csr"
	"github.com/rumsystem/ip-cert/internal/pkg/utils"
	"github.com/rumsystem/ip-cert/internal/pkg/zerossl"
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
		issueFromZeroSSL(certDir, ip, accessKey)
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

func issueFromZeroSSL(_certDir string, _ip string, _accessKey string) {
	client := zerossl.Client{
		AccessKey: _accessKey,
	}

	privKey, err := csr.LoadOrCreatePrivateKey(_certDir, _ip)
	if err != nil {
		panic(err)
	}

	csrStr, err := csr.NewCSRStr(_ip, privKey)
	if err != nil {
		panic(err)
	}

	logger.Debugf("csr string: %s\n", csrStr)

	// create cert
	createParams := zerossl.NewCreateCertParams([]string{_ip}, csrStr, 90, false)
	certInfo, err := client.CreateCert(*createParams)
	if err != nil {
		panic(err)
	}
	logger.Debugf("certInfo: %+v\n", certInfo)

	// prepare verify
	pathContents := make(map[string]string)
	for _, v := range certInfo.Validation.OtherMethods {
		_url, err := url.Parse(v.FileValidationUrlHttp)
		if err != nil {
			panic(err)
		}
		var content string
		if runtime.GOOS == "windows" {
			content = strings.Join(v.FileValidationContent, " ")
		} else {
			content = strings.Join(v.FileValidationContent, "\n")
		}
		pathContents[_url.Path] = content
	}
	logger.Debugf("verify path and contents: %+v\n", pathContents)

	// start verify server
	go func() {
		if err := zerossl.StartVerifyServer(pathContents); err != nil {
			logger.Panic(err)
		}
	}()

	// notify verify
	if _, err := client.VerifyDomains(certInfo.ID, zerossl.HttpCSRHash, nil); err != nil {
		logger.Panic(err)
	}

	// check cert status
	for {
		info, err := client.GetCert(certInfo.ID)
		if err != nil {
			logger.Panic(err)
		}

		if info.Status == "issued" {
			break
		}
		logger.Debug("sleep 5 seconds ...")
		time.Sleep(time.Second * 5)
	}

	// download cert
	cert, err := client.DownloadCertInline(certInfo.ID)
	if err != nil {
		logger.Panic(err)
	}
	if err := utils.SaveFile(filepath.Join(_certDir, _ip, "ca_bundle.crt"), []byte(cert.CABundle)); err != nil {
		logger.Panic(err)
	}
	if err := utils.SaveFile(filepath.Join(_certDir, _ip, "certificate.crt"), []byte(cert.Certificate)); err != nil {
		logger.Panic(err)
	}

	logger.Infof("saved certificate to: %s", filepath.Join(_certDir, _ip))
}
