/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/grantae/certinfo"
	"github.com/spf13/cobra"
	"github.com/rumsystem/ip-cert/internal/pkg/utils"
)

var (
	certPath    *string
	privKeyPath *string
	_url        *string
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check SSL Certificate",
	Run: func(cmd *cobra.Command, args []string) {
		checkCert(*certPath, *privKeyPath, *_url)
	},
}

func init() {
	certPath = checkCmd.Flags().StringP("cert", "c", "", "certificate path")
	privKeyPath = checkCmd.Flags().StringP("priv", "p", "", "private key path")
	_url = checkCmd.Flags().StringP("url", "u", "", "website url")

	rootCmd.AddCommand(checkCmd)
}

func checkCert(certPath string, privKeyPath string, _url string) {
	checkFlags(certPath, privKeyPath, _url)

	var err error
	var cert *x509.Certificate
	if certPath != "" && privKeyPath != "" {
		cert, err = utils.ParseCert(certPath, privKeyPath)
		if err != nil {
			logger.Panic(err)
		}
	} else if _url != "" {
		cert = getCertFromURL(_url)
	}

	res, err := certinfo.CertificateText(cert)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infof("%s", res)
}

func checkFlags(certPath string, privKeyPath string, _url string) {
	if _url == "" && (certPath == "" || privKeyPath == "") {
		logger.Fatalf("cert path and private key path should not be empty")
	}
	if certPath == "" && privKeyPath == "" && _url == "" {
		logger.Fatalf("url should not be empty")
	}
}

func getCertFromURL(_url string) *x509.Certificate {
	var host string
	port := "443"

	if strings.Contains(_url, "://") {
		u, err := url.Parse(_url)
		if err != nil {
			logger.Panic(err)
		}
		if u.Port() != "" {
			port = u.Port()
		}

		host = fmt.Sprintf("%s:%s", u.Host, port)
	} else if !strings.Contains(_url, ":") {
		host = fmt.Sprintf("%s:%s", host, port)
	}

	conn, err := tls.Dial("tcp", host, &tls.Config{})
	if err != nil {
		logger.Panic(err)
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0]
}
