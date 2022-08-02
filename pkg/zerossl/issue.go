package zerossl

import (
	"errors"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/rumsystem/ip-cert/pkg/csr"
	"github.com/rumsystem/ip-cert/pkg/utils"
)

// IssueIPCert issue SSL Certificate from ZeroSSL for an ip address, return private key path, certificate path and error
func IssueIPCert(_certDir string, _ip net.IP, _accessKey string) (string, string, error) {
	if _certDir == "" {
		return "", "", errors.New("certificate directory is null")
	}
	if _ip == nil {
		return "", "", errors.New("invalid ip address")
	}
	if _accessKey == "" {
		return "", "", errors.New("you should get ZeroSSL access key from: https://app.zerossl.com/developer")
	}

	ipStr := _ip.String()
	client := Client{
		AccessKey: _accessKey,
	}

	privKeyPath := utils.GetPrivateKeyPath(_certDir, ipStr)
	certPath := utils.GetCertPath(_certDir, ipStr)
	if utils.FileExist(privKeyPath) && utils.FileExist(certPath) {
		isExp, err := utils.IsCertExpired(certPath, privKeyPath)
		if err != nil {
			return "", "", err
		}
		if !isExp {
			return privKeyPath, certPath, nil
		}
	}

	privKey, err := csr.LoadOrCreatePrivateKey(_certDir, _ip.String())
	if err != nil {
		return "", "", err
	}

	csrStr, err := csr.NewCSRStr(_ip.String(), privKey)
	if err != nil {
		return "", "", err
	}

	logger.Debugf("csr string: %s\n", csrStr)

	// create cert
	createParams := NewCreateCertParams([]string{_ip.String()}, csrStr, 90, false)
	certInfo, err := client.CreateCert(*createParams)
	if err != nil {
		return "", "", err
	}
	logger.Debugf("certInfo: %+v\n", certInfo)
	if len(certInfo.Validation.OtherMethods) == 0 {
		logger.Debug("request certificate failed")
		return "", "", err
	}

	// prepare verify
	pathContents := make(map[string]string)
	for _, v := range certInfo.Validation.OtherMethods {
		_url, err := url.Parse(v.FileValidationUrlHttp)
		if err != nil {
			return "", "", err
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
		if err := StartVerifyServer(pathContents); err != nil {
			logger.Panic(err)
		}
	}()

	// notify verify
	if _, err := client.VerifyDomains(certInfo.ID, HttpCSRHash, nil); err != nil {
		return "", "", err
	}

	// check cert status
	for {
		info, err := client.GetCert(certInfo.ID)
		if err != nil {
			return "", "", err
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
		return "", "", err
	}
	caBundlePath := utils.GetCABundlePath(_certDir, ipStr)
	if err := utils.SaveFile(caBundlePath, []byte(cert.CABundle)); err != nil {
		return "", "", err
	}
	// save certificate and ca bundle to cert file
	if err := utils.SaveFile(certPath, []byte(cert.Certificate+cert.CABundle)); err != nil {
		return "", "", err
	}

	logger.Infof("saved private key: %s certificate: %s ca bundle: %s", privKeyPath, certPath, caBundlePath)

	// stop verify server
	if err := StopVerifyServer(); err != nil {
		logger.Errorf("stop verify server failed: %s", err)
	}

	return privKeyPath, certPath, nil
}
