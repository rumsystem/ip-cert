package zerossl

import (
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/rumsystem/ip-cert/internal/pkg/csr"
	"github.com/rumsystem/ip-cert/internal/pkg/utils"
)

// IssueIPCert issue SSL Certificate from ZeroSSL for an ip address, return private key path, certificate path and error
func IssueIPCert(_certDir string, _ip string, _accessKey string) (string, string, error) {
	client := Client{
		AccessKey: _accessKey,
	}

	privKeyPath := utils.GetPrivateKeyPath(_certDir, _ip)
	certPath := utils.GetCertPath(_certDir, _ip)
	if utils.FileExist(privKeyPath) && utils.FileExist(certPath) {
		isExp, err := utils.IsCertExpired(certPath, privKeyPath)
		if err != nil {
			return "", "", err
		}
		if !isExp {
			return privKeyPath, certPath, nil
		}
	}

	privKey, err := csr.LoadOrCreatePrivateKey(_certDir, _ip)
	if err != nil {
		return "", "", nil
	}

	csrStr, err := csr.NewCSRStr(_ip, privKey)
	if err != nil {
		return "", "", nil
	}

	logger.Debugf("csr string: %s\n", csrStr)

	// create cert
	createParams := NewCreateCertParams([]string{_ip}, csrStr, 90, false)
	certInfo, err := client.CreateCert(*createParams)
	if err != nil {
		return "", "", nil
	}
	logger.Debugf("certInfo: %+v\n", certInfo)

	// prepare verify
	pathContents := make(map[string]string)
	for _, v := range certInfo.Validation.OtherMethods {
		_url, err := url.Parse(v.FileValidationUrlHttp)
		if err != nil {
			return "", "", nil
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
		return "", "", nil
	}

	// check cert status
	for {
		info, err := client.GetCert(certInfo.ID)
		if err != nil {
			return "", "", nil
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
		return "", "", nil
	}
	caBundlePath := utils.GetCABundlePath(_certDir, _ip)
	if err := utils.SaveFile(caBundlePath, []byte(cert.CABundle)); err != nil {
		return "", "", nil
	}
	if err := utils.SaveFile(certPath, []byte(cert.Certificate)); err != nil {
		return "", "", nil
	}

	logger.Infof("saved private key: %s certificate: %s ca bundle: %s", privKeyPath, certPath, caBundlePath)
	return privKeyPath, certPath, nil
}
