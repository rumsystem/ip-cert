package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"time"
)

func ParseCert(certPath, keyPath string) (*x509.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return c, nil
}

// IsCertExpired check if cert is expired
func IsCertExpired(certPath, keyPath string) (bool, error) {
	c, err := ParseCert(certPath, keyPath)
	if err != nil {
		return false, err
	}

	now := time.Now()
	if now.After(c.NotAfter) {
		return false, errors.New("Certificate expired")
	} else if now.Before(c.NotBefore) {
		return false, errors.New("Certificate not valid yet")
	}

	return true, nil
}
