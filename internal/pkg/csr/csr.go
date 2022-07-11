package csr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"

	"github.com/rumsystem/ip-cert/internal/pkg/utils"
)

const (
	PrivateKeyBlockType = "EC PRIVATE KEY"
	CSRBlockType        = "CERTIFICATE REQUEST"
)

// newPrivateKey return private key
func newPrivateKey() (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func savePrivateKey(baseDir, domain string, privKey *ecdsa.PrivateKey) error {
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	privKeyPemBytes := pem.EncodeToMemory(&pem.Block{Type: PrivateKeyBlockType, Bytes: privKeyBytes})
	path := utils.GetPrivateKeyPath(baseDir, domain)
	return utils.SaveFile(path, privKeyPemBytes)
}

func loadPrivateKeyFromFile(baseDir, domain string) (*ecdsa.PrivateKey, error) {
	path := utils.GetPrivateKeyPath(baseDir, domain)
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// NOTE: just parse one private key
	block, _ := pem.Decode(raw)
	return x509.ParseECPrivateKey(block.Bytes)
}

func LoadOrCreatePrivateKey(baseDir, domain string) (*ecdsa.PrivateKey, error) {
	privKey, err := loadPrivateKeyFromFile(baseDir, domain)
	if err == nil && privKey != nil {
		return privKey, nil
	}

	privKey, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	// NOTE: save private key
	err = savePrivateKey(baseDir, domain, privKey)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func NewCSR(domain string, privKey *ecdsa.PrivateKey) ([]byte, error) {
	subject := NewSubject(SubjectParams{CommonName: domain})
	temp := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &temp, privKey)
	if err != nil {
		return nil, err
	}

	return csrBytes, nil
}

func pemEncodeCSR(csr []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: CSRBlockType, Bytes: csr})
}

func SaveCSR(baseDir string, domain string, csr []byte) error {
	path := filepath.Join(baseDir, domain, "csr")
	csrPemBytes := pemEncodeCSR(csr)
	return utils.SaveFile(path, csrPemBytes)
}

func csrToStr(csr []byte) string {
	csrPemBytes := pemEncodeCSR(csr)
	return bytes.NewBuffer(csrPemBytes).String()
}

func NewCSRStr(domain string, privKey *ecdsa.PrivateKey) (string, error) {
	csrBytes, err := NewCSR(domain, privKey)
	if err != nil {
		return "", err
	}

	return csrToStr(csrBytes), nil
}
