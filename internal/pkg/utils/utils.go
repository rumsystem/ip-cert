package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func GetPrivateKeyPath(_certDir, _ip string) string {
	return filepath.Join(_certDir, _ip, "private.key")
}

func GetCABundlePath(_certDir, _ip string) string {
	return filepath.Join(_certDir, _ip, "ca_bundle.crt")
}

func GetCertPath(_certDir, _ip string) string {
	return filepath.Join(_certDir, _ip, "certificate.crt")
}

func SaveFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, os.ModePerm)
}
