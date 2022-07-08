package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	PrivateKeyFilename = "private.key"
)

func SaveFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, os.ModePerm)
}
