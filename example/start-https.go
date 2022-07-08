package main

import (
	"log"
	"net/http"
	"path/filepath"
)

// NOTE: change it
var certDir = "/tmp/.zerossl-certs/1.2.3.4"
var certPath = filepath.Join(certDir, "certificate.crt")
var keyPath = filepath.Join(certDir, "private.key")

func main() {
	http.HandleFunc("/", handler)
	err := http.ListenAndServeTLS(":443", certPath, keyPath, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Just test https server.\n"))
}
