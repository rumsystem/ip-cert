package zerossl

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rumsystem/ip-cert/pkg/log"
)

var logger = log.GetLogger()

func StartVerifyServer(pathContents map[string]string) error {
	m := http.NewServeMux()
	s := http.Server{Addr: ":80", Handler: m}
	ctx, cancel := context.WithCancel(context.Background())

	for path, content := range pathContents {
		_path, _content := path, content
		m.HandleFunc(_path, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, _content)
		})
	}

	m.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "bye")
		cancel()
	})

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	<-ctx.Done()
	// Shutdown the server when the context is canceled
	if err := s.Shutdown(ctx); err != nil {
		logger.Error(err)
	}

	return nil
}

func StopVerifyServer() error {
	client := http.Client{
		Timeout: time.Second * 5,
	}
	resp, err := client.Get("http://localhost/quit")
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code: %d, not 200", resp.StatusCode)
	}
	return nil
}
