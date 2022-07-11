package zerossl

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/rumsystem/ip-cert/pkg/log"
)

var logger = log.GetLogger()

func StartVerifyServer(pathContents map[string]string) error {
	m := http.NewServeMux()
	s := http.Server{Addr: ":80", Handler: m}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		// NOTE: only listen ipv4
		ln, err := net.Listen("tcp4", s.Addr)
		if err != nil {
			logger.Errorf("net.Listen failed: %s", err)
			return
		}
		if err := s.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	<-ctx.Done()
	// Shutdown the server when the context is canceled
	if err := s.Shutdown(ctx); err != nil {
		logger.Fatal(err)
	}

	return nil
}
