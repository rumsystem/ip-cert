package utils

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/rumsystem/ip-cert/internal/pkg/log"
)

var logger = log.GetLogger()

// NewHTTPClient returns a new HTTP client
func NewHTTPClient() (*http.Client, error) {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 10,
		},
	}, nil
}

// Request sends a request to the API
func Request(url string, method string, body string, headers map[string]string) (int, []byte, error) {
	upperMethod := strings.ToUpper(method)
	methods := map[string]string{
		"HEAD":    http.MethodHead,
		"GET":     http.MethodGet,
		"POST":    http.MethodPost,
		"PUT":     http.MethodPut,
		"DELETE":  http.MethodDelete,
		"PATCH":   http.MethodPatch,
		"OPTIONS": http.MethodOptions,
	}

	if _, found := methods[upperMethod]; !found {
		panic(fmt.Sprintf("not support http method: %s", method))
	}

	method = methods[upperMethod]

	client, err := NewHTTPClient()
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	logger.Debugf("request: %s %s headers: %+v body: %s", method, url, headers, body)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	logger.Debugf("response: status: %d body: %s", resp.StatusCode, content)

	if resp.StatusCode >= 400 {
		return resp.StatusCode, content, fmt.Errorf("ZeroSSL response status code: %d, body: %s", resp.StatusCode, content)
	}

	return resp.StatusCode, content, nil
}
