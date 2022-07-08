package zerossl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-playground/form/v4"
	"github.com/google/go-querystring/query"
	"github.com/rumsystem/ip-cert/internal/pkg/utils"
)

const ApiEndpoint = "api.zerossl.com"

type (
	Client struct {
		AccessKey string
	}
)

func (c *Client) GetURL(path string, query url.Values) string {
	if query == nil {
		query = make(url.Values)
	}
	query.Add("access_key", c.AccessKey)

	_url := url.URL{
		Scheme: "https", Host: ApiEndpoint, Path: path, RawQuery: query.Encode(),
	}
	return _url.String()
}

func (c *Client) CreateCert(payload CreateCertParams) (*GetCertResult, error) {
	url := c.GetURL("/certificates", nil)

	encoder := form.NewEncoder()
	values, err := encoder.Encode(&payload)
	if err != nil {
		return nil, err
	}
	body := values.Encode()

	_, resp, err := utils.Request(url, "POST", body, nil)
	if err != nil {
		return nil, err
	}

	var result GetCertResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) GetCert(id string) (*GetCertResult, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s", id), nil)
	_, resp, err := utils.Request(url, "GET", "", nil)
	if err != nil {
		return nil, err
	}

	var result GetCertResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) ListCert(params ListCertParams) (*ListCertResult, error) {
	q, err := query.Values(params)
	if err != nil {
		return nil, err
	}
	url := c.GetURL("/certificates", q)

	_, resp, err := utils.Request(url, "GET", "", nil)
	if err != nil {
		return nil, err
	}

	var result ListCertResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) VerifyDomains(id string, method ValidationMethod, emails []string) (*VerifyDomainsResult, error) {
	_url := c.GetURL(fmt.Sprintf("certificates/%s/challenges", id), nil)
	values := make(url.Values)
	values.Add("validation_method", method.String())

	if method == Email {
		if len(emails) > 0 {
			values.Add("validation_email", strings.Join(emails, ","))
		} else {
			return nil, fmt.Errorf("emails is empty")
		}
	}

	_, resp, err := utils.Request(_url, "POST", values.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var result VerifyDomainsResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) VerifyStatus(id string) (*VerifyStatusResult, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s/status", id), nil)
	_, resp, err := utils.Request(url, "GET", "", nil)
	if err != nil {
		return nil, err
	}
	var result VerifyStatusResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) DownloadCertInline(id string) (*CertificateInlineResult, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s/download/return", id), nil)
	_, resp, err := utils.Request(url, "GET", "", nil)
	if err != nil {
		return nil, err
	}

	var result CertificateInlineResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) RevokeCert(id string) (bool, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s/revoke", id), nil)
	_, resp, err := utils.Request(url, "POST", "", nil)
	if err != nil {
		return false, err
	}

	var result SuccessResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return false, err
	}

	if result.isSuccess() {
		return true, nil
	}
	return false, nil
}

func (c *Client) CancelCert(id string) (bool, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s/cancel", id), nil)
	_, resp, err := utils.Request(url, "POST", "", nil)
	if err != nil {
		return false, err
	}

	var result SuccessResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return false, err
	}

	if result.isSuccess() {
		return true, nil
	}
	return false, nil
}

func (c *Client) DeleteCert(id string) (bool, error) {
	url := c.GetURL(fmt.Sprintf("certificates/%s", id), nil)
	_, resp, err := utils.Request(url, "DELETE", "", nil)
	if err != nil {
		return false, err
	}

	var result SuccessResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return false, err
	}

	if result.isSuccess() {
		return true, nil
	}
	return false, nil
}

func (c *Client) ValidateCSR(csr string) (bool, error) {
	_url := c.GetURL("/validation/csr", nil)

	values := make(url.Values)
	values.Add("csr", csr)
	body := values.Encode()

	_, resp, err := utils.Request(_url, "POST", body, nil)
	if err != nil {
		return false, err
	}
	var result ValidateCSRResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return false, err
	}

	if result.Valid {
		return true, nil
	}

	return false, errors.New(result.Error.Type)
}
