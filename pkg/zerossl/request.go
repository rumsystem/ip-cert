package zerossl

import (
	"encoding/json"
	"fmt"

	"github.com/rumsystem/ip-cert/pkg/utils"
)

type (
	CreateCertParams struct {
		Domains      []string `form:"certificate_domains"`
		CSR          string   `form:"certificate_csr"`
		ValidityDays uint     `form:"certificate_validity_days"`
		Strict       bool     `form:"strict_domains"`
	}

	// ListCertParams use google/go-querystring encode to URL query parameters
	ListCertParams struct {
		// Status Possible values: draft, pending_validation, issued, cancelled, revoked, expired
		Status string `url:"certificate_status,omitempty"`
		Search string `url:"search,omitempty"`
		Limit  uint   `url:"limit,omitempty"`
		Page   string `url:"page,omitempty"` // default is 1
	}
)

func NewCreateCertParams(domains []string, csr string, days uint, strict bool) *CreateCertParams {
	return &CreateCertParams{
		Domains:      domains,
		CSR:          csr,
		ValidityDays: days,
		Strict:       strict,
	}
}

func Request(url string, method string, body string, headers map[string]string) (int, []byte, error) {
	statusCode, content, err := utils.Request(url, method, body, headers)
	if err != nil {
		return statusCode, content, err
	}

	if statusCode >= 400 {
		return statusCode, content, fmt.Errorf("ZeroSSL response status code: %d, body: %s", statusCode, content)
	}

	var errResult ErrorResult
	if err := json.Unmarshal(content, &errResult); err != nil {
		return statusCode, content, err
	}

	if errResult.Error != nil && errResult.Error.Code > 0 {
		return statusCode, content, fmt.Errorf("ZeroSSL: %s", errResult.Error.Type)
	}

	return statusCode, content, nil
}
