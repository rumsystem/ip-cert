package zerossl

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
