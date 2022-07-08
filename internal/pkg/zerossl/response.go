package zerossl

type (
	PaginationResult struct {
		TotalCount  int `json:"total_count"`
		ResultCount int `json:"result_count"`
		Page        int `json:"page"`
		Limit       int `json:"limit"`
	}

	GetCertResult struct {
		ID                string           `json:"id"`
		Type              string           `json:"type"`
		CommonName        string           `json:"common_name"`
		AdditionalDomains string           `json:"additional_domains"`
		Created           string           `json:"created"`
		Expires           string           `json:"expires"`
		Status            string           `json:"status"`
		ValidationType    string           `json:"validation_type"`
		ValidationEmails  string           `json:"validation_email"`
		ReplacementFor    string           `json:"replacement_for"`
		Validation        ValidationResult `json:"validation"`
	}

	ListCertResult struct {
		PaginationResult
		Results []GetCertResult `json:"results"`
	}

	ValidationResult struct {
		EmailValidation map[string][]string              `json:"email_validation"`
		OtherMethods    map[string]OtherValidationResult `json:"other_methods"`
	}

	OtherValidationResult struct {
		FileValidationUrlHttp  string   `json:"file_validation_url_http"`
		FileValidationUrlHttps string   `json:"file_validation_url_https"`
		FileValidationContent  []string `json:"file_validation_content"`
		CNameValidationP1      string   `json:"cname_validation_p1"`
		CNameValidationP2      string   `json:"cname_validation_p2"`
	}

	CertificateInlineResult struct {
		Certificate string `json:"certificate.crt"`
		CABundle    string `json:"ca_bundle.crt"`
	}

	VerifyDomainsResult struct {
		Success bool               `json:"success"`
		Error   VerifyDomainsError `json:"error"`
	}

	VerifyDomainsError struct {
		Code    int                                            `json:"code"`
		Type    string                                         `json:"type"`
		Details map[string]map[string]VerifyDomainsErrorDetail `json:"details"`
	}

	VerifyDomainsErrorDetail struct {
		CNameFound    int    `json:"cname_found"`
		RecordCorrect int    `json:"record_correct"`
		TargetHost    string `json:"target_host"`
		TargetRecord  string `json:"target_record"`
		ActualRecord  string `json:"actual_record"`
	}

	VerifyStatusItem struct {
		Method string `json:"method"`
		Status string `json:"status"`
	}
	VerifyStatusDetails map[string]VerifyStatusItem

	VerifyStatusResult struct {
		Completed int                 `json:"validation_completed"`
		Details   VerifyStatusDetails `json:"details"`
	}

	SuccessResult struct {
		Success int `json:"success"`
	}

	ErrorResult struct {
		Code int    `json:"code"`
		Type string `json:"type"`
	}

	ValidateCSRResult struct {
		Valid bool         `json:"valid"`
		Error *ErrorResult `json:"error"`
	}
)

func (v *SuccessResult) isSuccess() bool {
	return v.Success == 1
}

/*
func (v *VerifyStatusResult) isCompleted() bool {
	return v.Completed == 1
}
*/
