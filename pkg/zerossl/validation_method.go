package zerossl

// ValidationMethod validation method
type ValidationMethod int64

const (
	Email = iota
	CNameCSRHash
	HttpCSRHash
	HttpsCSRHash
)

func (vm ValidationMethod) String() string {
	switch vm {
	case Email:
		return "EMAIL"
	case CNameCSRHash:
		return "CNAME_CSR_HASH"
	case HttpCSRHash:
		return "HTTP_CSR_HASH"
	case HttpsCSRHash:
		return "HTTPS_CSR_HASH"
	}
	return "unknown"
}
