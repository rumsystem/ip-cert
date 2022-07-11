package csr

import "crypto/x509/pkix"

type SubjectParams struct {
	Country      string
	Province     string
	City         string
	Organization string
	CommonName   string
}

func NewSubject(param SubjectParams) pkix.Name {
	if param.CommonName == "" {
		panic("CommonName should not be empty")
	}

	if param.Country == "" {
		param.Country = "US"
	}
	if param.Province == "" {
		param.Province = "California"
	}
	if param.City == "" {
		param.City = "San Francisco"
	}
	if param.Organization == "" {
		param.Organization = "Earth"
	}

	return pkix.Name{
		Country:      []string{param.Country},
		Province:     []string{param.Province},
		Locality:     []string{param.City},
		Organization: []string{param.Organization},
		CommonName:   param.CommonName,
	}
}
