// Package trustpolicy contains fail-closed reference adapters for deployment
// trust signals. Discovery metadata is never accepted as authorization.
package trustpolicy

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"time"
)

const MaxCertificateChain = 8

type WorkloadPrincipal struct {
	SPIFFEID string
	NotAfter time.Time
}

type WorkloadVerifier struct {
	trustDomain string
	roots       *x509.CertPool
}

func NewWorkloadVerifier(trustDomain string, roots *x509.CertPool) (*WorkloadVerifier, error) {
	if roots == nil || !validTrustDomain(trustDomain) {
		return nil, errors.New("invalid workload identity policy")
	}
	return &WorkloadVerifier{trustDomain: strings.ToLower(trustDomain), roots: roots.Clone()}, nil
}

// Verify validates an exact SPIFFE URI against an operator-owned X.509 root.
// ARD publisher identity, DNS names and transport endpoints are not consulted.
func (v *WorkloadVerifier) Verify(chain []*x509.Certificate, expectedID string, now time.Time) (WorkloadPrincipal, error) {
	if v == nil || len(chain) == 0 || len(chain) > MaxCertificateChain || chain[0] == nil || now.IsZero() {
		return WorkloadPrincipal{}, errors.New("workload identity rejected")
	}
	expected, err := parseSPIFFE(expectedID, v.trustDomain)
	if err != nil {
		return WorkloadPrincipal{}, errors.New("workload identity rejected")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		if certificate == nil {
			return WorkloadPrincipal{}, errors.New("workload identity rejected")
		}
		intermediates.AddCert(certificate)
	}
	verified, err := chain[0].Verify(x509.VerifyOptions{
		Roots: v.roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(verified) == 0 || len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != expected.String() {
		return WorkloadPrincipal{}, errors.New("workload identity rejected")
	}
	return WorkloadPrincipal{SPIFFEID: expected.String(), NotAfter: chain[0].NotAfter.UTC()}, nil
}

func parseSPIFFE(value, trustDomain string) (*url.URL, error) {
	if len(value) == 0 || len(value) > 512 {
		return nil, errors.New("invalid SPIFFE ID")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "spiffe" || strings.ToLower(parsed.Host) != trustDomain ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path == "" || parsed.Path == "/" || strings.Contains(parsed.Path, "//") ||
		parsed.RawPath != "" {
		return nil, errors.New("invalid SPIFFE ID")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return nil, errors.New("invalid SPIFFE ID")
		}
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed, nil
}

func validTrustDomain(value string) bool {
	if len(value) < 3 || len(value) > 253 || strings.ToLower(value) != value ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
