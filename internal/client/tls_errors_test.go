package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestClassifyTLSError_VersionMismatch(t *testing.T) {
	err := tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrVersionMismatch {
		t.Errorf("expected TLSErrVersionMismatch, got %v", result.Kind)
	}
}

func TestClassifyTLSError_UnknownAuthority(t *testing.T) {
	err := x509.UnknownAuthorityError{}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrUnknownAuthority {
		t.Errorf("expected TLSErrUnknownAuthority, got %v", result.Kind)
	}
}

func TestClassifyTLSError_CertificateInvalid(t *testing.T) {
	err := x509.CertificateInvalidError{Reason: x509.Expired}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrCertificateInvalid {
		t.Errorf("expected TLSErrCertificateInvalid, got %v", result.Kind)
	}
}

func TestClassifyTLSError_HostnameMismatch(t *testing.T) {
	err := x509.HostnameError{Host: "dns.example.com"}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrHostnameMismatch {
		t.Errorf("expected TLSErrHostnameMismatch, got %v", result.Kind)
	}
}

func TestClassifyTLSError_NetworkError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrNotTLS {
		t.Errorf("expected TLSErrNotTLS, got %v", result.Kind)
	}
}

func TestClassifyTLSError_WrappedError(t *testing.T) {
	inner := x509.UnknownAuthorityError{}
	wrapped := fmt.Errorf("Get https://dns.example.com: %w", inner)
	result := ClassifyTLSError(wrapped)
	if result.Kind != TLSErrUnknownAuthority {
		t.Errorf("expected TLSErrUnknownAuthority through wrapped error, got %v", result.Kind)
	}
}
