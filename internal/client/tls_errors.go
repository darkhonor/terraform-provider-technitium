package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

// TLSErrorKind identifies the category of a TLS handshake failure.
type TLSErrorKind int

const (
	// TLSErrNotTLS indicates the error is not TLS-related (e.g. a network
	// connectivity failure) or the input error was nil.
	TLSErrNotTLS TLSErrorKind = iota

	// TLSErrVersionMismatch indicates the server and client could not agree on
	// a TLS protocol version, or the server is not speaking TLS at all.
	TLSErrVersionMismatch

	// TLSErrUnknownAuthority indicates the server's certificate was signed by
	// a CA that the client does not trust.
	TLSErrUnknownAuthority

	// TLSErrCertificateInvalid indicates the server's certificate failed
	// validation for a reason other than an untrusted CA (e.g. expired, wrong
	// usage).
	TLSErrCertificateInvalid

	// TLSErrHostnameMismatch indicates the server's certificate does not cover
	// the hostname the client dialed.
	TLSErrHostnameMismatch
)

// TLSError holds a classified TLS error and its original cause.
type TLSError struct {
	// Kind is the category of the TLS failure.
	Kind TLSErrorKind

	// Original is the underlying error that was classified, preserved for
	// further inspection or logging.
	Original error
}

// ClassifyTLSError inspects err and returns a TLSError whose Kind describes
// the category of the failure. Wrapped errors are unwrapped via errors.As so
// that errors returned by net/http (e.g. *url.Error wrapping a *tls error)
// are handled transparently.
//
// If err is nil or does not match any known TLS failure pattern, the returned
// TLSError has Kind == TLSErrNotTLS.
func ClassifyTLSError(err error) TLSError {
	if err == nil {
		return TLSError{Kind: TLSErrNotTLS}
	}

	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return TLSError{Kind: TLSErrUnknownAuthority, Original: err}
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return TLSError{Kind: TLSErrHostnameMismatch, Original: err}
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return TLSError{Kind: TLSErrCertificateInvalid, Original: err}
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return TLSError{Kind: TLSErrVersionMismatch, Original: err}
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "protocol version not supported") ||
		strings.Contains(errMsg, "no mutual version") {
		return TLSError{Kind: TLSErrVersionMismatch, Original: err}
	}

	return TLSError{Kind: TLSErrNotTLS, Original: err}
}
