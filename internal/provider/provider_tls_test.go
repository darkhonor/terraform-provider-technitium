// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

func TestResolveTLSConfig_HCLWinsOverEnv(t *testing.T) {
	t.Setenv("TECHNITIUM_CACERT", "/env/ca.pem")
	result := resolveTLSString("hcl-value", "TECHNITIUM_CACERT")
	if result != "hcl-value" {
		t.Errorf("HCL should win over env var, got %q", result)
	}
}

func TestResolveTLSConfig_EnvFallback(t *testing.T) {
	t.Setenv("TECHNITIUM_CACERT", "/env/ca.pem")
	result := resolveTLSString("", "TECHNITIUM_CACERT")
	if result != "/env/ca.pem" {
		t.Errorf("env var should be fallback, got %q", result)
	}
}

func TestResolveTLSConfig_Default(t *testing.T) {
	result := resolveTLSString("", "TECHNITIUM_CACERT")
	if result != "" {
		t.Errorf("should return empty when neither HCL nor env set, got %q", result)
	}
}

func TestResolveTLSBool_HCLWinsOverEnv(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "true")
	result, err := resolveTLSBool(ptrBool(false), "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil { t.Fatal(err) }
	if result != false { t.Error("HCL false should win over env true") }
}

func TestResolveTLSBool_EnvFallback(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "true")
	result, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil { t.Fatal(err) }
	if result != true { t.Error("env var should be used as fallback") }
}

func TestResolveTLSBool_InvalidEnvVar(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "maybe")
	_, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err == nil { t.Error("expected error for invalid bool env var") }
}

func TestResolveTLSBool_Default(t *testing.T) {
	result, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil { t.Fatal(err) }
	if result != false { t.Error("should return default when neither HCL nor env set") }
}

func TestResolveTLSMinVersion_EnvInvalid(t *testing.T) {
	t.Setenv("TECHNITIUM_TLS_MIN_VERSION", "1.1")
	_, err := resolveTLSMinVersion("", "TECHNITIUM_TLS_MIN_VERSION", "1.3")
	if err == nil { t.Error("expected error for invalid TLS min version from env") }
}

func ptrBool(b bool) *bool { return &b }

func TestBuildTLSDiagnostic_VersionMismatch_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrVersionMismatch}, "https://dns.example.com", false, false)
	if !strings.Contains(msg, "tls_min_version") { t.Error("should suggest tls_min_version") }
	if !strings.Contains(msg, "skip_tls_verify") { t.Error("non-STIG should offer skip_tls_verify") }
}

func TestBuildTLSDiagnostic_VersionMismatch_STIG(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrVersionMismatch}, "https://dns.example.com", true, false)
	if !strings.Contains(msg, "tls_min_version") { t.Error("should suggest tls_min_version") }
	if strings.Contains(msg, "skip_tls_verify") { t.Error("STIG should NOT offer skip_tls_verify") }
}

func TestBuildTLSDiagnostic_VersionMismatch_NSS(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrVersionMismatch}, "https://dns.example.com", true, true)
	if strings.Contains(msg, "tls_min_version") { t.Error("NSS should NOT offer tls_min_version fallback") }
	if strings.Contains(msg, "skip_tls_verify") { t.Error("NSS should NOT offer skip_tls_verify") }
	if !strings.Contains(msg, "Upgrade") || !strings.Contains(msg, "TLS 1.3") { t.Error("NSS should only suggest upgrading the server") }
}

func TestBuildTLSDiagnostic_UnknownAuthority_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrUnknownAuthority}, "https://dns.example.com", false, false)
	if !strings.Contains(msg, "ca_cert_file") { t.Error("should suggest ca_cert_file") }
	if !strings.Contains(msg, "ca_cert_dir") { t.Error("should suggest ca_cert_dir") }
	if !strings.Contains(msg, "skip_tls_verify") { t.Error("non-STIG should offer skip_tls_verify") }
}

func TestBuildTLSDiagnostic_UnknownAuthority_NSS(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrUnknownAuthority}, "https://dns.example.com", true, true)
	if !strings.Contains(msg, "ca_cert_file") { t.Error("should suggest ca_cert_file") }
	if strings.Contains(msg, "skip_tls_verify") { t.Error("NSS should NOT offer skip_tls_verify") }
}

func TestBuildTLSDiagnostic_CertificateInvalid_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrCertificateInvalid}, "https://dns.example.com", false, false)
	if !strings.Contains(msg, "ca_cert_file") || !strings.Contains(msg, "ca_cert_dir") { t.Error("should suggest verifying correct CA chain") }
	if !strings.Contains(msg, "skip_tls_verify") { t.Error("non-STIG should offer skip_tls_verify") }
}

func TestBuildTLSDiagnostic_NotTLS(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrNotTLS}, "https://dns.example.com", false, false)
	if msg != "" { t.Error("non-TLS errors should return empty (pass through original error)") }
}
