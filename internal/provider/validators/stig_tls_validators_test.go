// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"
)

func TestValidateTLSEnabled_HTTP_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"server_url": "http://dns.example.com"})
	if validateTLSEnabled(context.Background(), accessor) {
		t.Error("HTTP URL should fail TLS enabled check")
	}
}

func TestValidateTLSEnabled_HTTPS_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"server_url": "https://dns.example.com"})
	if !validateTLSEnabled(context.Background(), accessor) {
		t.Error("HTTPS URL should pass TLS enabled check")
	}
}

func TestValidateTLSEnabled_NullURL_Passes(t *testing.T) {
	accessor := NewMockAccessor(nil)
	if !validateTLSEnabled(context.Background(), accessor) {
		t.Error("null URL should pass (cannot validate)")
	}
}

func TestValidateTLSMinVersion_12_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"tls_min_version": "1.2"})
	if validateTLSMinVersion(context.Background(), accessor) {
		t.Error("TLS 1.2 should fail min version check")
	}
}

func TestValidateTLSMinVersion_13_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"tls_min_version": "1.3"})
	if !validateTLSMinVersion(context.Background(), accessor) {
		t.Error("TLS 1.3 should pass min version check")
	}
}

func TestValidateTLSMinVersion_Null_Passes(t *testing.T) {
	accessor := NewMockAccessor(nil)
	if !validateTLSMinVersion(context.Background(), accessor) {
		t.Error("null (default 1.3) should pass")
	}
}

func TestValidateTLSVerification_SkipTrue_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"skip_tls_verify": true})
	if validateTLSVerification(context.Background(), accessor) {
		t.Error("skip_tls_verify=true should fail verification check")
	}
}

func TestValidateTLSVerification_SkipFalse_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{"skip_tls_verify": false})
	if !validateTLSVerification(context.Background(), accessor) {
		t.Error("skip_tls_verify=false should pass")
	}
}

func TestValidateTLSVerification_Null_Passes(t *testing.T) {
	accessor := NewMockAccessor(nil)
	if !validateTLSVerification(context.Background(), accessor) {
		t.Error("null (default false) should pass")
	}
}
