// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"
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
