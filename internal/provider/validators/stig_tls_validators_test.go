// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import "testing"

// ---------------------------------------------------------------------------
// Provider TLS validators — declarative test suite
// ---------------------------------------------------------------------------

func TestTLSValidators(t *testing.T) {
	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-028 TLS enabled",
		Fn:              validateTLSEnabled,
		Attribute:       "server_url",
		CompliantVal:    "https://dns.example.com",
		NonCompliantVal: "http://dns.example.com",
		NullCompliant:   true,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-028 TLS min version",
		Fn:              validateTLSMinVersion,
		Attribute:       "tls_min_version",
		CompliantVal:    "1.3",
		NonCompliantVal: "1.2",
		NullCompliant:   true,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-028 TLS verification",
		Fn:              validateTLSVerification,
		Attribute:       "skip_tls_verify",
		CompliantVal:    false,
		NonCompliantVal: true,
		NullCompliant:   true,
	})
}
