// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import "testing"

// ---------------------------------------------------------------------------
// Zone validators — declarative test suite
// ---------------------------------------------------------------------------

func TestZoneValidators(t *testing.T) {
	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-001 zone DNSSEC enabled",
		Fn:              validateDNSSECEnabled,
		Attribute:       "dnssec.enabled",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	RunStatefulValidatorTests(t, StatefulValidatorTestCase{
		Name:            "DNS-REQ-002 zone TSIG key names",
		Fn:              validateZoneTSIGKeyNames,
		Attribute:       "zone_transfer_tsig_key_names",
		CompliantVal:    []string{"key1"},
		NonCompliantVal: []string{},
		NullCompliant:   true,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-004 zone transfer networks",
		Fn:              validateZoneTransferNetworks,
		Attribute:       "zone_transfer_allowed_networks",
		CompliantVal:    []string{"10.0.0.0/8"},
		NonCompliantVal: []string{},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-011 NSEC3 required",
		Fn:              validateNSEC3Required,
		Attribute:       "dnssec.nx_proof",
		CompliantVal:    "NSEC3",
		NonCompliantVal: "NSEC",
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-012 FIPS crypto",
		Fn:              validateFIPSCrypto,
		Attribute:       "dnssec.algorithm",
		CompliantVal:    "ECDSA",
		NonCompliantVal: "RSA",
		CustomCases: []CustomTestCase{
			{Name: "DSA noncompliant", Attrs: map[string]interface{}{"dnssec.algorithm": "DSA"}, Compliant: false},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-016 zone notify addresses",
		Fn:              validateZoneNotifyAddresses,
		Attribute:       "notify_addresses",
		CompliantVal:    []string{"10.0.0.2"},
		NonCompliantVal: []string{},
	})
}

// ---------------------------------------------------------------------------
// Server settings validators — declarative test suite
// ---------------------------------------------------------------------------

func TestServerSettingsValidators(t *testing.T) {
	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-001 server DNSSEC validation",
		Fn:              validateDNSSECValidation,
		Attribute:       "dnssec_validation",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-005 recursion restricted",
		Fn:              validateRecursionRestricted,
		Attribute:       "recursion",
		CompliantVal:    "Deny",
		NonCompliantVal: "Allow",
		NullCompliant:   true,
		CustomCases: []CustomTestCase{
			{Name: "private networks compliant", Attrs: map[string]interface{}{"recursion": "AllowOnlyForPrivateNetworks"}, Compliant: true},
			{Name: "ACL mode compliant", Attrs: map[string]interface{}{"recursion": "UseSpecifiedNetworkACL"}, Compliant: true},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:          "DNS-REQ-006 recursion ACL",
		Fn:            validateRecursionACL,
		NullCompliant: true,
		// Multi-attribute — custom cases only (Attribute intentionally empty)
		CustomCases: []CustomTestCase{
			{Name: "ACL mode empty list noncompliant", Attrs: map[string]interface{}{"recursion": "UseSpecifiedNetworkACL", "recursion_network_acl": []string{}}, Compliant: false},
			{Name: "ACL mode with entries compliant", Attrs: map[string]interface{}{"recursion": "UseSpecifiedNetworkACL", "recursion_network_acl": []string{"10.0.0.0/8"}}, Compliant: true},
			{Name: "non-ACL mode compliant", Attrs: map[string]interface{}{"recursion": "Deny"}, Compliant: true},
			{Name: "unknown recursion compliant", Attrs: map[string]interface{}{}, Compliant: true},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-007 query logging",
		Fn:              validateLogQueriesEnabled,
		Attribute:       "log_queries",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-008 logging not null",
		Fn:              validateLoggingNotNull,
		Attribute:       "logging_type",
		CompliantVal:    "File",
		NonCompliantVal: "None",
		CustomCases: []CustomTestCase{
			{Name: "FileAndConsole compliant", Attrs: map[string]interface{}{"logging_type": "FileAndConsole"}, Compliant: true},
			{Name: "Console compliant (not None)", Attrs: map[string]interface{}{"logging_type": "Console"}, Compliant: true},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-009 logging to file",
		Fn:              validateLoggingToFile,
		Attribute:       "logging_type",
		CompliantVal:    "File",
		NonCompliantVal: "Console",
		CustomCases: []CustomTestCase{
			{Name: "FileAndConsole compliant", Attrs: map[string]interface{}{"logging_type": "FileAndConsole"}, Compliant: true},
			{Name: "None noncompliant", Attrs: map[string]interface{}{"logging_type": "None"}, Compliant: false},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name: "DNS-REQ-010 log retention (stub)",
		Fn:   validateLogRetention,
		// Stub always returns true — custom-only mode
		CustomCases: []CustomTestCase{
			{Name: "present compliant (stub)", Attrs: map[string]interface{}{"max_log_file_days": "30"}, Compliant: true},
			{Name: "null compliant (stub)", Attrs: map[string]interface{}{"max_log_file_days": NullValue}, Compliant: true},
			{Name: "unknown compliant (stub)", Attrs: map[string]interface{}{}, Compliant: true},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name: "DNS-REQ-013 forwarders (stub)",
		Fn:   validateForwarders,
		// Stub always returns true — custom-only mode
		CustomCases: []CustomTestCase{
			{Name: "present compliant (stub)", Attrs: map[string]interface{}{"forwarders": "any"}, Compliant: true},
			{Name: "null compliant (stub)", Attrs: map[string]interface{}{"forwarders": NullValue}, Compliant: true},
			{Name: "unknown compliant (stub)", Attrs: map[string]interface{}{}, Compliant: true},
		},
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-014 QNAME minimization",
		Fn:              validateQnameMinimization,
		Attribute:       "qname_minimization",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-015 randomize name",
		Fn:              validateRandomizeName,
		Attribute:       "randomize_name",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	RunValidatorTests(t, ValidatorTestCase{
		Name: "DNS-REQ-016 server notify (always compliant)",
		Fn:   validateServerNotifyAddresses,
		// Always returns true — custom-only mode
		CustomCases: []CustomTestCase{
			{Name: "present compliant", Attrs: map[string]interface{}{"notify_addresses": []string{"10.0.0.2"}}, Compliant: true},
			{Name: "null compliant", Attrs: map[string]interface{}{"notify_addresses": NullValue}, Compliant: true},
			{Name: "unknown compliant", Attrs: map[string]interface{}{}, Compliant: true},
		},
	})
}

// ---------------------------------------------------------------------------
// TSIG validators — declarative test suite
// ---------------------------------------------------------------------------

func TestTSIGValidators(t *testing.T) {
	RunValidatorTests(t, ValidatorTestCase{
		Name:            "DNS-REQ-002 TSIG algorithm",
		Fn:              validateTSIGAlgorithm,
		Attribute:       "algorithm",
		CompliantVal:    "hmac-sha256",
		NonCompliantVal: "hmac-md5",
		NullCompliant:   true,
		CustomCases: []CustomTestCase{
			{Name: "hmac-sha384 compliant", Attrs: map[string]interface{}{"algorithm": "hmac-sha384"}, Compliant: true},
			{Name: "hmac-sha512 compliant", Attrs: map[string]interface{}{"algorithm": "hmac-sha512"}, Compliant: true},
			{Name: "hmac-sha1 noncompliant", Attrs: map[string]interface{}{"algorithm": "hmac-sha1"}, Compliant: false},
		},
	})
}
