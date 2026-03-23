// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// DNS-REQ-001 (zone): DNSSEC enabled
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ001_Zone_DNSSECDisabled_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.enabled": false})
	if validateDNSSECEnabled(context.Background(), m) {
		t.Error("expected noncompliant when DNSSEC disabled")
	}
}

func TestValidator_DNSREQ001_Zone_DNSSECEnabled_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.enabled": true})
	if !validateDNSSECEnabled(context.Background(), m) {
		t.Error("expected compliant when DNSSEC enabled")
	}
}

func TestValidator_DNSREQ001_Zone_DNSSECUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{}) // no key = unknown
	if !validateDNSSECEnabled(context.Background(), m) {
		t.Error("expected compliant when DNSSEC unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-001 (server_settings): DNSSEC validation
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ001_Server_ValidationDisabled_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec_validation": false})
	if validateDNSSECValidation(context.Background(), m) {
		t.Error("expected noncompliant when dnssec_validation is false")
	}
}

func TestValidator_DNSREQ001_Server_ValidationEnabled_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec_validation": true})
	if !validateDNSSECValidation(context.Background(), m) {
		t.Error("expected compliant when dnssec_validation is true")
	}
}

func TestValidator_DNSREQ001_Server_ValidationUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateDNSSECValidation(context.Background(), m) {
		t.Error("expected compliant when dnssec_validation is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-002 (zone): TSIG key names (stateful)
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ002_Zone_NoTSIGKeys_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"zone_transfer_tsig_key_names": []string{}})
	if validateZoneTSIGKeyNames(context.Background(), m, m) {
		t.Error("expected noncompliant when zone_transfer_tsig_key_names is empty")
	}
}

func TestValidator_DNSREQ002_Zone_TSIGKeysSet_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"zone_transfer_tsig_key_names": []string{"key1"}})
	if !validateZoneTSIGKeyNames(context.Background(), m, m) {
		t.Error("expected compliant when zone_transfer_tsig_key_names has entries")
	}
}

func TestValidator_DNSREQ002_Zone_TSIGKeysUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateZoneTSIGKeyNames(context.Background(), m, m) {
		t.Error("expected compliant when zone_transfer_tsig_key_names is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-002 (TSIG key): algorithm compliance
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ002_TSIG_HMACMD5_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"algorithm": "hmac-md5"})
	if validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected noncompliant for hmac-md5")
	}
}

func TestValidator_DNSREQ002_TSIG_HMACSHA1_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"algorithm": "hmac-sha1"})
	if validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected noncompliant for hmac-sha1")
	}
}

func TestValidator_DNSREQ002_TSIG_HMACSHA256_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"algorithm": "hmac-sha256"})
	if !validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected compliant for hmac-sha256")
	}
}

func TestValidator_DNSREQ002_TSIG_HMACSHA384_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"algorithm": "hmac-sha384"})
	if !validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected compliant for hmac-sha384")
	}
}

func TestValidator_DNSREQ002_TSIG_HMACSHA512_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"algorithm": "hmac-sha512"})
	if !validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected compliant for hmac-sha512")
	}
}

func TestValidator_DNSREQ002_TSIG_AlgorithmUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateTSIGAlgorithm(context.Background(), m) {
		t.Error("expected compliant when algorithm is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-004: Zone transfer networks
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ004_EmptyNetworks_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"zone_transfer_allowed_networks": []string{}})
	if validateZoneTransferNetworks(context.Background(), m) {
		t.Error("expected noncompliant when zone_transfer_allowed_networks is empty")
	}
}

func TestValidator_DNSREQ004_NetworksSet_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"zone_transfer_allowed_networks": []string{"10.0.0.0/8"}})
	if !validateZoneTransferNetworks(context.Background(), m) {
		t.Error("expected compliant when zone_transfer_allowed_networks has entries")
	}
}

func TestValidator_DNSREQ004_NetworksUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateZoneTransferNetworks(context.Background(), m) {
		t.Error("expected compliant when zone_transfer_allowed_networks is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-005: Recursion restricted
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ005_RecursionAllow_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"recursion": "Allow"})
	if validateRecursionRestricted(context.Background(), m) {
		t.Error("expected noncompliant when recursion is Allow")
	}
}

func TestValidator_DNSREQ005_RecursionDeny_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"recursion": "Deny"})
	if !validateRecursionRestricted(context.Background(), m) {
		t.Error("expected compliant when recursion is Deny")
	}
}

func TestValidator_DNSREQ005_RecursionPrivateNetworks_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"recursion": "AllowOnlyForPrivateNetworks"})
	if !validateRecursionRestricted(context.Background(), m) {
		t.Error("expected compliant when recursion is AllowOnlyForPrivateNetworks")
	}
}

func TestValidator_DNSREQ005_RecursionACL_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"recursion": "UseSpecifiedNetworkACL"})
	if !validateRecursionRestricted(context.Background(), m) {
		t.Error("expected compliant when recursion is UseSpecifiedNetworkACL")
	}
}

func TestValidator_DNSREQ005_RecursionUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateRecursionRestricted(context.Background(), m) {
		t.Error("expected compliant when recursion is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-006: Recursion ACL gating
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ006_ACLModeEmptyACL_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"recursion":             "UseSpecifiedNetworkACL",
		"recursion_network_acl": []string{},
	})
	if validateRecursionACL(context.Background(), m) {
		t.Error("expected noncompliant when ACL mode is set but ACL list is empty")
	}
}

func TestValidator_DNSREQ006_ACLModeWithEntries_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"recursion":             "UseSpecifiedNetworkACL",
		"recursion_network_acl": []string{"10.0.0.0/8"},
	})
	if !validateRecursionACL(context.Background(), m) {
		t.Error("expected compliant when ACL mode has entries")
	}
}

func TestValidator_DNSREQ006_NonACLMode_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"recursion": "Deny"})
	if !validateRecursionACL(context.Background(), m) {
		t.Error("expected compliant when not in ACL recursion mode")
	}
}

func TestValidator_DNSREQ006_UnknownRecursion_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateRecursionACL(context.Background(), m) {
		t.Error("expected compliant when recursion is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-007: Query logging
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ007_LogQueriesDisabled_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"log_queries": false})
	if validateLogQueriesEnabled(context.Background(), m) {
		t.Error("expected noncompliant when log_queries is false")
	}
}

func TestValidator_DNSREQ007_LogQueriesEnabled_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"log_queries": true})
	if !validateLogQueriesEnabled(context.Background(), m) {
		t.Error("expected compliant when log_queries is true")
	}
}

func TestValidator_DNSREQ007_LogQueriesUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateLogQueriesEnabled(context.Background(), m) {
		t.Error("expected compliant when log_queries is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-008: Logging not null
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ008_LoggingNone_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "None"})
	if validateLoggingNotNull(context.Background(), m) {
		t.Error("expected noncompliant when logging_type is None")
	}
}

func TestValidator_DNSREQ008_LoggingFile_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "File"})
	if !validateLoggingNotNull(context.Background(), m) {
		t.Error("expected compliant when logging_type is File")
	}
}

func TestValidator_DNSREQ008_LoggingFileAndConsole_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "FileAndConsole"})
	if !validateLoggingNotNull(context.Background(), m) {
		t.Error("expected compliant when logging_type is FileAndConsole")
	}
}

func TestValidator_DNSREQ008_LoggingConsole_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "Console"})
	if !validateLoggingNotNull(context.Background(), m) {
		t.Error("expected compliant when logging_type is Console (not None)")
	}
}

func TestValidator_DNSREQ008_LoggingUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateLoggingNotNull(context.Background(), m) {
		t.Error("expected compliant when logging_type is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-009: Audit to file
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ009_LoggingConsoleOnly_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "Console"})
	if validateLoggingToFile(context.Background(), m) {
		t.Error("expected noncompliant for Console-only logging")
	}
}

func TestValidator_DNSREQ009_LoggingNone_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "None"})
	if validateLoggingToFile(context.Background(), m) {
		t.Error("expected noncompliant for None logging")
	}
}

func TestValidator_DNSREQ009_LoggingFile_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "File"})
	if !validateLoggingToFile(context.Background(), m) {
		t.Error("expected compliant when logging_type is File")
	}
}

func TestValidator_DNSREQ009_LoggingFileAndConsole_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": "FileAndConsole"})
	if !validateLoggingToFile(context.Background(), m) {
		t.Error("expected compliant when logging_type is FileAndConsole")
	}
}

func TestValidator_DNSREQ009_LoggingUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateLoggingToFile(context.Background(), m) {
		t.Error("expected compliant when logging_type is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-010: Log retention (stub — GetInt not yet in accessor)
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ010_AlwaysCompliant_Stub(t *testing.T) {
	// validateLogRetention always returns true pending GetInt accessor support.
	m := NewMockAccessor(map[string]interface{}{"max_log_file_days": "1"})
	if !validateLogRetention(context.Background(), m) {
		t.Error("expected stub validator to return true")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-011: NSEC3 required
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ011_NSEC_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.nx_proof": "NSEC"})
	if validateNSEC3Required(context.Background(), m) {
		t.Error("expected noncompliant when nx_proof is NSEC")
	}
}

func TestValidator_DNSREQ011_NSEC3_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.nx_proof": "NSEC3"})
	if !validateNSEC3Required(context.Background(), m) {
		t.Error("expected compliant when nx_proof is NSEC3")
	}
}

func TestValidator_DNSREQ011_NxProofUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateNSEC3Required(context.Background(), m) {
		t.Error("expected compliant when nx_proof is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-012: FIPS crypto
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ012_RSA_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.algorithm": "RSA"})
	if validateFIPSCrypto(context.Background(), m) {
		t.Error("expected noncompliant for RSA algorithm")
	}
}

func TestValidator_DNSREQ012_DSA_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.algorithm": "DSA"})
	if validateFIPSCrypto(context.Background(), m) {
		t.Error("expected noncompliant for DSA algorithm")
	}
}

func TestValidator_DNSREQ012_ECDSA_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.algorithm": "ECDSA"})
	if !validateFIPSCrypto(context.Background(), m) {
		t.Error("expected compliant for ECDSA algorithm")
	}
}

func TestValidator_DNSREQ012_AlgorithmUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateFIPSCrypto(context.Background(), m) {
		t.Error("expected compliant when algorithm is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-013: Forwarders (always compliant stub)
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ013_AlwaysCompliant_Stub(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateForwarders(context.Background(), m) {
		t.Error("expected stub validator to return true")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-014: QNAME minimization
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ014_QnameDisabled_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"qname_minimization": false})
	if validateQnameMinimization(context.Background(), m) {
		t.Error("expected noncompliant when qname_minimization is false")
	}
}

func TestValidator_DNSREQ014_QnameEnabled_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"qname_minimization": true})
	if !validateQnameMinimization(context.Background(), m) {
		t.Error("expected compliant when qname_minimization is true")
	}
}

func TestValidator_DNSREQ014_QnameUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateQnameMinimization(context.Background(), m) {
		t.Error("expected compliant when qname_minimization is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-015: Randomize name
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ015_RandomizeDisabled_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"randomize_name": false})
	if validateRandomizeName(context.Background(), m) {
		t.Error("expected noncompliant when randomize_name is false")
	}
}

func TestValidator_DNSREQ015_RandomizeEnabled_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"randomize_name": true})
	if !validateRandomizeName(context.Background(), m) {
		t.Error("expected compliant when randomize_name is true")
	}
}

func TestValidator_DNSREQ015_RandomizeUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateRandomizeName(context.Background(), m) {
		t.Error("expected compliant when randomize_name is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-016 (zone): notify addresses
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ016_Zone_EmptyAddresses_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"notify_addresses": []string{}})
	if validateZoneNotifyAddresses(context.Background(), m) {
		t.Error("expected noncompliant when notify_addresses is empty")
	}
}

func TestValidator_DNSREQ016_Zone_AddressesSet_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"notify_addresses": []string{"10.0.0.2"}})
	if !validateZoneNotifyAddresses(context.Background(), m) {
		t.Error("expected compliant when notify_addresses has entries")
	}
}

func TestValidator_DNSREQ016_Zone_AddressesUnknown_Compliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateZoneNotifyAddresses(context.Background(), m) {
		t.Error("expected compliant when notify_addresses is unknown/null")
	}
}

// ---------------------------------------------------------------------------
// DNS-REQ-016 (server): always compliant
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ016_Server_AlwaysCompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if !validateServerNotifyAddresses(context.Background(), m) {
		t.Error("expected server notify addresses validator to always return true")
	}
}

// ---------------------------------------------------------------------------
// Null-means-noncompliant tests (GitHub #8)
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ001_Zone_DNSSECNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.enabled": NullValue})
	if validateDNSSECEnabled(context.Background(), m) {
		t.Error("expected noncompliant when dnssec.enabled is null (omitted)")
	}
}

func TestValidator_DNSREQ011_NxProofNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.nx_proof": NullValue})
	if validateNSEC3Required(context.Background(), m) {
		t.Error("expected noncompliant when dnssec.nx_proof is null (omitted)")
	}
}

func TestValidator_DNSREQ012_AlgorithmNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec.algorithm": NullValue})
	if validateFIPSCrypto(context.Background(), m) {
		t.Error("expected noncompliant when dnssec.algorithm is null (omitted)")
	}
}

func TestValidator_DNSREQ004_ZoneTransferNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"zone_transfer_allowed_networks": NullValue})
	if validateZoneTransferNetworks(context.Background(), m) {
		t.Error("expected noncompliant when zone_transfer_allowed_networks is null (omitted)")
	}
}

func TestValidator_DNSREQ016_Zone_NotifyNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"notify_addresses": NullValue})
	if validateZoneNotifyAddresses(context.Background(), m) {
		t.Error("expected noncompliant when notify_addresses is null (omitted)")
	}
}

// ---------------------------------------------------------------------------
// Server settings: null-means-noncompliant tests (GitHub #8)
// ---------------------------------------------------------------------------

func TestValidator_DNSREQ001_Server_ValidationNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"dnssec_validation": NullValue})
	if validateDNSSECValidation(context.Background(), m) {
		t.Error("expected noncompliant when dnssec_validation is null (omitted)")
	}
}

func TestValidator_DNSREQ007_LogQueriesNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"log_queries": NullValue})
	if validateLogQueriesEnabled(context.Background(), m) {
		t.Error("expected noncompliant when log_queries is null (omitted)")
	}
}

func TestValidator_DNSREQ008_LoggingTypeNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": NullValue})
	if validateLoggingNotNull(context.Background(), m) {
		t.Error("expected noncompliant when logging_type is null (omitted)")
	}
}

func TestValidator_DNSREQ009_LoggingTypeNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"logging_type": NullValue})
	if validateLoggingToFile(context.Background(), m) {
		t.Error("expected noncompliant when logging_type is null (omitted) for file logging check")
	}
}

func TestValidator_DNSREQ014_QnameNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"qname_minimization": NullValue})
	if validateQnameMinimization(context.Background(), m) {
		t.Error("expected noncompliant when qname_minimization is null (omitted)")
	}
}

func TestValidator_DNSREQ015_RandomizeNull_Noncompliant(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"randomize_name": NullValue})
	if validateRandomizeName(context.Background(), m) {
		t.Error("expected noncompliant when randomize_name is null (omitted)")
	}
}
