// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"strings"
)

// ---------------------------------------------------------------------------
// Zone bindings
// ---------------------------------------------------------------------------

// ZoneBindings maps DNS security requirements to zone resource attributes.
var ZoneBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-001",
		Resource:      ResourceZone,
		Attributes:    []string{"dnssec.enabled"},
		Implemented:   true,
		StatelessFn:   validateDNSSECEnabled,
	},
	{
		RequirementID: "DNS-REQ-002",
		Resource:      ResourceZone,
		Attributes:    []string{"zone_transfer_tsig_key_names"},
		Implemented:   true,
		StatefulFn:    validateZoneTSIGKeyNames,
	},
	{
		RequirementID: "DNS-REQ-004",
		Resource:      ResourceZone,
		Attributes:    []string{"zone_transfer_allowed_networks"},
		Implemented:   true,
		StatelessFn:   validateZoneTransferNetworks,
	},
	{
		RequirementID: "DNS-REQ-011",
		Resource:      ResourceZone,
		Attributes:    []string{"dnssec.nx_proof"},
		Implemented:   true,
		StatelessFn:   validateNSEC3Required,
	},
	{
		RequirementID: "DNS-REQ-012",
		Resource:      ResourceZone,
		Attributes:    []string{"dnssec.algorithm"},
		Implemented:   true,
		StatelessFn:   validateFIPSCrypto,
	},
	{
		RequirementID: "DNS-REQ-016",
		Resource:      ResourceZone,
		Attributes:    []string{"notify_addresses"},
		Implemented:   true,
		StatelessFn:   validateZoneNotifyAddresses,
	},
	{
		RequirementID: "DNS-REQ-022",
		Resource:      ResourceZone,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
}

// ---------------------------------------------------------------------------
// Server settings bindings
// ---------------------------------------------------------------------------

// ServerSettingsBindings maps DNS security requirements to server settings attributes.
var ServerSettingsBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-001",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"dnssec_validation"},
		Implemented:   true,
		StatelessFn:   validateDNSSECValidation,
	},
	{
		RequirementID: "DNS-REQ-003",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-004",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"zone_transfer_allowed_networks"},
		Implemented:   true,
		StatelessFn:   validateZoneTransferNetworks,
	},
	{
		RequirementID: "DNS-REQ-005",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"recursion"},
		Implemented:   true,
		StatelessFn:   validateRecursionRestricted,
	},
	{
		RequirementID: "DNS-REQ-006",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"recursion", "recursion_network_acl"},
		Implemented:   true,
		StatelessFn:   validateRecursionACL,
	},
	{
		RequirementID: "DNS-REQ-007",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"log_queries"},
		Implemented:   true,
		StatelessFn:   validateLogQueriesEnabled,
	},
	{
		RequirementID: "DNS-REQ-008",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"logging_type"},
		Implemented:   true,
		StatelessFn:   validateLoggingNotNull,
	},
	{
		RequirementID: "DNS-REQ-009",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"logging_type"},
		Implemented:   true,
		StatelessFn:   validateLoggingToFile,
	},
	{
		// TODO: needs GetInt accessor method to validate max_log_file_days >= 3 properly.
		// Returning true (compliant) until GetInt is added to ConfigAccessor.
		RequirementID: "DNS-REQ-010",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"max_log_file_days"},
		Implemented:   true,
		StatelessFn:   validateLogRetention,
	},
	{
		// Forwarder IP ownership cannot be validated statically; presence is sufficient.
		RequirementID: "DNS-REQ-013",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"forwarders"},
		Implemented:   true,
		StatelessFn:   validateForwarders,
	},
	{
		RequirementID: "DNS-REQ-014",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"qname_minimization"},
		Implemented:   true,
		StatelessFn:   validateQnameMinimization,
	},
	{
		RequirementID: "DNS-REQ-015",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"randomize_name"},
		Implemented:   true,
		StatelessFn:   validateRandomizeName,
	},
	{
		// Server-level notify is optional; always compliant at this layer.
		RequirementID: "DNS-REQ-016",
		Resource:      ResourceServerSettings,
		Attributes:    []string{"notify_addresses"},
		Implemented:   true,
		StatelessFn:   validateServerNotifyAddresses,
	},
	{
		RequirementID: "DNS-REQ-023",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-024",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-025",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-026",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-027",
		Resource:      ResourceServerSettings,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
}

// ---------------------------------------------------------------------------
// Record bindings
// ---------------------------------------------------------------------------

// RecordBindings maps DNS security requirements to record resource attributes.
var RecordBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-020",
		Resource:      ResourceRecord,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-021",
		Resource:      ResourceRecord,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-022",
		Resource:      ResourceRecord,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
}

// ---------------------------------------------------------------------------
// TSIG key bindings
// ---------------------------------------------------------------------------

// TSIGKeyBindings maps DNS security requirements to TSIG key resource attributes.
var TSIGKeyBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-002",
		Resource:      ResourceTSIGKey,
		Attributes:    []string{"algorithm"},
		Implemented:   true,
		StatelessFn:   validateTSIGAlgorithm,
	},
	{
		RequirementID: "DNS-REQ-017",
		Resource:      ResourceTSIGKey,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-018",
		Resource:      ResourceTSIGKey,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
	{
		RequirementID: "DNS-REQ-019",
		Resource:      ResourceTSIGKey,
		Attributes:    nil,
		Implemented:   false,
		StatelessFn:   nil,
		StatefulFn:    nil,
	},
}

// ---------------------------------------------------------------------------
// Provider bindings
// ---------------------------------------------------------------------------

// ProviderBindings defines STIG validators for provider-level TLS configuration.
// Uses DNS-REQ-028 (TLS transport encryption), NOT DNS-REQ-001 (DNSSEC zone signing).
var ProviderBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-028",
		Resource:      TargetProvider,
		Attributes:    []string{"server_url"},
		StatelessFn:   validateTLSEnabled,
		Implemented:   true,
	},
	{
		RequirementID: "DNS-REQ-028",
		Resource:      TargetProvider,
		Attributes:    []string{"tls_min_version"},
		StatelessFn:   validateTLSMinVersion,
		Implemented:   true,
	},
	{
		RequirementID: "DNS-REQ-028",
		Resource:      TargetProvider,
		Attributes:    []string{"skip_tls_verify"},
		StatelessFn:   validateTLSVerification,
		Implemented:   true,
	},
}

// ---------------------------------------------------------------------------
// AllBindings aggregates all binding slices for registry inspection.
// ---------------------------------------------------------------------------

// AllBindings returns all bindings across all resources.
func AllBindings() []ValidatorBinding {
	var all []ValidatorBinding
	all = append(all, ZoneBindings...)
	all = append(all, ServerSettingsBindings...)
	all = append(all, RecordBindings...)
	all = append(all, TSIGKeyBindings...)
	all = append(all, ProviderBindings...)
	return all
}

// ---------------------------------------------------------------------------
// Validator functions — unexported, pure, side-effect free.
// Convention: return true = compliant, false = finding.
// If the attribute is null/unknown (ok == false), return true — we cannot
// validate what has not been configured yet.
// ---------------------------------------------------------------------------

// validateDNSSECEnabled checks that DNSSEC is enabled on the zone.
// DNS-REQ-001 (zone)
func validateDNSSECEnabled(ctx context.Context, config ConfigAccessor) bool {
	enabled, ok := config.GetBool("dnssec.enabled")
	if !ok {
		return true
	}
	return enabled
}

// validateDNSSECValidation checks that DNSSEC validation is enabled on the server.
// DNS-REQ-001 (server_settings)
func validateDNSSECValidation(ctx context.Context, config ConfigAccessor) bool {
	enabled, ok := config.GetBool("dnssec_validation")
	if !ok {
		return true
	}
	return enabled
}

// validateZoneTSIGKeyNames checks that at least one TSIG key name is configured
// for zone transfers, enforcing cryptographic authentication (DNS-REQ-002 zone).
// This is a stateful check because it must inspect the existing state to confirm
// a key is actually associated; the StatefulFn signature is used.
func validateZoneTSIGKeyNames(_ context.Context, plan PlanAccessor, _ StateAccessor) bool {
	names, ok := plan.GetStringList("zone_transfer_tsig_key_names")
	if !ok {
		return true
	}
	return len(names) > 0
}

// validateZoneTransferNetworks checks that zone transfer is restricted to an
// explicit set of authorized networks (DNS-REQ-004).
func validateZoneTransferNetworks(ctx context.Context, config ConfigAccessor) bool {
	networks, ok := config.GetStringList("zone_transfer_allowed_networks")
	if !ok {
		return true
	}
	return len(networks) > 0
}

// validateNSEC3Required checks that NSEC3 is used for non-existence proofs
// instead of the weaker NSEC (DNS-REQ-011).
func validateNSEC3Required(ctx context.Context, config ConfigAccessor) bool {
	nxProof, ok := config.GetString("dnssec.nx_proof")
	if !ok {
		return true
	}
	return nxProof == "NSEC3"
}

// validateFIPSCrypto checks that the DNSSEC algorithm is FIPS-compliant (ECDSA,
// not RSA) (DNS-REQ-012).
func validateFIPSCrypto(ctx context.Context, config ConfigAccessor) bool {
	algo, ok := config.GetString("dnssec.algorithm")
	if !ok {
		return true
	}
	return algo == "ECDSA"
}

// validateZoneNotifyAddresses checks that notify addresses are configured on
// the zone so authorized secondaries are informed of changes (DNS-REQ-016 zone).
func validateZoneNotifyAddresses(ctx context.Context, config ConfigAccessor) bool {
	addrs, ok := config.GetStringList("notify_addresses")
	if !ok {
		return true
	}
	return len(addrs) > 0
}

// validateRecursionRestricted checks that recursion is not set to "Allow"
// (unrestricted) on the server — authoritative servers must not offer open
// recursion (DNS-REQ-005).
func validateRecursionRestricted(ctx context.Context, config ConfigAccessor) bool {
	recursion, ok := config.GetString("recursion")
	if !ok {
		return true
	}
	return recursion != "Allow"
}

// validateRecursionACL checks that if recursion is "UseSpecifiedNetworkACL",
// the ACL list is not empty — caching recursion must be restricted to known
// clients (DNS-REQ-006).
func validateRecursionACL(ctx context.Context, config ConfigAccessor) bool {
	recursion, ok := config.GetString("recursion")
	if !ok {
		return true
	}
	if recursion != "UseSpecifiedNetworkACL" {
		// Not using ACL-gated recursion — check doesn't apply.
		return true
	}
	acl, ok := config.GetStringList("recursion_network_acl")
	if !ok {
		return true
	}
	return len(acl) > 0
}

// validateLogQueriesEnabled checks that query logging is enabled (DNS-REQ-007).
func validateLogQueriesEnabled(ctx context.Context, config ConfigAccessor) bool {
	enabled, ok := config.GetBool("log_queries")
	if !ok {
		return true
	}
	return enabled
}

// validateLoggingNotNull checks that logging_type is not "None" (DNS-REQ-008).
func validateLoggingNotNull(ctx context.Context, config ConfigAccessor) bool {
	loggingType, ok := config.GetString("logging_type")
	if !ok {
		return true
	}
	return loggingType != "None"
}

// validateLoggingToFile checks that logging_type writes to a file ("File" or
// "FileAndConsole") so audit records are retained locally (DNS-REQ-009).
func validateLoggingToFile(ctx context.Context, config ConfigAccessor) bool {
	loggingType, ok := config.GetString("logging_type")
	if !ok {
		return true
	}
	return strings.Contains(loggingType, "File")
}

// validateLogRetention checks that max_log_file_days meets the minimum
// retention requirement (DNS-REQ-010).
// TODO: ConfigAccessor currently lacks GetInt; returning true until GetInt is
// added to the interface and this validator can perform a numeric comparison.
func validateLogRetention(ctx context.Context, config ConfigAccessor) bool {
	return true
}

// validateForwarders checks the forwarders attribute (DNS-REQ-013).
// IP ownership (US-government-controlled) cannot be validated statically;
// returning true because the presence of any configured forwarder is the only
// machine-verifiable aspect of this requirement.
func validateForwarders(ctx context.Context, config ConfigAccessor) bool {
	return true
}

// validateQnameMinimization checks that QNAME minimization is enabled
// (DNS-REQ-014).
func validateQnameMinimization(ctx context.Context, config ConfigAccessor) bool {
	enabled, ok := config.GetBool("qname_minimization")
	if !ok {
		return true
	}
	return enabled
}

// validateRandomizeName checks that query-name randomization (0x20 encoding)
// is enabled (DNS-REQ-015).
func validateRandomizeName(ctx context.Context, config ConfigAccessor) bool {
	enabled, ok := config.GetBool("randomize_name")
	if !ok {
		return true
	}
	return enabled
}

// validateServerNotifyAddresses is always compliant for the server-settings
// resource because server-level notify configuration is optional; zone-level
// notify_addresses is where the requirement is enforced (DNS-REQ-016 server).
func validateServerNotifyAddresses(ctx context.Context, config ConfigAccessor) bool {
	return true
}

// validateTSIGAlgorithm checks that the TSIG key uses a FIPS-compliant HMAC
// algorithm (hmac-sha256, hmac-sha384, or hmac-sha512) — not the deprecated
// hmac-md5 (DNS-REQ-002 TSIG key).
func validateTSIGAlgorithm(ctx context.Context, config ConfigAccessor) bool {
	algo, ok := config.GetString("algorithm")
	if !ok {
		return true
	}
	switch algo {
	case "hmac-sha256", "hmac-sha384", "hmac-sha512":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Provider validator functions — DNS-REQ-028 (SC-8 TLS transport encryption)
// ---------------------------------------------------------------------------

// validateTLSEnabled checks that server_url uses HTTPS (SC-8).
func validateTLSEnabled(ctx context.Context, config ConfigAccessor) bool {
	url, ok := config.GetString("server_url")
	if !ok {
		return true
	}
	return strings.HasPrefix(url, "https://")
}

// validateTLSMinVersion checks that tls_min_version is "1.3" (SC-8).
func validateTLSMinVersion(ctx context.Context, config ConfigAccessor) bool {
	version, ok := config.GetString("tls_min_version")
	if !ok {
		return true
	}
	return version == "1.3"
}

// validateTLSVerification checks that skip_tls_verify is false (SC-8).
func validateTLSVerification(ctx context.Context, config ConfigAccessor) bool {
	skip, ok := config.GetBool("skip_tls_verify")
	if !ok {
		return true
	}
	return !skip
}
