// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"fmt"
)

// validRecordTypes is the set of record types supported by the provider.
var validRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"NS": true, "PTR": true, "SRV": true, "TXT": true, "CAA": true,
}

// registerRecordRules adds all DNS record validation rules to the registry.
func registerRecordRules(r *Registry) {
	r.Register(validateRecordType())
	r.Register(validateARecord())
	r.Register(validateAAAARecord())
	r.Register(validateTXTRecord())
	r.Register(validateCNAMERecord())
	r.Register(validateMXRecord())
	r.Register(validateNSRecord())
	r.Register(validatePTRRecord())
	r.Register(validateSRVRecord())
	r.Register(validateCAARecord())
}

// DefaultRegistry returns a registry pre-loaded with all built-in validation rules.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	registerRecordRules(r)
	return r
}

// ---------------------------------------------------------------------------
// Record type validator
// ---------------------------------------------------------------------------

func validateRecordType() ValidationRule {
	return ValidationRule{
		Name:        "record_type",
		Description: "Validates the record type is one of the 9 supported types",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok {
				return nil
			}
			if !validRecordTypes[rt] {
				return []Finding{{
					Attribute: "type",
					Summary:   fmt.Sprintf("Invalid record type: %q", rt),
					Detail:    "Supported record types are: A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA (case-sensitive).",
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// A record
// ---------------------------------------------------------------------------

func validateARecord() ValidationRule {
	return ValidationRule{
		Name:        "a_record_ipv4",
		Description: "A record value must be a valid IPv4 address",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "A" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidIPv4(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid A record value: %q is not a valid IPv4 address", value),
					Detail:    `A records require a valid IPv4 address (e.g., "192.0.2.1").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// AAAA record
// ---------------------------------------------------------------------------

func validateAAAARecord() ValidationRule {
	return ValidationRule{
		Name:        "aaaa_record_ipv6",
		Description: "AAAA record value must be a valid IPv6 address",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "AAAA" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidIPv6(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid AAAA record value: %q is not a valid IPv6 address", value),
					Detail:    `AAAA records require a valid IPv6 address (e.g., "2001:db8::1").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TXT record
// ---------------------------------------------------------------------------

func validateTXTRecord() ValidationRule {
	return ValidationRule{
		Name:        "txt_record_nonempty",
		Description: "TXT record value must not be empty",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "TXT" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if value == "" {
				return []Finding{{
					Attribute: "value",
					Summary:   "Invalid TXT record value: value must not be empty",
					Detail:    `TXT records require a non-empty text value (e.g., "v=spf1 -all").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// Stubs — implemented in Tasks 5 and 6
// ---------------------------------------------------------------------------

func validateCNAMERecord() ValidationRule {
	return ValidationRule{Name: "cname_record_fqdn", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}

func validateMXRecord() ValidationRule {
	return ValidationRule{Name: "mx_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}

func validateNSRecord() ValidationRule {
	return ValidationRule{Name: "ns_record_fqdn", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}

func validatePTRRecord() ValidationRule {
	return ValidationRule{Name: "ptr_record_hostname", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}

func validateSRVRecord() ValidationRule {
	return ValidationRule{Name: "srv_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}

func validateCAARecord() ValidationRule {
	return ValidationRule{Name: "caa_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
