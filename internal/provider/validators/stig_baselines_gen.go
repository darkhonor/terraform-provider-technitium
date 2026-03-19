// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

// Code generated from DISA STIG data; DO NOT EDIT.
// Source: BIND 9.x STIG V3R1, Windows Server 2022 DNS STIG V2R3
// Generated: 2026-03-19

package validators

import "context"

// TargetResource identifies which Terraform resource type a requirement applies to.
type TargetResource int

const (
	ResourceZone TargetResource = iota
	ResourceRecord
	ResourceServerSettings
	ResourceTSIGKey
	TargetProvider TargetResource = 4
)

// CheckType identifies when a compliance check is evaluated.
type CheckType int

const (
	StatelessCheck CheckType = iota // terraform validate
	StatefulCheck                   // terraform plan (ModifyPlan)
	BothChecks                      // both hooks
)

// STIGProvenance records the originating STIG rule for a requirement.
type STIGProvenance struct {
	RuleID      string
	BenchmarkID string
	Title       string
}

// DNSSecurityRequirement represents a single STIG-derived DNS security requirement.
type DNSSecurityRequirement struct {
	ID         string
	Title      string
	Severity   string   // "high" or "medium"
	Controls   []string // NIST 800-53 controls
	CCIs       []string // Control Correlation Identifiers
	Provenance []STIGProvenance
	CheckType  CheckType
}

// StatelessValidator is a function that checks compliance from configuration alone.
type StatelessValidator func(ctx context.Context, config ConfigAccessor) bool

// StatefulValidator is a function that checks compliance using both plan and state.
type StatefulValidator func(ctx context.Context, plan PlanAccessor, state StateAccessor) bool

// ValidatorBinding associates a requirement with its implementation.
type ValidatorBinding struct {
	RequirementID string
	Resource      TargetResource
	Attributes    []string
	StatelessFn   StatelessValidator
	StatefulFn    StatefulValidator
	Implemented   bool
}

// BaselineMembership maps NIST 800-53 controls to their minimum baseline level.
var BaselineMembership = map[string]string{
	"SC-20": "LOW",
	"SC-21": "LOW",
	"SC-22": "LOW",
	"SC-5":  "LOW",
	"SC-8":  "MODERATE",
	"SC-13": "LOW",
	"SC-23": "MODERATE",
	"SC-24": "HIGH",
	"AC-10": "HIGH",
	"AU-3":  "LOW",
	"AU-9":  "LOW",
	"AU-10": "HIGH",
	"AU-12": "LOW",
	"CM-6":  "LOW",
	"IA-3":  "MODERATE",
	"IA-5":  "LOW",
	"SI-6":  "HIGH",
	"SI-10": "MODERATE",
}

// DNSSecurityRequirements is the authoritative list of all DNS security requirements
// derived from DISA STIG data for BIND 9.x and Windows Server 2022 DNS.
var DNSSecurityRequirements = []DNSSecurityRequirement{
	// -------------------------------------------------------------------------
	// HIGH Severity
	// -------------------------------------------------------------------------
	{
		ID:       "DNS-REQ-001",
		Title:    "DNSSEC must be enabled for authoritative zones",
		Severity: "high",
		Controls: []string{"SC-20", "SC-21", "SC-23", "SC-8", "AU-10", "CM-6", "SI-10"},
		CCIs: []string{
			"CCI-001178", "CCI-001663", "CCI-002462", "CCI-002463", "CCI-002464",
			"CCI-002465", "CCI-002466", "CCI-002467", "CCI-002468", "CCI-001184",
			"CCI-002420", "CCI-002422", "CCI-001901", "CCI-001902", "CCI-001904",
			"CCI-000366", "CCI-001310",
		},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001650",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "A BIND 9.x server implementation must maintain the integrity and confidentiality of DNS information...",
			},
			{
				RuleID:      "WDNS-22-000019",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "The Windows DNS Server must be configured to enable DNSSEC Resource Records (RRs).",
			},
		},
		CheckType: BothChecks,
	},
	{
		ID:       "DNS-REQ-002",
		Title:    "Server-to-server transactions must use crypto auth (TSIG)",
		Severity: "high",
		Controls: []string{"IA-3", "SC-8"},
		CCIs:     []string{"CCI-000778", "CCI-001958", "CCI-001967", "CCI-002418", "CCI-002421"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002010",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "The BIND 9.x server implementation must uniquely identify and authenticate the other DNS server...",
			},
			{
				RuleID:      "WDNS-22-000062",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "The Windows DNS Server must protect the authenticity of dynamic updates via transaction signing.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-003",
		Title:    "Audit records must be sent to remote syslog",
		Severity: "high",
		Controls: []string{"AU-9"},
		CCIs:     []string{"CCI-001348"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001910",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "The BIND 9.x server implementation must be configured with a channel to send audit records to at least two remote syslogs.",
			},
		},
		CheckType: StatelessCheck,
	},
	// -------------------------------------------------------------------------
	// MEDIUM Severity — Implemented
	// -------------------------------------------------------------------------
	{
		ID:       "DNS-REQ-004",
		Title:    "Zone transfers restricted to authorized secondaries",
		Severity: "medium",
		Controls: []string{"AC-10"},
		CCIs:     []string{"CCI-000054"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001010",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Zone transfers restricted to authorized secondaries.",
			},
			{
				RuleID:      "WDNS-22-000037",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Zone transfers restricted to authorized secondaries.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-005",
		Title:    "Recursion prohibited on authoritative name servers",
		Severity: "medium",
		Controls: []string{"CM-6", "SC-5"},
		CCIs:     []string{"CCI-000366", "CCI-001094"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001380",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Recursion prohibited on authoritative name servers.",
			},
			{
				RuleID:      "WDNS-22-000009",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Recursion prohibited on authoritative name servers.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-006",
		Title:    "Caching recursion restricted to known clients",
		Severity: "medium",
		Controls: []string{"SC-5"},
		CCIs:     []string{"CCI-001094"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001740",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Caching recursion restricted to known clients.",
			},
			{
				RuleID:      "WDNS-22-000011",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Caching recursion restricted to known clients.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-007",
		Title:    "Query logging enabled",
		Severity: "medium",
		Controls: []string{"AU-12", "AU-3", "SC-24", "SI-6"},
		CCIs:     []string{"CCI-000169", "CCI-000133", "CCI-000134", "CCI-001665", "CCI-001294"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001110",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Query logging enabled.",
			},
			{
				RuleID:      "WDNS-22-000004",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Query logging enabled.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-008",
		Title:    "Logging must not be null",
		Severity: "medium",
		Controls: []string{"AU-9"},
		CCIs:     []string{"CCI-001348"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001920",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Logging must not be null.",
			},
			{
				RuleID:      "WDNS-22-000004",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Logging must not be null.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-009",
		Title:    "Audit logs written to local file",
		Severity: "medium",
		Controls: []string{"AU-9"},
		CCIs:     []string{"CCI-001348"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001900",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Audit logs written to local file.",
			},
			{
				RuleID:      "WDNS-22-000004",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Audit logs written to local file.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-010",
		Title:    "Log file retention meets minimum",
		Severity: "medium",
		Controls: []string{"AU-9"},
		CCIs:     []string{"CCI-001348"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001890",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Log file retention meets minimum.",
			},
			{
				RuleID:      "WDNS-22-000115",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Log file retention meets minimum.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-011",
		Title:    "NSEC3 required for zone non-existence proofs",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001270",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "NSEC3 required for zone non-existence proofs.",
			},
			{
				RuleID:      "WDNS-22-000019",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "NSEC3 required for zone non-existence proofs (implied).",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-012",
		Title:    "FIPS-validated cryptography for DNSSEC",
		Severity: "medium",
		Controls: []string{"SC-13"},
		CCIs:     []string{"CCI-002450"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002050",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "FIPS-validated cryptography for DNSSEC.",
			},
			{
				RuleID:      "WDNS-22-000072",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "FIPS-validated cryptography for DNSSEC.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-013",
		Title:    "Forwarder restrictions (US govt controlled only)",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001360",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Forwarder restrictions (US govt controlled only).",
			},
			{
				RuleID:      "WDNS-22-000010",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Forwarder restrictions (US govt controlled only).",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-014",
		Title:    "QNAME minimization enabled",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002440",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "QNAME minimization enabled.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-015",
		Title:    "Query name randomization (0x20 encoding)",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001490",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Query name randomization (0x20 encoding).",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-016",
		Title:    "Primary servers notify authorized secondaries",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001390",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Primary servers notify authorized secondaries.",
			},
			{
				RuleID:      "WDNS-22-000068",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Primary servers notify authorized secondaries.",
			},
		},
		CheckType: StatelessCheck,
	},
	// -------------------------------------------------------------------------
	// MEDIUM Severity — Not Yet Implemented
	// -------------------------------------------------------------------------
	{
		ID:       "DNS-REQ-017",
		Title:    "Separate TSIG key-pairs per server pair",
		Severity: "medium",
		Controls: []string{"IA-3"},
		CCIs:     []string{"CCI-000778"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001700",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Separate TSIG key-pairs per server pair.",
			},
			{
				RuleID:      "WDNS-22-000035",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Separate TSIG key-pairs per server pair.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-018",
		Title:    "Unique TSIG key per communicating host pair",
		Severity: "medium",
		Controls: []string{"IA-5"},
		CCIs:     []string{"CCI-000186"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001190",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Unique TSIG key per communicating host pair.",
			},
			{
				RuleID:      "WDNS-22-000035",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Unique TSIG key per communicating host pair.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-019",
		Title:    "TSIG/DNSSEC key rotation within one year",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001610",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "TSIG/DNSSEC key rotation within one year.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-020",
		Title:    "CNAME records must not cross to lesser security zones",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001580",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "CNAME records must not cross to lesser security zones.",
			},
			{
				RuleID:      "WDNS-22-000030",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "CNAME records must not cross to lesser security zones.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-021",
		Title:    "Zone RRs must not reference FQDNs in other zones",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001590",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Zone RRs must not reference FQDNs in other zones.",
			},
			{
				RuleID:      "WDNS-22-000029",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Zone RRs must not reference FQDNs in other zones.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-022",
		Title:    "Secure delegation via DS records for child zones",
		Severity: "medium",
		Controls: []string{"SC-20"},
		CCIs:     []string{"CCI-001179"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-001770",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Secure delegation via DS records for child zones.",
			},
			{
				RuleID:      "WDNS-22-000051",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Secure delegation via DS records for child zones.",
			},
		},
		CheckType: StatefulCheck,
	},
	{
		ID:       "DNS-REQ-023",
		Title:    "Response rate limiting enabled",
		Severity: "medium",
		Controls: []string{"SC-5"},
		CCIs:     []string{"CCI-001095"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "WDNS-22-000120",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Response rate limiting enabled.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-024",
		Title:    "Fetches-per-zone rate limiting",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002450",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Fetches-per-zone rate limiting.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-025",
		Title:    "Fetches-per-server rate limiting",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002460",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Fetches-per-server rate limiting.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-026",
		Title:    "DNS cookies enabled",
		Severity: "medium",
		Controls: []string{"CM-6"},
		CCIs:     []string{"CCI-000366"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002470",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "DNS cookies enabled.",
			},
		},
		CheckType: StatelessCheck,
	},
	{
		ID:       "DNS-REQ-027",
		Title:    "Dynamic update client limits",
		Severity: "medium",
		Controls: []string{"AC-10"},
		CCIs:     []string{"CCI-000054"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "BIND-9X-002480",
				BenchmarkID: "BIND_9-x_STIG",
				Title:       "Dynamic update client limits.",
			},
			{
				RuleID:      "WDNS-22-000001",
				BenchmarkID: "MS_Windows_Server_2022_DNS_STIG",
				Title:       "Dynamic update client limits.",
			},
		},
		CheckType: StatelessCheck,
	},
	// -------------------------------------------------------------------------
	// Provider-Level Requirements
	// -------------------------------------------------------------------------
	{
		ID:       "DNS-REQ-028",
		Title:    "Management plane connections must use encrypted transport (TLS)",
		Severity: "medium",
		Controls: []string{"SC-8"},
		CCIs:     []string{"CCI-002418", "CCI-002420", "CCI-002421"},
		Provenance: []STIGProvenance{
			{
				RuleID:      "SV-270286r1_rule",
				BenchmarkID: "DNS_Policy",
				Title:       "Management connections to DNS infrastructure must use encrypted transport",
			},
		},
		CheckType: StatelessCheck,
	},
}

// AllRequirementIDs returns the IDs of all defined DNS security requirements.
func AllRequirementIDs() []string {
	ids := make([]string, len(DNSSecurityRequirements))
	for i, req := range DNSSecurityRequirements {
		ids[i] = req.ID
	}
	return ids
}

// GeneratedAt is the timestamp when this file was generated.
var GeneratedAt = "2026-03-19T00:00:00Z"

// GeneratedFrom identifies the source STIG documents used for generation.
var GeneratedFrom = "security-mcp: BIND_9-x_STIG V3R1 (2025-07-14), MS_Windows_Server_2022_DNS_STIG V2R3 (2025-04-02), NIST_800_53_R5"
