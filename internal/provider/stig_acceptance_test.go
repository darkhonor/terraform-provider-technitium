// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// testAccSTIGProviderConfig generates a provider config with STIG compliance settings.
// Server URL and CA cert come from environment variables via testAccProviderHCL_STIG,
// so the same helper works under both `make testacc-up` (HTTP) and `make testacc-up-tls` (HTTPS).
func testAccSTIGProviderConfig(enforcement string, suppress []string, baseline string) string {
	return testAccProviderHCL_STIG(enforcement, suppress, baseline)
}

// ---------------------------------------------------------------------------
// Zone tests
// ---------------------------------------------------------------------------

// TestAccSTIG_Strict_Zone_DNSSECDisabled_PlanFails verifies that strict mode
// blocks a zone with DNSSEC explicitly disabled (DNS-REQ-001).
func TestAccSTIG_Strict_Zone_DNSSECDisabled_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", nil, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-dnssec-disabled.example.com"
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-001.*DNSSEC must be enabled`),
			},
		},
	})
}

// TestAccSTIG_Warn_Zone_DNSSECDisabled_PlanSucceeds verifies that warn mode
// allows a non-compliant zone (DNSSEC disabled) without error.
func TestAccSTIG_Warn_Zone_DNSSECDisabled_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("warn", nil, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-warn.example.com"
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`,
				// No ExpectError — should succeed with warning only
			},
		},
	})
}

// TestAccSTIG_Silent_Zone_DNSSECDisabled_NoDiagnostic verifies that silent mode
// produces no diagnostics for a non-compliant zone.
func TestAccSTIG_Silent_Zone_DNSSECDisabled_NoDiagnostic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("silent", nil, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-silent.example.com"
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`,
				// No error, no warning visible in test
			},
		},
	})
}

// TestAccSTIG_Suppress_DNSSECReq_PlanSucceeds verifies that suppressing the
// DNSSEC-family requirements (DNS-REQ-001 enabled, DNS-REQ-011 NSEC3 nxproof,
// DNS-REQ-012 FIPS algorithm) downgrades each finding from error to warning
// in strict mode so the plan can proceed with DNSSEC explicitly disabled.
func TestAccSTIG_Suppress_DNSSECReq_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig(
					"strict",
					[]string{"DNS-REQ-001", "DNS-REQ-011", "DNS-REQ-012"},
					"low",
				) + `
resource "technitium_zone" "test" {
  name = "stig-test-suppress.example.com"
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`,
				// All DNSSEC reqs suppressed → warnings not errors → plan succeeds
			},
		},
	})
}

// TestAccSTIG_LowBaseline_HighControlNotChecked verifies that at the LOW
// baseline, a zone configured to satisfy DNSSEC validators passes strict
// enforcement without error. The implicit assertion is that any HIGH-only
// requirement is correctly skipped at LOW.
//
// DNS-REQ-002 (TSIG keys), DNS-REQ-004 (zone transfer ACL), and DNS-REQ-016
// (notify addresses) are suppressed because the corresponding zone-resource
// schema attributes are not yet exposed in this provider — the validators
// reference paths that the schema does not satisfy. Tracked in
// https://github.com/darkhonor/terraform-provider-technitium/issues/37 .
func TestAccSTIG_LowBaseline_HighControlNotChecked(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig(
					"strict",
					[]string{"DNS-REQ-002", "DNS-REQ-004", "DNS-REQ-016"},
					"low",
				) + `
resource "technitium_zone" "test" {
  name = "stig-test-low-baseline.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`,
				// No error — DNSSEC validators are satisfied; the suppressed
				// requirements correspond to zone attributes the provider
				// schema does not yet expose.
			},
		},
	})
}

// TestAccSTIG_Strict_FullyCompliant_PlanSucceeds verifies that a zone with
// DNSSEC fully configured (enabled, FIPS algorithm, NSEC3) passes strict
// enforcement at the LOW baseline. DNS-REQ-002, DNS-REQ-004, and DNS-REQ-016
// are suppressed for the same reason as in
// TestAccSTIG_LowBaseline_HighControlNotChecked.
func TestAccSTIG_Strict_FullyCompliant_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig(
					"strict",
					[]string{"DNS-REQ-002", "DNS-REQ-004", "DNS-REQ-016"},
					"low",
				) + `
resource "technitium_zone" "test" {
  name = "stig-test-compliant.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`,
				// DNSSEC validators satisfied → no errors.
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Server settings tests
// ---------------------------------------------------------------------------

// TestAccSTIG_ServerSettings_LoggingNone_PlanFails verifies that strict mode
// blocks logging_type = "None" (DNS-REQ-008).
func TestAccSTIG_ServerSettings_LoggingNone_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", nil, "low") + `
resource "technitium_server_settings" "test" {
  logging_type = "None"
}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-008.*Logging must not be null`),
			},
		},
	})
}

// TestAccSTIG_ServerSettings_RecursionAllow_PlanFails verifies that strict mode
// blocks recursion = "Allow" (DNS-REQ-005).
func TestAccSTIG_ServerSettings_RecursionAllow_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", nil, "low") + `
resource "technitium_server_settings" "test" {
  recursion = "Allow"
}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-005.*Recursion prohibited`),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// TLS provider-level validator tests
// ---------------------------------------------------------------------------

// TestAccSTIG_Strict_HTTP_PlanFails verifies that strict mode rejects an HTTP
// server_url before any network connectivity is attempted (DNS-REQ-028 / SC-8).
func TestAccSTIG_Strict_HTTP_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigHTTP("strict", nil, "moderate") + `
data "technitium_server_settings" "test" {}
`,
				ExpectError: regexp.MustCompile(`(?s)DNS-REQ-028.*SC-8`),
			},
		},
	})
}

// TestAccSTIG_Warn_HTTP_PlanSucceeds verifies that warn mode allows an HTTP
// server_url without blocking the plan.
func TestAccSTIG_Warn_HTTP_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigHTTP("warn", nil, "moderate") + `
data "technitium_server_settings" "test" {}
`,
			},
		},
	})
}

// TestAccSTIG_Strict_SkipTLSVerify_PlanFails verifies that strict mode rejects
// skip_tls_verify = true (DNS-REQ-028 / SC-8).
func TestAccSTIG_Strict_SkipTLSVerify_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigSkipTLS("strict", nil, "moderate") + `
data "technitium_server_settings" "test" {}
`,
				ExpectError: regexp.MustCompile(`(?s)DNS-REQ-028.*SC-8`),
			},
		},
	})
}

// TestAccSTIG_Suppress_TLSReq_SkipVerify_Succeeds verifies that suppressing
// DNS-REQ-028 downgrades the finding so skip_tls_verify does not block the plan.
func TestAccSTIG_Suppress_TLSReq_SkipVerify_Succeeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigSkipTLS("strict", []string{"DNS-REQ-028"}, "moderate") + `
data "technitium_server_settings" "test" {}
`,
			},
		},
	})
}

// testAccSTIGProviderConfigHTTP generates a provider config with an HTTP
// server_url and the given STIG compliance settings. The HTTP URL is hardcoded
// because these tests assert on the provider's HTTP-rejection behavior and
// must NOT pick up the TLS overrides used by `make testacc-up-tls`.
func testAccSTIGProviderConfigHTTP(enforcement string, suppress []string, baseline string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://localhost:5380"
  api_token  = %q

  stig_compliance {
    enabled     = true
    enforcement = %q
    suppress    = %s

    categorization {
      baseline = %q
    }
  }
}
`, testAccAPIToken(), enforcement, formatSuppressList(suppress), baseline)
}

// testAccSTIGProviderConfigSkipTLS generates a provider config with an HTTPS
// server_url and skip_tls_verify = true and the given STIG compliance settings.
// The URL and skip_tls_verify are hardcoded because these tests assert on the
// provider's skip_tls_verify-rejection behavior under strict mode.
//
// Tests using this helper that proceed past plan-time STIG validation (i.e.
// the suppress variants) require the HTTPS port from the TLS test container
// to be live — they will fail under `make testacc-up` (HTTP-only) and pass
// under `make testacc-up-tls`. Tests that expect a plan-time STIG rejection
// never reach the network and work under either target.
func testAccSTIGProviderConfigSkipTLS(enforcement string, suppress []string, baseline string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url      = "https://127.0.0.1:5443"
  api_token       = %q
  skip_tls_verify = true

  stig_compliance {
    enabled     = true
    enforcement = %q
    suppress    = %s

    categorization {
      baseline = %q
    }
  }
}
`, testAccAPIToken(), enforcement, formatSuppressList(suppress), baseline)
}
