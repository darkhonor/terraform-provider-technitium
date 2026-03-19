// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// testAccSTIGProviderConfig generates a provider config with STIG compliance settings.
func testAccSTIGProviderConfig(enforcement string, suppress []string, baseline string) string {
	suppressStr := "[]"
	if len(suppress) > 0 {
		items := ""
		for i, s := range suppress {
			if i > 0 {
				items += ", "
			}
			items += fmt.Sprintf("%q", s)
		}
		suppressStr = fmt.Sprintf("[%s]", items)
	}

	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"

  stig_compliance {
    enabled     = true
    enforcement = "%s"
    suppress    = %s

    categorization {
      baseline = "%s"
    }
  }
}
`, testAccAPIToken(), enforcement, suppressStr, baseline)
}

// testAccSTIGProviderConfigCIA generates provider config with per-objective categorization.
func testAccSTIGProviderConfigCIA(enforcement string, c, i, a string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"

  stig_compliance {
    enabled     = true
    enforcement = "%s"

    categorization {
      confidentiality = "%s"
      integrity       = "%s"
      availability    = "%s"
    }
  }
}
`, testAccAPIToken(), enforcement, c, i, a)
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

// TestAccSTIG_Suppress_DNSSECReq_PlanSucceeds verifies that suppressing
// DNS-REQ-001 downgrades the finding from error to warning in strict mode.
func TestAccSTIG_Suppress_DNSSECReq_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", []string{"DNS-REQ-001"}, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-suppress.example.com"
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`,
				// Suppressed → warning not error → plan succeeds
			},
		},
	})
}

// TestAccSTIG_LowBaseline_HighControlNotChecked verifies that at LOW baseline,
// controls that only appear at HIGH (e.g., AC-10) are not evaluated.
func TestAccSTIG_LowBaseline_HighControlNotChecked(t *testing.T) {
	// AC-10 (zone transfers) is HIGH baseline only.
	// At LOW baseline, this should NOT be checked.
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", nil, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-low-baseline.example.com"
  type = "Primary"
}
`,
				// No error — AC-10 not in scope at LOW baseline
			},
		},
	})
}

// TestAccSTIG_Strict_FullyCompliant_PlanSucceeds verifies that a fully
// compliant zone configuration passes strict enforcement without errors.
func TestAccSTIG_Strict_FullyCompliant_PlanSucceeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfig("strict", nil, "low") + `
resource "technitium_zone" "test" {
  name = "stig-test-compliant.example.com"
  type = "Primary"
}
`,
				// Default zone settings are STIG-hardened — should pass
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
data "technitium_zones" "test" {}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-028.*SC-8`),
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
data "technitium_zones" "test" {}
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
data "technitium_zones" "test" {}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-028.*SC-8`),
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
data "technitium_zones" "test" {}
`,
			},
		},
	})
}

// testAccSTIGProviderConfigHTTP generates a provider config with an HTTP
// server_url and the given STIG compliance settings.
func testAccSTIGProviderConfigHTTP(enforcement string, suppress []string, baseline string) string {
	suppressStr := "[]"
	if len(suppress) > 0 {
		items := make([]string, len(suppress))
		for i, s := range suppress {
			items[i] = fmt.Sprintf("%q", s)
		}
		suppressStr = fmt.Sprintf("[%s]", strings.Join(items, ", "))
	}
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
`, testAccAPIToken(), enforcement, suppressStr, baseline)
}

// testAccSTIGProviderConfigSkipTLS generates a provider config with an HTTPS
// server_url and skip_tls_verify = true and the given STIG compliance settings.
func testAccSTIGProviderConfigSkipTLS(enforcement string, suppress []string, baseline string) string {
	suppressStr := "[]"
	if len(suppress) > 0 {
		items := make([]string, len(suppress))
		for i, s := range suppress {
			items[i] = fmt.Sprintf("%q", s)
		}
		suppressStr = fmt.Sprintf("[%s]", strings.Join(items, ", "))
	}
	return fmt.Sprintf(`
provider "technitium" {
  server_url      = "https://localhost:5380"
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
`, testAccAPIToken(), enforcement, suppressStr, baseline)
}
