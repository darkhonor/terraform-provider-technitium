// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used by acceptance tests.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"technitium": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccProviderHCL returns a `provider "technitium" { ... }` HCL block
// suitable for use in acceptance test configurations. Values are taken from
// environment variables so the same test config works against either the
// default HTTP test container or the HTTPS-enabled one (`make testacc-up-tls`).
//
// Environment variables consulted:
//
//	TECHNITIUM_SERVER_URL  defaults to "http://127.0.0.1:5380"
//	TECHNITIUM_CACERT      defaults to "" (ca_cert_file omitted from the block)
//	TECHNITIUM_API_TOKEN   resolved by testAccAPIToken()
//
// Tests that need to assert on a SPECIFIC provider configuration (for example,
// to test the provider's own behavior when given an HTTP URL or a self-signed
// cert with skip_tls_verify) should NOT use this helper — they should write
// their own provider block inline.
func testAccProviderHCL() string {
	return testAccProviderHCLWithExtras("")
}

// testAccProviderHCL_NSS returns an env-aware provider HCL block with NSS-mode
// STIG compliance enabled and the supplied per-objective categorization.
func testAccProviderHCL_NSS(confidentiality, integrity, availability string) string {
	extras := fmt.Sprintf(`

  stig_compliance {
    enabled = true
    nss     = true

    categorization {
      confidentiality = %q
      integrity       = %q
      availability    = %q
    }
  }`, confidentiality, integrity, availability)
	return testAccProviderHCLWithExtras(extras)
}

// testAccProviderHCL_STIG returns an env-aware provider HCL block with non-NSS
// STIG compliance enabled, parameterized by enforcement mode, suppression list
// (any DNS-REQ-XXX IDs to suppress), and baseline.
func testAccProviderHCL_STIG(enforcement string, suppress []string, baseline string) string {
	extras := fmt.Sprintf(`

  stig_compliance {
    enabled     = true
    enforcement = %q
    suppress    = %s

    categorization {
      baseline = %q
    }
  }`, enforcement, formatSuppressList(suppress), baseline)
	return testAccProviderHCLWithExtras(extras)
}

// formatSuppressList renders a string slice as an HCL list literal.
// formatSuppressList(nil) and formatSuppressList([]string{}) both return "[]".
func formatSuppressList(suppress []string) string {
	if len(suppress) == 0 {
		return "[]"
	}
	items := make([]string, len(suppress))
	for i, s := range suppress {
		items[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(items, ", ") + "]"
}

// testAccProviderHCLWithExtras is the common factory used by the public
// helpers above. It assembles the env-aware provider block and appends any
// supplied extra body (with the supplied indentation already applied).
func testAccProviderHCLWithExtras(extras string) string {
	serverURL := os.Getenv("TECHNITIUM_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:5380"
	}
	caCertLine := ""
	if ca := os.Getenv("TECHNITIUM_CACERT"); ca != "" {
		caCertLine = fmt.Sprintf("\n  ca_cert_file = %q", ca)
	}
	return fmt.Sprintf(`provider "technitium" {
  server_url = %q
  api_token  = %q%s%s
}
`, serverURL, testAccAPIToken(), caCertLine, extras)
}

func TestProviderSchema_NoError(t *testing.T) {
	p := New("test")()
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("provider schema returned errors: %v", schemaResp.Diagnostics)
	}

	// Verify key attributes exist
	attrs := schemaResp.Schema.Attributes
	for _, key := range []string{"server_url", "api_token", "skip_tls_verify"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("expected attribute %q in provider schema", key)
		}
	}

	// Verify stig_compliance block exists
	blocks := schemaResp.Schema.Blocks
	if _, ok := blocks["stig_compliance"]; !ok {
		t.Error("expected stig_compliance block in provider schema")
	}
}

func TestValidateCategorization_NSSWithBaseline(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("moderate"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, true)
	if !diags.HasError() {
		t.Error("expected error for NSS + baseline")
	}
}

func TestValidateCategorization_NSSMissingObjective(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("high"),
		Integrity:       types.StringValue("moderate"),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, true)
	if !diags.HasError() {
		t.Error("expected error for NSS with missing availability")
	}
}

func TestValidateCategorization_NSSValid(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("moderate"),
		Integrity:       types.StringValue("high"),
		Availability:    types.StringValue("moderate"),
	}
	result, diags := validateCategorization(cat, true)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if result.Confidentiality != "moderate" {
		t.Errorf("expected confidentiality=moderate, got %s", result.Confidentiality)
	}
	if result.Integrity != "high" {
		t.Errorf("expected integrity=high, got %s", result.Integrity)
	}
	if result.Availability != "moderate" {
		t.Errorf("expected availability=moderate, got %s", result.Availability)
	}
}

func TestValidateCategorization_BaselineExpands(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("high"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	result, diags := validateCategorization(cat, false)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	for _, level := range []string{result.Confidentiality, result.Integrity, result.Availability} {
		if level != "high" {
			t.Errorf("expected all objectives=high, got %s", level)
		}
	}
}

func TestValidateCategorization_BaselineAndIndividualMutuallyExclusive(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("moderate"),
		Confidentiality: types.StringValue("high"),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, false)
	if !diags.HasError() {
		t.Error("expected error for baseline + individual objectives")
	}
}

func TestValidateCategorization_InvalidLevel(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("critical"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, false)
	if !diags.HasError() {
		t.Error("expected error for invalid baseline level 'critical'")
	}
}

func TestValidateCategorization_NonNSSIndividual(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("low"),
		Integrity:       types.StringValue("moderate"),
		Availability:    types.StringValue("high"),
	}
	result, diags := validateCategorization(cat, false)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if result.Confidentiality != "low" || result.Integrity != "moderate" || result.Availability != "high" {
		t.Error("individual objectives not preserved correctly")
	}
}

func TestValidateEnforcement_Strict(t *testing.T) {
	diags := validateEnforcement("strict")
	if diags.HasError() {
		t.Errorf("unexpected error for 'strict'")
	}
}

func TestValidateEnforcement_Warn(t *testing.T) {
	diags := validateEnforcement("warn")
	if diags.HasError() {
		t.Errorf("unexpected error for 'warn'")
	}
}

func TestValidateEnforcement_Silent(t *testing.T) {
	diags := validateEnforcement("silent")
	if diags.HasError() {
		t.Errorf("unexpected error for 'silent'")
	}
}

func TestValidateEnforcement_Invalid(t *testing.T) {
	diags := validateEnforcement("yolo")
	if !diags.HasError() {
		t.Error("expected error for invalid enforcement")
	}
}

func TestValidateSuppressIDs_Valid(t *testing.T) {
	diags := validateSuppressIDs([]string{"DNS-REQ-001", "DNS-REQ-015"})
	if diags.HasError() {
		t.Errorf("unexpected error for valid IDs")
	}
}

func TestValidateSuppressIDs_Invalid(t *testing.T) {
	diags := validateSuppressIDs([]string{"DNS-REQ-999"})
	if !diags.HasError() {
		t.Error("expected error for invalid ID")
	}
}

func TestValidateSuppressIDs_Empty(t *testing.T) {
	diags := validateSuppressIDs([]string{})
	if diags.HasError() {
		t.Errorf("unexpected error for empty list")
	}
}
