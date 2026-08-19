// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Acceptance coverage for issue #96: DNSSEC parameter changes on signed
// zones reach defined outcomes (refusal / acknowledged re-sign / in-place
// nx_proof conversion / posture-gated unsign).

func testAccZoneDNSSECChange(name, curve, ack string) string {
	ackLine := ""
	if ack != "" {
		ackLine = fmt.Sprintf("    change_acknowledgment = %q\n", ack)
	}
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "chg" {
  name = %q
  type = "Primary"

  soa_serial_date_scheme = true

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = %q
    nx_proof  = "NSEC3"
%s  }
}
`, name, curve, ackLine)
}

func TestAccZoneResource_DNSSECInvalidPairRefusedAtCreate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-96-badpair.example.com"
  type = "Primary"
  dnssec {
    enabled   = true
    algorithm = "EDDSA"
    curve     = "P256"
  }
}
`,
				ExpectError: regexp.MustCompile("not a signable combination"),
			},
		},
	})
}

func TestAccZoneResource_DNSSECChangeRefused(t *testing.T) {
	zone := "acc-96-refused.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDNSSECChange(zone, "P256", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec.curve", "P256"),
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec_status", "SignedWithNSEC3"),
				),
			},
			{
				Config:      testAccZoneDNSSECChange(zone, "P384", ""),
				ExpectError: regexp.MustCompile("change_acknowledgment"),
			},
			// Separate step: an ExpectError step runs no checks — refresh and
			// assert the server still reports the old parameters.
			{
				Config: testAccZoneDNSSECChange(zone, "P256", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec.curve", "P256"),
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec_status", "SignedWithNSEC3"),
				),
			},
		},
	})
}

func TestAccZoneResource_DNSSECChangeAcknowledged(t *testing.T) {
	zone := "acc-96-acked.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDNSSECChange(zone, "P256", ""),
				Check:  resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec.curve", "P256"),
			},
			{
				Config: testAccZoneDNSSECChange(zone, "P384", "ECDSA/P384"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec.curve", "P384"),
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec_status", "SignedWithNSEC3"),
					// State-equality criterion: post-apply state equals the
					// operator-declared config value, no provider divergence.
					resource.TestCheckResourceAttr("technitium_zone.chg", "dnssec.change_acknowledgment", "ECDSA/P384"),
				),
			},
			// No planned resource changes with the acknowledgment in place.
			{
				Config:   testAccZoneDNSSECChange(zone, "P384", "ECDSA/P384"),
				PlanOnly: true,
			},
		},
	})
}

func testAccZoneDNSSECNxProof(name, nxProof string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "nx" {
  name = %q
  type = "Primary"

  soa_serial_date_scheme = true

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = %q
  }
}
`, name, nxProof)
}

func TestAccZoneResource_DNSSECNxProofInPlace(t *testing.T) {
	zone := "acc-96-nxproof.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDNSSECNxProof(zone, "NSEC3"),
				Check:  resource.TestCheckResourceAttr("technitium_zone.nx", "dnssec_status", "SignedWithNSEC3"),
			},
			{
				Config: testAccZoneDNSSECNxProof(zone, "NSEC"),
				Check:  resource.TestCheckResourceAttr("technitium_zone.nx", "dnssec_status", "SignedWithNSEC"),
			},
			{
				Config: testAccZoneDNSSECNxProof(zone, "NSEC3"),
				Check:  resource.TestCheckResourceAttr("technitium_zone.nx", "dnssec_status", "SignedWithNSEC3"),
			},
		},
	})
}

// Strict-posture unsign gate. The suppression list {DNS-REQ-001,011,012,
// 016} is minimal-and-complete at baseline "low", verified EMPIRICALLY
// against the live engine: SC-20/SC-13/CM-6 are LOW-baseline so those
// findings (DNSSEC required, NSEC3, FIPS algorithm, notify) fire on this
// zone shape and must be silenced for the GATE to be the only strict
// blocker; DNS-REQ-002/004 need MODERATE/HIGH controls and are not
// evaluated. Suppressing findings does NOT lower enforcement (the spec
// forbids requiring that).
func testAccZoneDNSSECStrictUnsign(name string, enabled bool, ack string) string {
	ackLine := ""
	if ack != "" {
		ackLine = fmt.Sprintf("    change_acknowledgment = %q\n", ack)
	}
	return testAccProviderHCL_STIG("strict", []string{"DNS-REQ-001", "DNS-REQ-011", "DNS-REQ-012", "DNS-REQ-016"}, "low") + fmt.Sprintf(`
resource "technitium_zone" "sg" {
  name = %q
  type = "Primary"

  soa_serial_date_scheme = true

  dnssec {
    enabled   = %t
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
%s  }
}
`, name, enabled, ackLine)
}

func TestAccZoneResource_DNSSECStrictUnsignGate(t *testing.T) {
	zone := "acc-96-strict.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDNSSECStrictUnsign(zone, true, ""),
				Check:  resource.TestCheckResourceAttr("technitium_zone.sg", "dnssec_status", "SignedWithNSEC3"),
			},
			{
				Config:      testAccZoneDNSSECStrictUnsign(zone, false, ""),
				ExpectError: regexp.MustCompile("change_acknowledgment"),
			},
			{
				Config: testAccZoneDNSSECStrictUnsign(zone, false, "unsigned"),
				Check:  resource.TestCheckResourceAttr("technitium_zone.sg", "dnssec_status", "Unsigned"),
			},
		},
	})
}
