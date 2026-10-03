// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

func TestParseDHCPReservedLeaseID(t *testing.T) {
	cases := []struct {
		id         string
		scope, mac string
		ok         bool
	}{
		{"lan::00-11-22-33-44-55", "lan", "00-11-22-33-44-55", true},
		{"lan::aa:bb:cc:dd:ee:ff", "lan", "aa:bb:cc:dd:ee:ff", true},
		// Split on the LAST "::": scope names may contain "::", a MAC's
		// colons only ever come one at a time.
		{"office::floor2::00-11-22-33-44-55", "office::floor2", "00-11-22-33-44-55", true},
		{"lan", "", "", false},
		{"::00-11-22-33-44-55", "", "", false},
		{"lan::", "", "", false},
	}
	for _, tc := range cases {
		scope, mac, ok := parseDHCPReservedLeaseID(tc.id)
		if scope != tc.scope || mac != tc.mac || ok != tc.ok {
			t.Errorf("parseDHCPReservedLeaseID(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.id, scope, mac, ok, tc.scope, tc.mac, tc.ok)
		}
	}
}

// Respelling the MAC (case or separators) must not force a replace; only a
// genuinely different address does.
func TestAccDHCPReservedLeaseResource_macRespellingNoReplace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPReservedLease("acc-scope-respell", "00-AA-BB-CC-DD-04", "10.45.0.102"),
			},
			{
				Config: testAccDHCPReservedLease("acc-scope-respell", "00:aa:bb:cc:dd:04", "10.45.0.102"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "id", "acc-scope-respell::00-AA-BB-CC-DD-04"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "hardware_address", "00-AA-BB-CC-DD-04"),
				),
			},
		},
	})
}

func TestAccDHCPReservedLeaseResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccDHCPReservedLease("acc-scope-rl", "00-AA-BB-CC-DD-01", "10.45.0.100"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "id", "acc-scope-rl::00-AA-BB-CC-DD-01"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "scope", "acc-scope-rl"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "hardware_address", "00-AA-BB-CC-DD-01"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "ip_address", "10.45.0.100"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "host_name", "printer"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "comments", "acc reservation"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_dhcp_reserved_lease.test",
				ImportState:       true,
				ImportStateId:     "acc-scope-rl::00-AA-BB-CC-DD-01",
				ImportStateVerify: true,
			},
			// Replace: new IP forces remove+add
			{
				Config: testAccDHCPReservedLease("acc-scope-rl", "00-AA-BB-CC-DD-01", "10.45.0.101"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.test", "ip_address", "10.45.0.101"),
				),
			},
		},
	})
}

func TestAccDHCPReservedLeaseResource_multiplePerScope(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPReservedLeases2("acc-scope-rl2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.a", "ip_address", "10.46.0.100"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.b", "ip_address", "10.46.0.101"),
				),
			},
			// Remove one of the two; the other must survive
			{
				Config: testAccDHCPReservedLeases1("acc-scope-rl2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.a", "ip_address", "10.46.0.100"),
				),
			},
		},
	})
}

func testAccDHCPReservedLease(scopeName, mac, ip string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "rl" {
  name             = %q
  starting_address = "10.45.0.50"
  ending_address   = "10.45.0.250"
  subnet_mask      = "255.255.255.0"
}

resource "technitium_dhcp_reserved_lease" "test" {
  scope            = technitium_dhcp_scope.rl.name
  hardware_address = %q
  ip_address       = %q
  host_name        = "printer"
  comments         = "acc reservation"
}
`, scopeName, mac, ip)
}

func testAccDHCPReservedLeases2(scopeName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "rl2" {
  name             = %q
  starting_address = "10.46.0.50"
  ending_address   = "10.46.0.250"
  subnet_mask      = "255.255.255.0"
}

resource "technitium_dhcp_reserved_lease" "a" {
  scope            = technitium_dhcp_scope.rl2.name
  hardware_address = "00-AA-BB-CC-DD-02"
  ip_address       = "10.46.0.100"
}

resource "technitium_dhcp_reserved_lease" "b" {
  scope            = technitium_dhcp_scope.rl2.name
  hardware_address = "00-AA-BB-CC-DD-03"
  ip_address       = "10.46.0.101"
}
`, scopeName)
}

func testAccDHCPReservedLeases1(scopeName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "rl2" {
  name             = %q
  starting_address = "10.46.0.50"
  ending_address   = "10.46.0.250"
  subnet_mask      = "255.255.255.0"
}

resource "technitium_dhcp_reserved_lease" "a" {
  scope            = technitium_dhcp_scope.rl2.name
  hardware_address = "00-AA-BB-CC-DD-02"
  ip_address       = "10.46.0.100"
}
`, scopeName)
}
