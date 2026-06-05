// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
