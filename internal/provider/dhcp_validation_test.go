// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDHCPScopeResource_invalidRange_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-range"
  starting_address = "10.50.0.250"
  ending_address   = "10.50.0.50"
  subnet_mask      = "255.255.255.0"
}
`,
				ExpectError: regexp.MustCompile(`is after ending_address`),
			},
		},
	})
}

func TestAccDHCPScopeResource_invalidIP_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-ip"
  starting_address = "not-an-ip"
  ending_address   = "10.50.0.250"
  subnet_mask      = "255.255.255.0"
}
`,
				ExpectError: regexp.MustCompile(`not a valid IPv4 address`),
			},
		},
	})
}

func TestAccDHCPScopeResource_exclusionOutsideRange_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-excl"
  starting_address = "10.50.0.50"
  ending_address   = "10.50.0.250"
  subnet_mask      = "255.255.255.0"

  exclusions = [
    {
      starting_address = "10.51.0.1"
      ending_address   = "10.51.0.10"
    }
  ]
}
`,
				ExpectError: regexp.MustCompile(`not contained in the scope range`),
			},
		},
	})
}

func TestAccDHCPReservedLeaseResource_invalidMAC_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_reserved_lease" "bad" {
  scope            = "whatever"
  hardware_address = "zz-11-22-33-44-55"
  ip_address       = "10.50.0.100"
}
`,
				ExpectError: regexp.MustCompile(`not a valid MAC address`),
			},
		},
	})
}
