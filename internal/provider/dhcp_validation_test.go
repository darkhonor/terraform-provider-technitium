// Copyright (c) 2026 Stefano Bertelli
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

func TestAccDHCPScopeResource_zeroSubnetMask_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-zero-mask"
  starting_address = "10.50.0.50"
  ending_address   = "10.50.0.250"
  subnet_mask      = "0.0.0.0"
}
`,
				ExpectError: regexp.MustCompile(`not a usable subnet mask`),
			},
		},
	})
}

func TestAccDHCPScopeResource_mappedIPv6Address_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-mapped"
  starting_address = "::ffff:10.50.0.50"
  ending_address   = "10.50.0.250"
  subnet_mask      = "255.255.255.0"
}
`,
				ExpectError: regexp.MustCompile(`not a valid IPv4 address`),
			},
		},
	})
}

func TestAccDHCPScopeResource_invalidServerListEntry_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-dns-list"
  starting_address = "10.50.0.50"
  ending_address   = "10.50.0.250"
  subnet_mask      = "255.255.255.0"

  dns_servers = ["10.50.0.5", "not-an-ip"]
}
`,
				ExpectError: regexp.MustCompile(`not a valid IPv4 address`),
			},
		},
	})
}

// The scopes/set wire encoding joins fields with "|"; a literal pipe in any
// free-text field would shift every later field, so it is rejected at plan time.
func TestAccDHCPScopeResource_pipeInFields_Rejected(t *testing.T) {
	cases := []struct {
		name string
		attr string
	}{
		{"reserved lease comments", `
  reserved_leases = [
    {
      hardware_address = "00-11-22-33-44-55"
      address          = "10.50.0.100"
      comments         = "rack 3 | port 12"
    }
  ]`},
		{"reserved lease host name", `
  reserved_leases = [
    {
      host_name        = "a|b"
      hardware_address = "00-11-22-33-44-55"
      address          = "10.50.0.100"
    }
  ]`},
		{"vendor info", `
  vendor_info = [
    {
      identifier  = "MSFT|5.0"
      information = "AA:BB"
    }
  ]`},
		{"generic option value", `
  generic_options = [
    {
      code  = 150
      value = "AA|BB"
    }
  ]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccProviderHCL() + `
resource "technitium_dhcp_scope" "bad" {
  name             = "acc-bad-pipe"
  starting_address = "10.50.0.50"
  ending_address   = "10.50.0.250"
  subnet_mask      = "255.255.255.0"
` + tc.attr + `
}
`,
						ExpectError: regexp.MustCompile(`must not contain "\|"`),
					},
				},
			})
		})
	}
}

func TestAccDHCPReservedLeaseResource_pipeInFields_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_dhcp_reserved_lease" "bad" {
  scope            = "whatever"
  hardware_address = "00-11-22-33-44-55"
  ip_address       = "10.50.0.100"
  comments         = "rack 3 | port 12"
}
`,
				ExpectError: regexp.MustCompile(`must not contain "\|"`),
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
