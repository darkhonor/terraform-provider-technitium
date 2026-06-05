// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDHCPScopeResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccDHCPScopeBasic("acc-scope-basic"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "id", "acc-scope-basic"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-basic"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "starting_address", "10.42.0.50"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "ending_address", "10.42.0.250"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "subnet_mask", "255.255.255.0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "enabled", "false"),
					// Server-side defaults must be read back into computed attrs
					resource.TestCheckResourceAttrSet("technitium_dhcp_scope.test", "lease_time_days"),
					resource.TestCheckResourceAttrSet("technitium_dhcp_scope.test", "dns_ttl"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_dhcp_scope.test",
				ImportState:       true,
				ImportStateId:     "acc-scope-basic",
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDHCPScopeResource_fullOptions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeFull("acc-scope-full"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_name", "lab.example"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_search_list.#", "2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_search_list.0", "lab.example"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "router_address", "10.43.0.1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "dns_servers.#", "2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "ntp_servers.0", "10.43.0.5"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "lease_time_days", "3"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.0.destination", "172.16.0.0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.0.router", "10.43.0.2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.0.starting_address", "10.43.0.50"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.0.hardware_address", "00-11-22-33-44-55"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.0.address", "10.43.0.100"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "generic_options.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "generic_options.0.code", "150"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "allow_only_reserved_leases", "true"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "ping_check_enabled", "true"),
				),
			},
			// Update: drop reservations/exclusions, change lease time and lists
			{
				Config: testAccDHCPScopeFullUpdated("acc-scope-full"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "lease_time_days", "7"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "dns_servers.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.#", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.#", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "allow_only_reserved_leases", "false"),
				),
			},
		},
	})
}

func TestAccDHCPScopeResource_rename(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeBasicNamed("acc-scope-rename-a", "10.44.0.50", "10.44.0.250"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-rename-a"),
				),
			},
			// Rename in place — same range, new name; must NOT destroy/recreate
			{
				Config: testAccDHCPScopeBasicNamed("acc-scope-rename-b", "10.44.0.50", "10.44.0.250"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-rename-b"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "id", "acc-scope-rename-b"),
				),
			},
		},
	})
}

func testAccDHCPScopeBasic(name string) string {
	return testAccDHCPScopeBasicNamed(name, "10.42.0.50", "10.42.0.250")
}

func testAccDHCPScopeBasicNamed(name, start, end string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = %q
  ending_address   = %q
  subnet_mask      = "255.255.255.0"
}
`, name, start, end)
}

func testAccDHCPScopeFull(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "full" {
  name             = %q
  starting_address = "10.43.0.50"
  ending_address   = "10.43.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_days    = 3
  ping_check_enabled = true

  domain_name        = "lab.example"
  domain_search_list = ["lab.example", "corp.example"]
  dns_updates        = true
  dns_ttl            = 600

  router_address = "10.43.0.1"
  dns_servers    = ["10.43.0.5", "10.43.0.6"]
  ntp_servers    = ["10.43.0.5"]

  static_routes = [
    {
      destination = "172.16.0.0"
      subnet_mask = "255.255.255.0"
      router      = "10.43.0.2"
    }
  ]

  exclusions = [
    {
      starting_address = "10.43.0.50"
      ending_address   = "10.43.0.60"
    }
  ]

  reserved_leases = [
    {
      host_name        = "printer"
      hardware_address = "00-11-22-33-44-55"
      address          = "10.43.0.100"
      comments         = "acc test reservation"
    }
  ]

  generic_options = [
    {
      code  = 150
      value = "0A:2B:00:05"
    }
  ]

  allow_only_reserved_leases = true
}
`, name)
}

func testAccDHCPScopeFullUpdated(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "full" {
  name             = %q
  starting_address = "10.43.0.50"
  ending_address   = "10.43.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_days = 7

  domain_name        = "lab.example"
  domain_search_list = ["lab.example", "corp.example"]
  dns_updates        = true
  dns_ttl            = 600

  router_address = "10.43.0.1"
  dns_servers    = ["10.43.0.5"]
  ntp_servers    = ["10.43.0.5"]

  static_routes = [
    {
      destination = "172.16.0.0"
      subnet_mask = "255.255.255.0"
      router      = "10.43.0.2"
    }
  ]

  exclusions      = []
  reserved_leases = []

  allow_only_reserved_leases = false
}
`, name)
}
