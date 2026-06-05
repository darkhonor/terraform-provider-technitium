// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDHCPScopeDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeDataSourceConfig("acc-scope-ds"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "name", "acc-scope-ds"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "starting_address", "10.47.0.50"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "ending_address", "10.47.0.250"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "subnet_mask", "255.255.255.0"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "domain_name", "ds.example"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "router_address", "10.47.0.1"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "dns_servers.#", "1"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "reserved_leases.#", "1"),
					resource.TestCheckResourceAttr("data.technitium_dhcp_scope.test", "reserved_leases.0.address", "10.47.0.100"),
					resource.TestCheckResourceAttrSet("data.technitium_dhcp_scope.test", "lease_time_days"),
				),
			},
		},
	})
}

func TestAccDHCPScopesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopesDataSourceConfig("acc-scopes-ds"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// At least the scope created in this config must be present.
					resource.TestCheckResourceAttrWith("data.technitium_dhcp_scopes.all", "scopes.#", func(v string) error {
						if v == "0" {
							return fmt.Errorf("expected at least one scope, got %s", v)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccDHCPLeasesDataSource_emptyScope(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// A fresh scope with no clients has no leases; the data source
				// must return an empty list, not an error.
				Config: testAccDHCPLeasesDataSourceConfig("acc-leases-ds"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_dhcp_leases.test", "leases.#", "0"),
				),
			},
		},
	})
}

func testAccDHCPScopeDataSourceConfig(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "seed" {
  name             = %q
  starting_address = "10.47.0.50"
  ending_address   = "10.47.0.250"
  subnet_mask      = "255.255.255.0"

  domain_name    = "ds.example"
  router_address = "10.47.0.1"
  dns_servers    = ["10.47.0.5"]

  reserved_leases = [
    {
      hardware_address = "00-AA-BB-CC-DD-10"
      address          = "10.47.0.100"
    }
  ]
}

data "technitium_dhcp_scope" "test" {
  name = technitium_dhcp_scope.seed.name
}
`, name)
}

func testAccDHCPScopesDataSourceConfig(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "seed" {
  name             = %q
  starting_address = "10.48.0.50"
  ending_address   = "10.48.0.250"
  subnet_mask      = "255.255.255.0"
}

data "technitium_dhcp_scopes" "all" {
  depends_on = [technitium_dhcp_scope.seed]
}
`, name)
}

func testAccDHCPLeasesDataSourceConfig(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "seed" {
  name             = %q
  starting_address = "10.49.0.50"
  ending_address   = "10.49.0.250"
  subnet_mask      = "255.255.255.0"
}

data "technitium_dhcp_leases" "test" {
  scope      = technitium_dhcp_scope.seed.name
  depends_on = [technitium_dhcp_scope.seed]
}
`, name)
}
