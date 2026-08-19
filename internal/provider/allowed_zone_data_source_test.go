// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAllowedZoneDataSource_exists(t *testing.T) {
	domain := "acc-ds-allowed-exists.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZoneDataSourceConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "domain", domain),
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "id", domain),
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "exists", "true"),
				),
			},
		},
	})
}

func TestAccAllowedZoneDataSource_notExists(t *testing.T) {
	domain := "acc-ds-allowed-notexists.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZoneDataSourceOnlyConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "domain", domain),
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "id", domain),
					resource.TestCheckResourceAttr("data.technitium_allowed_zone.check", "exists", "false"),
				),
			},
		},
	})
}

// testAccAllowedZoneDataSourceConfig creates an allowed_zone resource and then
// reads it back via the data source — expects exists=true.
func testAccAllowedZoneDataSourceConfig(domain string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

resource "technitium_allowed_zone" "setup" {
  domain = %q
}

data "technitium_allowed_zone" "check" {
  domain     = %q
  depends_on = [technitium_allowed_zone.setup]
}
`, domain, domain)
}

// testAccAllowedZoneDataSourceOnlyConfig reads a domain that does not exist —
// expects exists=false.
func testAccAllowedZoneDataSourceOnlyConfig(domain string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

data "technitium_allowed_zone" "check" {
  domain = %q
}
`, domain)
}
