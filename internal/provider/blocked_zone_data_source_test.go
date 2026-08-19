// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccBlockedZoneDataSource_exists(t *testing.T) {
	domain := "acc-ds-blocked-exists.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZoneDataSourceConfig_exists(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "domain", domain),
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "id", domain),
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "exists", "true"),
				),
			},
		},
	})
}

func TestAccBlockedZoneDataSource_notExists(t *testing.T) {
	domain := "acc-ds-blocked-notexists.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZoneDataSourceConfig_notExists(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "domain", domain),
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "id", domain),
					resource.TestCheckResourceAttr("data.technitium_blocked_zone.check", "exists", "false"),
				),
			},
		},
	})
}

func testAccBlockedZoneDataSourceConfig_exists(domain string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

resource "technitium_blocked_zone" "seed" {
  domain = %q
}

data "technitium_blocked_zone" "check" {
  domain = technitium_blocked_zone.seed.domain
}
`, domain)
}

func testAccBlockedZoneDataSourceConfig_notExists(domain string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

data "technitium_blocked_zone" "check" {
  domain = %q
}
`, domain)
}
