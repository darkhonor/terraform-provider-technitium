// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccBlockedZonesDataSource_list(t *testing.T) {
	domain1 := "acc-ds-bz-list1.example.com"
	domain2 := "acc-ds-bz-list2.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZonesDataSourceConfig_list(domain1, domain2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.technitium_blocked_zones.all", "id"),
					resource.TestCheckResourceAttrSet("data.technitium_blocked_zones.all", "domains.#"),
				),
			},
		},
	})
}

func testAccBlockedZonesDataSourceConfig_list(domain1, domain2 string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

resource "technitium_blocked_zone" "seed1" {
  domain = %q
}

resource "technitium_blocked_zone" "seed2" {
  domain = %q
}

data "technitium_blocked_zones" "all" {
  depends_on = [
    technitium_blocked_zone.seed1,
    technitium_blocked_zone.seed2,
  ]
}
`, domain1, domain2)
}
