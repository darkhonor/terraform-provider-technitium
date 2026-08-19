// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAllowedZonesDataSource_list(t *testing.T) {
	domain1 := "acc-ds-az-list1.example.com"
	domain2 := "acc-ds-az-list2.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZonesDataSourceConfig(domain1, domain2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_allowed_zones.all", "id", "allowed-zones"),
					resource.TestCheckTypeSetElemAttr("data.technitium_allowed_zones.all", "domains.*", domain1),
					resource.TestCheckTypeSetElemAttr("data.technitium_allowed_zones.all", "domains.*", domain2),
				),
			},
		},
	})
}

func testAccAllowedZonesDataSourceConfig(domain1, domain2 string) string {
	return testAccProviderHCL() + fmt.Sprintf(`

resource "technitium_allowed_zone" "setup1" {
  domain = %q
}

resource "technitium_allowed_zone" "setup2" {
  domain = %q
}

data "technitium_allowed_zones" "all" {
  depends_on = [
    technitium_allowed_zone.setup1,
    technitium_allowed_zone.setup2,
  ]
}
`, domain1, domain2)
}
