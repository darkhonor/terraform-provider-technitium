// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

func testAccServerSettingsForwarders(forwarders, protocol string) string {
	return testAccProviderHCL() + fmt.Sprintf(`resource "technitium_server_settings" "main" {
  forwarders         = %s
  forwarder_protocol = %q
}
`, forwarders, protocol)
}

func TestAccServerSettingsResource_forwardersCanonical(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccServerSettingsForwarders(`["1.1.1.1", "9.9.9.9"]`, "Tls"),
				Check:  resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarders.0", "1.1.1.1"),
			},
			{
				Config: testAccServerSettingsForwarders(`["1.1.1.1", "9.9.9.9"]`, "Tls"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccServerSettingsForwarders(`["1.1.1.1", "dns.example.test"]`, "Https"),
				Check:  resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarders.1", "dns.example.test"),
			},
			{
				Config: testAccServerSettingsForwarders(`["2606:4700:4700::1111"]`, "Tcp"),
				Check:  resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarders.0", "2606:4700:4700::1111"),
			},
			{
				Config: testAccServerSettingsForwarders(`["2606:4700:4700::1111"]`, "Udp"),
				Check:  resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarder_protocol", "Udp"),
			},
			{
				Config: testAccProviderHCL() + `resource "technitium_server_settings" "main" {}
`,
				Check: resource.TestCheckNoResourceAttr("technitium_server_settings.main", "forwarders.#"),
			},
			{
				Config: testAccProviderHCL() + `resource "technitium_server_settings" "main" {}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config:      testAccServerSettingsForwarders(`["1.1.1.1:53"]`, "Tls"),
				ExpectError: regexp.MustCompile(`port 53`),
			},
			{
				Config: testAccServerSettingsForwarders(`[]`, "Tls"),
				Check:  resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarders.#", "0"),
			},
		},
	})
}
