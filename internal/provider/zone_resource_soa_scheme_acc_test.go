// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccCheckSOAScheme(t *testing.T, zone string, want bool) resource.TestCheckFunc {
	return func(*terraform.State) error {
		soa, err := testAccDirectClient(t).ZoneSOAGet(context.Background(), zone)
		if err != nil {
			return err
		}
		if v := soa.RData.UseSerialDateScheme; v == nil || *v != want {
			if v == nil {
				return fmt.Errorf("server does not report useSerialDateScheme, want %t", want)
			}
			return fmt.Errorf("server useSerialDateScheme = %t, want %t", *v, want)
		}
		return nil
	}
}

func testAccSetSOASchemeOutOfBand(t *testing.T, zone string, v bool) {
	if err := testAccDirectClient(t).ZoneSOASetSerialDateScheme(context.Background(), zone, v); err != nil {
		t.Fatalf("out-of-band SOA update: %v", err)
	}
}

func testAccZoneSOASchemeConfig(name, zoneType string, scheme bool) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "soa" {
  name                   = %q
  type                   = %q
  soa_serial_date_scheme = %t
}
`, name, zoneType, scheme)
}

func TestAccZoneResource_SOASerialDateScheme_Primary(t *testing.T) {
	const zone = "acc-soa-scheme.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneSOASchemeConfig(zone, "Primary", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.soa", "soa_serial_date_scheme", "false"),
					testAccCheckSOAScheme(t, zone, false),
				),
			},
			{
				Config: testAccZoneSOASchemeConfig(zone, "Primary", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.soa", "soa_serial_date_scheme", "true"),
					resource.TestMatchResourceAttr("technitium_zone.soa", "soa_serial", regexp.MustCompile(`^20\d{8}$`)),
					testAccCheckSOAScheme(t, zone, true),
				),
			},
			{
				PreConfig: func() { testAccSetSOASchemeOutOfBand(t, zone, false) },
				Config:    testAccZoneSOASchemeConfig(zone, "Primary", true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("technitium_zone.soa", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckSOAScheme(t, zone, true),
			},
			{
				ResourceName:            "technitium_zone.soa",
				ImportState:             true,
				ImportStateId:           zone,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"dnssec"},
			},
		},
	})
}

func TestAccZoneResource_SOASerialDateScheme_ImportFalse(t *testing.T) {
	const zone = "acc-soa-import.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneSOASchemeConfig(zone, "Primary", false),
			},
			{
				Config:                  testAccZoneSOASchemeConfig(zone, "Primary", true),
				ResourceName:            "technitium_zone.soa",
				ImportState:             true,
				ImportStateId:           zone,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"dnssec"},
				ImportStateCheck: func(s []*terraform.InstanceState) error {
					if len(s) != 1 || s[0].Attributes["soa_serial_date_scheme"] != "false" {
						return fmt.Errorf("imported soa_serial_date_scheme must be the server's false, got %v", s)
					}
					return nil
				},
			},
			{
				Config: testAccZoneSOASchemeConfig(zone, "Primary", true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("technitium_zone.soa", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckSOAScheme(t, zone, true),
			},
		},
	})
}

func TestAccZoneResource_SOASerialDateScheme_Forwarder(t *testing.T) {
	const zone = "acc-soa-fwd.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceForwarderConfig(zone),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.forwarder", "soa_serial_date_scheme", "true"),
					testAccCheckSOAScheme(t, zone, true),
				),
			},
			{
				PreConfig: func() { testAccSetSOASchemeOutOfBand(t, zone, false) },
				Config:    testAccZoneResourceForwarderConfig(zone),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("technitium_zone.forwarder", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckSOAScheme(t, zone, true),
			},
		},
	})
}

func TestAccZoneResource_SOASerialDateScheme_SignedPrimary(t *testing.T) {
	const zone = "acc-soa-signed.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceConfig(zone, "Primary"),
				Check:  testAccCheckSOAScheme(t, zone, true),
			},
			{
				PreConfig: func() { testAccSetSOASchemeOutOfBand(t, zone, false) },
				Config:    testAccZoneResourceConfig(zone, "Primary"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("technitium_zone.test", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckSOAScheme(t, zone, true),
			},
		},
	})
}
