// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAllowedZoneResource_basic(t *testing.T) {
	domain := "acc-allowed-basic.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZoneResourceConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "domain", domain),
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "id", domain),
				),
			},
			{
				ResourceName:      "technitium_allowed_zone.test",
				ImportState:       true,
				ImportStateId:     domain,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAllowedZoneResource_checkAndSetAdopt(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	domain := "acc-allowed-adopt.example.com"

	c := testAccDirectClient(t)

	// Pre-create the zone via direct API call so Terraform must adopt it
	if err := c.AllowedZoneAdd(context.Background(), domain); err != nil {
		t.Fatalf("pre-create allowed zone: %v", err)
	}
	t.Cleanup(func() {
		_ = c.AllowedZoneDelete(context.Background(), domain)
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Terraform should adopt the pre-existing zone without error
				Config: testAccAllowedZoneResourceConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "domain", domain),
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "id", domain),
				),
			},
		},
	})
}

func TestAccAllowedZoneResource_domainChangeForceNew(t *testing.T) {
	domainOld := "acc-allowed-fn-old.example.com"
	domainNew := "acc-allowed-fn-new.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZoneResourceConfig(domainOld),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "domain", domainOld),
				),
			},
			{
				Config: testAccAllowedZoneResourceConfig(domainNew),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zone.test", "domain", domainNew),
				),
			},
		},
	})
}

func testAccAllowedZoneResourceConfig(domain string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_allowed_zone" "test" {
  domain = %q
}
`, testAccAPIToken(), domain)
}
