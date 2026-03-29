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

func TestAccBlockedZoneResource_basic(t *testing.T) {
	domain := "acc-blocked-basic.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZoneResourceConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "domain", domain),
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "id", domain),
				),
			},
			{
				ResourceName:      "technitium_blocked_zone.test",
				ImportState:       true,
				ImportStateId:     domain,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccBlockedZoneResource_checkAndSetAdopt(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	domain := "acc-blocked-adopt.example.com"
	c := testAccDirectClient(t)

	// Clean up any stale entry then pre-create via direct API.
	_ = c.BlockedZoneDelete(context.Background(), domain)
	if err := c.BlockedZoneAdd(context.Background(), domain); err != nil {
		t.Fatalf("failed to pre-create blocked zone %q: %s", domain, err)
	}
	t.Cleanup(func() { _ = c.BlockedZoneDelete(context.Background(), domain) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Resource should adopt the pre-existing entry without error.
				Config: testAccBlockedZoneResourceConfig(domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "domain", domain),
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "id", domain),
				),
			},
		},
	})
}

func TestAccBlockedZoneResource_domainChangeForceNew(t *testing.T) {
	domainOld := "acc-blocked-forcenew-old.example.com"
	domainNew := "acc-blocked-forcenew-new.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZoneResourceConfig(domainOld),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "domain", domainOld),
				),
			},
			{
				Config: testAccBlockedZoneResourceConfig(domainNew),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zone.test", "domain", domainNew),
				),
			},
		},
	})
}

func testAccBlockedZoneResourceConfig(domain string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_blocked_zone" "test" {
  domain = %q
}
`, testAccAPIToken(), domain)
}
