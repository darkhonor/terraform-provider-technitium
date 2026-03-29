// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccBlockedZonesResource_basic(t *testing.T) {
	domains := []string{
		"acc-bz-set1.example.com",
		"acc-bz-set2.example.com",
		"acc-bz-set3.example.com",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZonesResourceConfig(domains),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zones.corporate", "domains.#", "3"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-set1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-set2.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-set3.example.com"),
					resource.TestCheckResourceAttrSet("technitium_blocked_zones.corporate", "id"),
				),
			},
		},
	})
}

func TestAccBlockedZonesResource_update(t *testing.T) {
	domainsInitial := []string{
		"acc-bz-upd1.example.com",
		"acc-bz-upd2.example.com",
		"acc-bz-upd3.example.com",
	}
	// Remove acc-bz-upd3, keep acc-bz-upd1 and acc-bz-upd2, add acc-bz-upd4
	domainsUpdated := []string{
		"acc-bz-upd1.example.com",
		"acc-bz-upd2.example.com",
		"acc-bz-upd4.example.com",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedZonesResourceConfig(domainsInitial),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zones.corporate", "domains.#", "3"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd2.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd3.example.com"),
				),
			},
			{
				Config: testAccBlockedZonesResourceConfig(domainsUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zones.corporate", "domains.#", "3"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd2.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-upd4.example.com"),
				),
			},
		},
	})
}

func TestAccBlockedZonesResource_checkAndSetAdopt(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	adoptDomain := "acc-bz-adopt.example.com"
	domains := []string{
		adoptDomain,
		"acc-bz-adopt2.example.com",
	}

	c := testAccDirectClient(t)

	// Clean up any stale entry then pre-create via direct API.
	_ = c.BlockedZoneDelete(context.Background(), adoptDomain)
	if err := c.BlockedZoneAdd(context.Background(), adoptDomain); err != nil {
		t.Fatalf("failed to pre-create blocked zone %q: %s", adoptDomain, err)
	}
	t.Cleanup(func() {
		_ = c.BlockedZoneDelete(context.Background(), adoptDomain)
		_ = c.BlockedZoneDelete(context.Background(), "acc-bz-adopt2.example.com")
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Resource should adopt the pre-existing domain without error.
				Config: testAccBlockedZonesResourceConfig(domains),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_blocked_zones.corporate", "domains.#", "2"),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", adoptDomain),
					resource.TestCheckTypeSetElemAttr("technitium_blocked_zones.corporate", "domains.*", "acc-bz-adopt2.example.com"),
					resource.TestCheckResourceAttrSet("technitium_blocked_zones.corporate", "id"),
				),
			},
		},
	})
}

func testAccBlockedZonesResourceConfig(domains []string) string {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_blocked_zones" "corporate" {
  domains = [%s]
}
`, testAccAPIToken(), strings.Join(quoted, ", "))
}
