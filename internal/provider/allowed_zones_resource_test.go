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

func TestAccAllowedZonesResource_basic(t *testing.T) {
	domains := []string{
		"acc-az-set1.example.com",
		"acc-az-set2.example.com",
		"acc-az-set3.example.com",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZonesResourceConfig(domains),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zones.test", "domains.#", "3"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-set1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-set2.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-set3.example.com"),
					resource.TestCheckResourceAttrSet("technitium_allowed_zones.test", "id"),
				),
			},
		},
	})
}

func TestAccAllowedZonesResource_update(t *testing.T) {
	domainsInitial := []string{
		"acc-az-upd1.example.com",
		"acc-az-upd2.example.com",
		"acc-az-upd3.example.com",
	}
	domainsUpdated := []string{
		"acc-az-upd1.example.com",
		"acc-az-upd2.example.com",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZonesResourceConfig(domainsInitial),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zones.test", "domains.#", "3"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-upd1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-upd2.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-upd3.example.com"),
				),
			},
			{
				Config: testAccAllowedZonesResourceConfig(domainsUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zones.test", "domains.#", "2"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-upd1.example.com"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-upd2.example.com"),
				),
			},
		},
	})
}

func TestAccAllowedZonesResource_checkAndSetAdopt(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	adoptDomain := "acc-az-adopt.example.com"
	allDomains := []string{
		adoptDomain,
		"acc-az-adopt2.example.com",
	}

	c := testAccDirectClient(t)

	// Pre-create the domain so Terraform must adopt it.
	if err := c.AllowedZoneAdd(context.Background(), adoptDomain); err != nil {
		t.Fatalf("pre-create allowed zone %q: %v", adoptDomain, err)
	}
	t.Cleanup(func() {
		for _, d := range allDomains {
			_ = c.AllowedZoneDelete(context.Background(), d)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowedZonesResourceConfig(allDomains),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_allowed_zones.test", "domains.#", "2"),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", adoptDomain),
					resource.TestCheckTypeSetElemAttr("technitium_allowed_zones.test", "domains.*", "acc-az-adopt2.example.com"),
				),
			},
		},
	})
}

func testAccAllowedZonesResourceConfig(domains []string) string {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_allowed_zones" "test" {
  domains = [%s]
}
`, testAccAPIToken(), strings.Join(quoted, ", "))
}
