// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestAccCatalogMembershipResource_basic exercises the create / read / import
// round-trip against a Technitium server.
func TestAccCatalogMembershipResource_basic(t *testing.T) {
	const memberZone = "acc-cm-basic-member.example.com"
	const catalogZone = "acc-cm-basic-catalog.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCatalogMembershipBasic(memberZone, catalogZone),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_catalog_membership.test", "zone", memberZone),
					resource.TestCheckResourceAttr("technitium_catalog_membership.test", "catalog_zone", catalogZone),
					resource.TestCheckResourceAttr("technitium_catalog_membership.test", "id", memberZone),
					checkZoneCatalogFn(t, memberZone, catalogZone),
				),
			},
			{
				ResourceName:      "technitium_catalog_membership.test",
				ImportState:       true,
				ImportStateId:     memberZone,
				ImportStateVerify: true,
			},
		},
	})
}

// SecondaryCatalog coverage is intentionally deferred to the multi-node
// acceptance suite tracked by issue #30: a SecondaryCatalog zone is, by
// definition, a slave of a primary catalog hosted elsewhere, which the
// current single-node docker-compose test environment cannot provide.

// TestAccCatalogMembershipResource_update verifies that moving a member zone
// from one catalog zone to another is handled in-place (no replacement).
func TestAccCatalogMembershipResource_update(t *testing.T) {
	const memberZone = "acc-cm-update-member.example.com"
	const catalogZoneA = "acc-cm-update-catalog-a.example.com"
	const catalogZoneB = "acc-cm-update-catalog-b.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCatalogMembershipTwoCatalogs(memberZone, catalogZoneA, catalogZoneB, catalogZoneA),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_catalog_membership.test", "catalog_zone", catalogZoneA),
					checkZoneCatalogFn(t, memberZone, catalogZoneA),
				),
			},
			{
				Config: testAccCatalogMembershipTwoCatalogs(memberZone, catalogZoneA, catalogZoneB, catalogZoneB),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_catalog_membership.test", "catalog_zone", catalogZoneB),
					checkZoneCatalogFn(t, memberZone, catalogZoneB),
				),
			},
		},
	})
}

// TestAccCatalogMembershipResource_destroyPreservesZones verifies that
// removing a technitium_catalog_membership from configuration unsets catalog
// membership on the member zone but leaves both the member zone and the
// catalog zone intact. This empirically validates the Technitium API
// convention that an empty "catalog" parameter unsets membership without
// affecting the zone itself.
func TestAccCatalogMembershipResource_destroyPreservesZones(t *testing.T) {
	const memberZone = "acc-cm-destroy-member.example.com"
	const catalogZone = "acc-cm-destroy-catalog.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCatalogMembershipBasic(memberZone, catalogZone),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkZoneCatalogFn(t, memberZone, catalogZone),
				),
			},
			{
				// Same zones, membership resource removed.
				Config: testAccCatalogMembershipZonesOnly(memberZone, catalogZone),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Member zone still present, catalog field cleared.
					checkZoneCatalogFn(t, memberZone, ""),
					// Catalog zone still present.
					checkZoneExistsFn(t, catalogZone),
				),
			},
		},
	})
}

// TestAccCatalogMembershipResource_outOfBandRemovalDriftRecovery verifies that
// when catalog membership is removed out-of-band (e.g., directly via the
// Technitium UI), the next refresh detects this and removes the resource
// from state, and the next plan offers to recreate it.
func TestAccCatalogMembershipResource_outOfBandRemovalDriftRecovery(t *testing.T) {
	const memberZone = "acc-cm-drift-member.example.com"
	const catalogZone = "acc-cm-drift-catalog.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCatalogMembershipBasic(memberZone, catalogZone),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkZoneCatalogFn(t, memberZone, catalogZone),
				),
			},
			{
				// Out-of-band: clear catalog membership directly via API.
				PreConfig: func() {
					c := testAccDirectClient(t)
					if err := c.ZoneSetCatalog(context.Background(), memberZone, ""); err != nil {
						t.Fatalf("out-of-band unset failed: %s", err)
					}
				},
				// Same config; the provider should detect the removal in Read,
				// drop from state, then re-create on the same plan.
				Config: testAccCatalogMembershipBasic(memberZone, catalogZone),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkZoneCatalogFn(t, memberZone, catalogZone),
				),
			},
		},
	})
}

// TestAccCatalogMembershipResource_applyErrorMissingMember verifies that
// referencing a member zone that does not exist surfaces as an apply-time
// error from the Technitium API. Plan-time existence checking was removed
// to support same-apply zone+membership creation; the API is the gate.
func TestAccCatalogMembershipResource_applyErrorMissingMember(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCatalogMembershipMissingMember("nonexistent-member.example.com", "acc-cm-applymiss-catalog.example.com"),
				ExpectError: regexp.MustCompile(`(?i)Error assigning catalog membership`),
			},
		},
	})
}

// TestAccCatalogMembershipResource_applyErrorMissingCatalog verifies that
// referencing a catalog zone that does not exist surfaces as an apply-time
// error from the Technitium API.
func TestAccCatalogMembershipResource_applyErrorMissingCatalog(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCatalogMembershipMissingCatalog("acc-cm-applymisscat-member.example.com", "nonexistent-catalog.example.com"),
				ExpectError: regexp.MustCompile(`(?i)Error assigning catalog membership`),
			},
		},
	})
}

// TestAccCatalogMembershipResource_applyErrorWrongCatalogType verifies that
// referencing a Primary zone (instead of a Catalog/SecondaryCatalog zone) as
// catalog_zone surfaces as an apply-time error from the Technitium API.
func TestAccCatalogMembershipResource_applyErrorWrongCatalogType(t *testing.T) {
	const memberZone = "acc-cm-wrongcat-member.example.com"
	const wrongCatalog = "acc-cm-wrongcat-not-a-catalog.example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCatalogMembershipWrongType(memberZone, wrongCatalog),
				ExpectError: regexp.MustCompile(`(?i)Error assigning catalog membership`),
			},
		},
	})
}

// TestAccCatalogMembershipResource_planErrorSelfReference verifies that
// configuring a zone as a member of itself surfaces at plan time via the
// resource's ConfigValidator (no API access required).
func TestAccCatalogMembershipResource_planErrorSelfReference(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCatalogMembershipSelfReference("acc-cm-self.example.com"),
				ExpectError: regexp.MustCompile(`catalog_zone must differ from zone`),
			},
		},
	})
}

// checkZoneCatalogFn returns a TestCheckFunc that verifies a zone's catalog
// membership matches the expected catalog name, by querying the Technitium
// API directly.
func checkZoneCatalogFn(t *testing.T, zone, expectedCatalog string) resource.TestCheckFunc {
	t.Helper()
	return func(_ *terraform.State) error {
		c := testAccDirectClient(t)
		opts, err := c.ZoneOptionsGet(context.Background(), zone)
		if err != nil {
			return fmt.Errorf("direct API check: read zone %q options: %w", zone, err)
		}
		observed := ""
		if opts.Catalog != nil {
			observed = *opts.Catalog
		}
		if observed != expectedCatalog {
			return fmt.Errorf("zone %q catalog membership: expected %q, got %q", zone, expectedCatalog, observed)
		}
		return nil
	}
}

// checkZoneExistsFn returns a TestCheckFunc that verifies a zone is present
// on the Technitium server, by querying the API directly.
func checkZoneExistsFn(t *testing.T, zone string) resource.TestCheckFunc {
	t.Helper()
	return func(_ *terraform.State) error {
		c := testAccDirectClient(t)
		exists, err := c.ZoneExists(context.Background(), zone)
		if err != nil {
			return fmt.Errorf("direct API check: ZoneExists for %q: %w", zone, err)
		}
		if !exists {
			return fmt.Errorf("zone %q is not present on the Technitium server (expected to exist)", zone)
		}
		return nil
	}
}

func testAccCatalogMembershipZonesOnly(memberZone, catalogZone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "catalog" {
  name = %q
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "member" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`, testAccAPIToken(), catalogZone, memberZone)
}

func testAccCatalogMembershipBasic(memberZone, catalogZone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "catalog" {
  name = %q
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "member" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "test" {
  zone         = technitium_zone.member.name
  catalog_zone = technitium_zone.catalog.name
}
`, testAccAPIToken(), catalogZone, memberZone)
}

func testAccCatalogMembershipTwoCatalogs(memberZone, catalogA, catalogB, active string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "catalog_a" {
  name = %q
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "catalog_b" {
  name = %q
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "member" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "test" {
  zone         = technitium_zone.member.name
  catalog_zone = %q

  depends_on = [
    technitium_zone.catalog_a,
    technitium_zone.catalog_b,
  ]
}
`, testAccAPIToken(), catalogA, catalogB, memberZone, active)
}

func testAccCatalogMembershipMissingCatalog(memberZone, missingCatalog string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "member" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "test" {
  zone         = technitium_zone.member.name
  catalog_zone = %q
}
`, testAccAPIToken(), memberZone, missingCatalog)
}

func testAccCatalogMembershipMissingMember(missingMember, catalogZone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "catalog" {
  name = %q
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "test" {
  zone         = %q
  catalog_zone = technitium_zone.catalog.name
}
`, testAccAPIToken(), catalogZone, missingMember)
}

func testAccCatalogMembershipWrongType(memberZone, wrongCatalog string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "wrong" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "member" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "test" {
  zone         = technitium_zone.member.name
  catalog_zone = technitium_zone.wrong.name
}
`, testAccAPIToken(), wrongCatalog, memberZone)
}

func testAccCatalogMembershipSelfReference(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_catalog_membership" "self" {
  zone         = %q
  catalog_zone = %q
}
`, testAccAPIToken(), zone, zone)
}
