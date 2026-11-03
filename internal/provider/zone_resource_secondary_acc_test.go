// Copyright (c) 2026 Tristan Milnthorp
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// These tests prove an actual zone transfer (AXFR), not just that the provider
// sends the right parameters. docker-compose.test.yml runs two Technitium
// servers on a fixed network:
//
//	technitium          172.29.168.2   the server the provider manages: the SECONDARY
//	technitium-primary  172.29.168.10  the PRIMARY, set up directly through its API
//
// The primary holds a zone and allows transfers only to the secondary's
// address. The secondary zone is then created through the provider with
// primary_name_server_addresses, and the tests assert that the primary's
// records appear on the secondary.
const (
	accPrimaryDefaultURL = "http://127.0.0.1:5381"
	accPrimaryAdminUser  = "admin"
	accPrimaryAdminPass  = "acc-primary-fixture" // matches docker-compose.test.yml
	accPrimaryAddress    = "172.29.168.10"
	accSecondaryAddress  = "172.29.168.2"
	accTSIGSecret        = "dGVzdHNlY3JldGtleWZvcmFjY2VwdGFuY2V0ZXN0cw=="
)

// testAccPrimaryClient returns an API client for the second ("primary")
// Technitium container.
func testAccPrimaryClient(t *testing.T) *client.Client {
	t.Helper()
	skipUnlessAcceptance(t)
	baseURL := os.Getenv("TECHNITIUM_PRIMARY_URL")
	if baseURL == "" {
		baseURL = accPrimaryDefaultURL
	}
	c, err := client.NewClient(client.ClientConfig{
		BaseURL:  baseURL,
		Username: accPrimaryAdminUser,
		Password: accPrimaryAdminPass,
	})
	if err != nil {
		t.Fatalf("primary client: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("logging in to the primary test container at %s (is it up? see docker-compose.test.yml): %v", baseURL, err)
	}
	return c
}

// testAccSeedPrimaryZone creates a Primary zone on the primary container with
// one A record, allows transfers to the secondary's address (and, when
// tsigKey is set, only with that key), and removes the zone again on cleanup.
func testAccSeedPrimaryZone(t *testing.T, zone, host, ip, tsigKey string) {
	t.Helper()
	ctx := context.Background()
	p := testAccPrimaryClient(t)

	_ = p.ZoneDelete(ctx, zone) // leftovers from an aborted run
	if _, err := p.ZoneCreate(ctx, zone, "Primary", false); err != nil {
		t.Fatalf("creating zone on primary: %v", err)
	}
	t.Cleanup(func() { _ = p.ZoneDelete(context.Background(), zone) })

	if _, err := p.RecordAdd(ctx, host+"."+zone, zone, "A", 300, true, map[string]string{"ipAddress": ip}); err != nil {
		t.Fatalf("adding record on primary: %v", err)
	}

	if tsigKey != "" {
		_ = p.TSIGKeyDelete(ctx, tsigKey)
		if err := p.TSIGKeyCreate(ctx, client.TSIGKey{KeyName: tsigKey, SharedSecret: accTSIGSecret, AlgorithmName: "hmac-sha256"}); err != nil {
			t.Fatalf("creating TSIG key on primary: %v", err)
		}
		t.Cleanup(func() { _ = p.TSIGKeyDelete(context.Background(), tsigKey) })
	}
	opts := map[string]string{
		"zoneTransfer":           "UseSpecifiedNetworkACL",
		"zoneTransferNetworkACL": accSecondaryAddress,
	}
	if tsigKey != "" {
		opts["zoneTransferTsigKeyNames"] = tsigKey
	}
	if err := p.ZoneOptionsSet(ctx, zone, opts); err != nil {
		t.Fatalf("allowing transfer on primary: %v", err)
	}
}

// testAccCheckSecondaryHasRecord asserts that the managed (secondary) server
// holds host.zone A ip: data it could only have obtained by AXFR from the
// primary, since nothing else writes it.
func testAccCheckSecondaryHasRecord(t *testing.T, zone, host, ip string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		c := testAccDirectClient(t)
		deadline := time.Now().Add(20 * time.Second)
		var lastErr error
		for {
			recs, err := c.RecordGet(context.Background(), host+"."+zone, zone)
			if err == nil {
				for _, r := range recs {
					if r.Type == "A" && fmt.Sprint(r.RData["ipAddress"]) == ip {
						return nil
					}
				}
				lastErr = fmt.Errorf("no A %s for %s.%s on the secondary yet: %+v", ip, host, zone, recs)
			} else {
				lastErr = err
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the secondary never received the zone by AXFR: %w", lastErr)
			}
			time.Sleep(time.Second)
		}
	}
}

func testAccSecondaryZoneConfig(zone, extra string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "secondary" {
  name = %q
  type = "Secondary"
%s}
`, zone, extra)
}

func TestAccZoneResource_Secondary_TransfersFromPrimary(t *testing.T) {
	const (
		zone = "acc-axfr.example.com"
		ip   = "192.0.2.53"
	)
	testAccSeedPrimaryZone(t, zone, "www", ip, "")

	byAddr := fmt.Sprintf(`  primary_name_server_addresses = [%q]
  zone_transfer_protocol        = "Tcp"
`, accPrimaryAddress)
	// Adding a second, unreachable primary exercises the options/set update
	// path; the first stays valid so the zone keeps serving.
	twoPrimaries := fmt.Sprintf(`  primary_name_server_addresses = [%q, "172.29.168.99"]
  zone_transfer_protocol        = "Tcp"
`, accPrimaryAddress)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSecondaryZoneConfig(zone, byAddr),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.secondary", "type", "Secondary"),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_name_server_addresses.#", "1"),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_name_server_addresses.0", accPrimaryAddress),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "zone_transfer_protocol", "Tcp"),
					testAccCheckSecondaryHasRecord(t, zone, "www", ip),
				),
			},
			{
				// Update path: zones/options/set. The plan after apply must be
				// empty (checked by the framework), proving no perpetual diff.
				Config: testAccSecondaryZoneConfig(zone, twoPrimaries),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_name_server_addresses.#", "2"),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_name_server_addresses.1", "172.29.168.99"),
				),
			},
			{
				// Omitting the attributes leaves the server's values alone.
				Config: testAccSecondaryZoneConfig(zone, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_name_server_addresses.#", "2"),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "zone_transfer_protocol", "Tcp"),
				),
			},
			{
				ResourceName:            "technitium_zone.secondary",
				ImportState:             true,
				ImportStateId:           zone,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"dnssec"},
			},
		},
	})
}

// Omitting the protocol must read back the server default without a diff, and
// a TSIG-authenticated transfer must carry the key on the create call (the
// first transfer happens inside zones/create).
func TestAccZoneResource_Secondary_TSIGAuthenticatedTransfer(t *testing.T) {
	const (
		zone    = "acc-axfr-tsig.example.com"
		keyName = "acc-axfr-key"
		ip      = "192.0.2.54"
	)
	testAccSeedPrimaryZone(t, zone, "www", ip, keyName)

	cfg := testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "axfr" {
  key_name      = %q
  algorithm     = "hmac-sha256"
  shared_secret = %q
}

resource "technitium_zone" "secondary" {
  name                                = %q
  type                                = "Secondary"
  primary_name_server_addresses       = [%q]
  primary_zone_transfer_tsig_key_name = technitium_tsig_key.axfr.key_name
}
`, keyName, accTSIGSecret, zone, accPrimaryAddress)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.secondary", "zone_transfer_protocol", "Tcp"),
					resource.TestCheckResourceAttr("technitium_zone.secondary", "primary_zone_transfer_tsig_key_name", keyName),
					testAccCheckSecondaryHasRecord(t, zone, "www", ip),
				),
			},
		},
	})
}

// Plan-time validation needs no second server.
func TestAccZoneResource_PrimaryNameServers_RejectedOnPrimaryZone(t *testing.T) {
	skipUnlessAcceptance(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name                          = "acc-primaries-on-primary.example.com"
  type                          = "Primary"
  primary_name_server_addresses = ["10.0.0.1"]
}
`,
				ExpectError: regexp.MustCompile(`Invalid zone type for primary_name_server_addresses`),
			},
			{
				Config: testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name                   = "acc-proto-on-stub.example.com"
  type                   = "Stub"
  zone_transfer_protocol = "Tls"
}
`,
				ExpectError: regexp.MustCompile(`Invalid zone type for zone_transfer_protocol`),
			},
		},
	})
}

// A Primary zone never shows the new attributes, on create or on re-plan.
func TestAccZoneResource_PrimaryZone_NewAttributesStayNull(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceConfig("acc-primary-null.example.com", "Primary"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("technitium_zone.test", "primary_name_server_addresses.#"),
					resource.TestCheckNoResourceAttr("technitium_zone.test", "zone_transfer_protocol"),
				),
			},
		},
	})
}
