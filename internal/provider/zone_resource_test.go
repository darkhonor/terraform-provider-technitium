// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccZoneResource_Primary(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccZoneResourceConfig("acc-test.example.com", "Primary"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.test", "name", "acc-test.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.test", "type", "Primary"),
					resource.TestCheckResourceAttr("technitium_zone.test", "status", "enabled"),
					resource.TestCheckResourceAttr("technitium_zone.test", "dnssec_status", "SignedWithNSEC3"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_zone.test",
				ImportState:       true,
				ImportStateId:     "acc-test.example.com",
				ImportStateVerify: true,
				// soa_serial_date_scheme is a create-only param, can't be read back
				ImportStateVerifyIgnore: []string{"soa_serial_date_scheme", "dnssec"},
			},
		},
	})
}

func TestAccZoneResource_PrimaryNoDNSSEC(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNoDNSSEC("acc-unsigned.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.unsigned", "name", "acc-unsigned.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.unsigned", "dnssec_status", "Unsigned"),
				),
			},
		},
	})
}

func TestAccZoneDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDataSourceConfig("acc-ds.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_zone.test", "name", "acc-ds.example.com"),
					resource.TestCheckResourceAttr("data.technitium_zone.test", "type", "Primary"),
				),
			},
		},
	})
}

func TestAccZoneResource_NSSRejectsP256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceNSSP256("acc-nss-reject.example.com"),
				ExpectError: regexp.MustCompile(`P256 not allowed in NSS mode`),
			},
		},
	})
}

func TestAccZoneResource_NSSAcceptsP384(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNSSP384("acc-nss-p384.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nss", "name", "acc-nss-p384.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.nss", "dnssec_status", "SignedWithNSEC3"),
					resource.TestCheckResourceAttr("technitium_zone.nss", "dnssec.curve", "P384"),
				),
			},
		},
	})
}

func TestAccZoneResource_NonNSSKeepsP256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNonNSSP256("acc-nonnss.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "name", "acc-nonnss.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "dnssec_status", "SignedWithNSEC3"),
					// Without NSS, P256 should stay P256
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "dnssec.curve", "P256"),
				),
			},
		},
	})
}

func TestAccZoneResource_ZoneTransferTsigKeys(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceWithTsigKeys("acc-tsig-xfer.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "name", "acc-tsig-xfer.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "1"),
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.0", "acc-xfer-key.example.com"),
				),
			},
		},
	})
}

func TestAccZoneResource_ZoneTransferTsigKeys_Clear(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create zone with TSIG key
			{
				Config: testAccZoneResourceWithTsigKeys("acc-tsig-clear.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "1"),
				),
			},
			// Step 2: Remove TSIG keys
			{
				Config: testAccZoneResourceNoTsigKeys("acc-tsig-clear.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "0"),
				),
			},
		},
	})
}

func TestAccZoneResource_PrimaryTsigKeyOnPrimaryZone_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourcePrimaryTsigOnPrimary(),
				ExpectError: regexp.MustCompile(`only valid for Secondary`),
			},
		},
	})
}

func testAccZoneResourcePrimaryTsigOnPrimary() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-primary-tsig.example.com"
  type = "Primary"

  primary_zone_transfer_tsig_key_name = "nonexistent-key"

  dnssec {
    enabled = false
  }
}
`
}

func TestAccZoneResource_ZoneTransferTsigKeys_OnStub_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceTsigKeysOnStub(),
				ExpectError: regexp.MustCompile(`only valid for Primary`),
			},
		},
	})
}

func testAccZoneResourceTsigKeysOnStub() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-stub-tsig.example.com"
  type = "Stub"

  zone_transfer_tsig_key_names = ["some-key"]
}
`
}

func TestAccZoneResource_TsigKeyNotFound_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceTsigKeyNotFound(),
				ExpectError: regexp.MustCompile(`TSIG key .* not found`),
			},
		},
	})
}

func testAccZoneResourceTsigKeyNotFound() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-notfound-tsig.example.com"
  type = "Primary"

  zone_transfer_tsig_key_names = ["nonexistent-key.example.com"]

  dnssec {
    enabled = false
  }
}
`
}

func testAccZoneResourceWithTsigKeys(zoneName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "xfer" {
  key_name  = "acc-xfer-key.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "tsig" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = [technitium_tsig_key.xfer.key_name]

  dnssec {
    enabled = false
  }
}
`, zoneName)
}

func testAccZoneResourceNoTsigKeys(zoneName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "xfer" {
  key_name  = "acc-xfer-key.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "tsig" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = []

  dnssec {
    enabled = false
  }
}
`, zoneName)
}

func testAccZoneResourceNSSP256(name string) string {
	return testAccProviderHCL_NSS("high", "high", "moderate") + fmt.Sprintf(`
resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, name)
}

func testAccZoneResourceNSSP384(name string) string {
	return testAccProviderHCL_NSS("high", "high", "moderate") + fmt.Sprintf(`
resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`, name)
}

func testAccZoneResourceNonNSSP256(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "nonnss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, name)
}

func testAccZoneResourceConfig(name, zoneType string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "test" {
  name = %q
  type = %q

  soa_serial_date_scheme = true

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, name, zoneType)
}

func testAccZoneResourceNoDNSSEC(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "unsigned" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`, name)
}

func testAccZoneDataSourceConfig(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "seed" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

data "technitium_zone" "test" {
  name = technitium_zone.seed.name
}
`, name)
}

// testAccDirectClient creates a direct API client for test setup operations
// that need to bypass Terraform resource lifecycle.
func testAccDirectClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.NewClient(client.ClientConfig{BaseURL: "http://127.0.0.1:5380", Token: testAccAPIToken()})
	if err != nil {
		t.Fatalf("failed to create direct API client: %s", err)
	}
	return c
}

// testAccZoneResourceNSSTsigKey creates both a TSIG key and zone with NSS enabled.
// Only works for NSS-compliant algorithms (sha256, sha384, sha512).
func testAccZoneResourceNSSTsigKey(zoneName, keyName, algo string) string {
	return testAccProviderHCL_NSS("high", "high", "moderate") + fmt.Sprintf(`
resource "technitium_tsig_key" "test" {
  key_name  = %q
  algorithm = %q
}

resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = [technitium_tsig_key.test.key_name]

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`, keyName, algo, zoneName)
}

// testAccZoneOnlyNSSReferencingKey creates ONLY a zone (not the key) with NSS enabled,
// referencing a pre-existing TSIG key by name string literal.
func testAccZoneOnlyNSSReferencingKey(zoneName, keyName string) string {
	return testAccProviderHCL_NSS("high", "high", "moderate") + fmt.Sprintf(`
resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = [%q]

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`, zoneName, keyName)
}

func TestAccZoneResource_NSS_TsigKeyCompliant_sha256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNSSTsigKey("acc-nss-ztsig-sha256.example.com", "acc-nss-zk-sha256.example.com", "hmac-sha256"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nss", "zone_transfer_tsig_key_names.#", "1"),
				),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyCompliant_sha384(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNSSTsigKey("acc-nss-ztsig-sha384.example.com", "acc-nss-zk-sha384.example.com", "hmac-sha384"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nss", "zone_transfer_tsig_key_names.#", "1"),
				),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyCompliant_sha512(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNSSTsigKey("acc-nss-ztsig-sha512.example.com", "acc-nss-zk-sha512.example.com", "hmac-sha512"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nss", "zone_transfer_tsig_key_names.#", "1"),
				),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyNonCompliant_md5(t *testing.T) {
	c := testAccDirectClient(t)
	keyName := "acc-nss-zk-md5.example.com"
	_ = c.TSIGKeyDelete(context.Background(), keyName) // best-effort cleanup of stale key from prior runs
	if err := c.TSIGKeyCreate(context.Background(), client.TSIGKey{KeyName: keyName, AlgorithmName: "hmac-md5.sig-alg.reg.int"}); err != nil {
		t.Fatalf("failed to pre-create TSIG key: %s", err)
	}
	t.Cleanup(func() {
		if err := c.TSIGKeyDelete(context.Background(), keyName); err != nil {
			t.Logf("cleanup: failed to delete TSIG key %s: %v", keyName, err)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneOnlyNSSReferencingKey("acc-nss-ztsig-md5.example.com", keyName),
				ExpectError: regexp.MustCompile(`TSIG key does not meet NSS`),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyNonCompliant_sha1(t *testing.T) {
	c := testAccDirectClient(t)
	keyName := "acc-nss-zk-sha1.example.com"
	_ = c.TSIGKeyDelete(context.Background(), keyName) // best-effort cleanup of stale key from prior runs
	if err := c.TSIGKeyCreate(context.Background(), client.TSIGKey{KeyName: keyName, AlgorithmName: "hmac-sha1"}); err != nil {
		t.Fatalf("failed to pre-create TSIG key: %s", err)
	}
	t.Cleanup(func() {
		if err := c.TSIGKeyDelete(context.Background(), keyName); err != nil {
			t.Logf("cleanup: failed to delete TSIG key %s: %v", keyName, err)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneOnlyNSSReferencingKey("acc-nss-ztsig-sha1.example.com", keyName),
				ExpectError: regexp.MustCompile(`TSIG key does not meet NSS`),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyNonCompliant_sha256_128(t *testing.T) {
	c := testAccDirectClient(t)
	keyName := "acc-nss-zk-sha256-128.example.com"
	_ = c.TSIGKeyDelete(context.Background(), keyName) // best-effort cleanup of stale key from prior runs
	if err := c.TSIGKeyCreate(context.Background(), client.TSIGKey{KeyName: keyName, AlgorithmName: "hmac-sha256-128"}); err != nil {
		t.Fatalf("failed to pre-create TSIG key: %s", err)
	}
	t.Cleanup(func() {
		if err := c.TSIGKeyDelete(context.Background(), keyName); err != nil {
			t.Logf("cleanup: failed to delete TSIG key %s: %v", keyName, err)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneOnlyNSSReferencingKey("acc-nss-ztsig-sha256-128.example.com", keyName),
				ExpectError: regexp.MustCompile(`TSIG key does not meet NSS`),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyNonCompliant_sha384_192(t *testing.T) {
	c := testAccDirectClient(t)
	keyName := "acc-nss-zk-sha384-192.example.com"
	_ = c.TSIGKeyDelete(context.Background(), keyName) // best-effort cleanup of stale key from prior runs
	if err := c.TSIGKeyCreate(context.Background(), client.TSIGKey{KeyName: keyName, AlgorithmName: "hmac-sha384-192"}); err != nil {
		t.Fatalf("failed to pre-create TSIG key: %s", err)
	}
	t.Cleanup(func() {
		if err := c.TSIGKeyDelete(context.Background(), keyName); err != nil {
			t.Logf("cleanup: failed to delete TSIG key %s: %v", keyName, err)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneOnlyNSSReferencingKey("acc-nss-ztsig-sha384-192.example.com", keyName),
				ExpectError: regexp.MustCompile(`TSIG key does not meet NSS`),
			},
		},
	})
}

func TestAccZoneResource_NSS_TsigKeyNonCompliant_sha512_256(t *testing.T) {
	c := testAccDirectClient(t)
	keyName := "acc-nss-zk-sha512-256.example.com"
	_ = c.TSIGKeyDelete(context.Background(), keyName) // best-effort cleanup of stale key from prior runs
	if err := c.TSIGKeyCreate(context.Background(), client.TSIGKey{KeyName: keyName, AlgorithmName: "hmac-sha512-256"}); err != nil {
		t.Fatalf("failed to pre-create TSIG key: %s", err)
	}
	t.Cleanup(func() {
		if err := c.TSIGKeyDelete(context.Background(), keyName); err != nil {
			t.Logf("cleanup: failed to delete TSIG key %s: %v", keyName, err)
		}
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneOnlyNSSReferencingKey("acc-nss-ztsig-sha512-256.example.com", keyName),
				ExpectError: regexp.MustCompile(`TSIG key does not meet NSS`),
			},
		},
	})
}

func testAccAPIToken() string {
	// Read from environment — token is provisioned when the Docker test instance starts.
	// Set via .env.test or TECHNITIUM_API_TOKEN env var.
	token := os.Getenv("TECHNITIUM_API_TOKEN")
	if token == "" {
		// Fallback for CI or manual runs
		token = "7b34e85a6f9bdf8dacf8513024463408c51980663e47c1cd522f2f9071686388"
	}
	return token
}
