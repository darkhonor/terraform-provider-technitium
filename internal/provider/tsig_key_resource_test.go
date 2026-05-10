// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccTSIGKeyResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "key_name", "acc-basic.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "algorithm", "hmac-sha256"),
					resource.TestCheckResourceAttrSet("technitium_tsig_key.test", "shared_secret"),
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "id", "acc-basic.example.com"),
				),
			},
			{
				ResourceName:            "technitium_tsig_key.test",
				ImportState:             true,
				ImportStateId:           "acc-basic.example.com",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"shared_secret"},
			},
		},
	})
}

func testAccTSIGKeyResourceBasic() string {
	return testAccProviderHCL() + `
resource "technitium_tsig_key" "test" {
  key_name      = "acc-basic.example.com"
  algorithm     = "hmac-sha256"
  shared_secret = "dGVzdHNlY3JldGtleWZvcmFjY2VwdGFuY2V0ZXN0cw=="
}
`
}

func TestAccTSIGKeyResource_generated_secret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceGeneratedSecret(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.gen", "key_name", "acc-gen.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.gen", "algorithm", "hmac-sha256"),
					resource.TestCheckResourceAttrSet("technitium_tsig_key.gen", "shared_secret"),
				),
			},
		},
	})
}

func testAccTSIGKeyResourceGeneratedSecret() string {
	return testAccProviderHCL() + `
resource "technitium_tsig_key" "gen" {
  key_name  = "acc-gen.example.com"
  algorithm = "hmac-sha256"
}
`
}

func TestAccTSIGKeyResource_update_algorithm(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceWithAlgo("acc-updalgo.example.com", "hmac-sha256", "dGVzdHNlY3JldGtleWZvcmFjY2VwdGFuY2V0ZXN0cw=="),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.upd", "algorithm", "hmac-sha256"),
				),
			},
			{
				Config: testAccTSIGKeyResourceWithAlgo("acc-updalgo.example.com", "hmac-sha512", "dGVzdHNlY3JldGtleWZvcmFjY2VwdGFuY2V0ZXN0cw=="),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.upd", "algorithm", "hmac-sha512"),
				),
			},
		},
	})
}

func testAccTSIGKeyResourceWithAlgo(name, algo, secret string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "upd" {
  key_name      = %q
  algorithm     = %q
  shared_secret = %q
}
`, name, algo, secret)
}

func TestAccTSIGKeyResource_update_secret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceWithAlgo("acc-updsec.example.com", "hmac-sha256", "c2VjcmV0b25l"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.upd", "shared_secret", "c2VjcmV0b25l"),
				),
			},
			{
				Config: testAccTSIGKeyResourceWithAlgo("acc-updsec.example.com", "hmac-sha256", "c2VjcmV0dHdv"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.upd", "shared_secret", "c2VjcmV0dHdv"),
				),
			},
		},
	})
}

func TestAccTSIGKeyResource_multiple_keys(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceMultiple(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.key1", "key_name", "acc-multi1.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.key2", "key_name", "acc-multi2.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.key1", "algorithm", "hmac-sha256"),
					resource.TestCheckResourceAttr("technitium_tsig_key.key2", "algorithm", "hmac-sha512"),
				),
			},
		},
	})
}

func testAccTSIGKeyResourceMultiple() string {
	return testAccProviderHCL() + `
resource "technitium_tsig_key" "key1" {
  key_name      = "acc-multi1.example.com"
  algorithm     = "hmac-sha256"
  shared_secret = "a2V5b25lc2VjcmV0"
}

resource "technitium_tsig_key" "key2" {
  key_name      = "acc-multi2.example.com"
  algorithm     = "hmac-sha512"
  shared_secret = "a2V5dHdvc2VjcmV0"

  depends_on = [technitium_tsig_key.key1]
}
`
}

func TestAccTSIGKeyResource_rename_forces_new(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceWithName("acc-rename-old.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.rename", "key_name", "acc-rename-old.example.com"),
				),
			},
			{
				Config: testAccTSIGKeyResourceWithName("acc-rename-new.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.rename", "key_name", "acc-rename-new.example.com"),
				),
			},
		},
	})
}

func testAccTSIGKeyResourceWithName(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "rename" {
  key_name      = %q
  algorithm     = "hmac-sha256"
  shared_secret = "cmVuYW1ldGVzdHNlY3JldA=="
}
`, name)
}

func TestAccTSIGKeyResource_algorithms(t *testing.T) {
	algorithms := []string{
		"hmac-md5.sig-alg.reg.int",
		"hmac-sha1",
		"hmac-sha256",
		"hmac-sha256-128",
		"hmac-sha384",
		"hmac-sha384-192",
		"hmac-sha512",
		"hmac-sha512-256",
	}
	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccTSIGKeyResourceAlgorithm(algo),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr("technitium_tsig_key.algo", "algorithm", algo),
						),
					},
				},
			})
		})
	}
}

// --- NSS acceptance tests ---

func testAccTSIGKeyResourceNSS(name, algo string) string {
	return testAccProviderHCL_NSS("high", "high", "moderate") + fmt.Sprintf(`
resource "technitium_tsig_key" "nss" {
  key_name  = %q
  algorithm = %q
}
`, name, algo)
}

func TestAccTSIGKeyResource_NSS_allowed_sha256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceNSS("acc-nss-sha256.example.com", "hmac-sha256"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "key_name", "acc-nss-sha256.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "algorithm", "hmac-sha256"),
				),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_allowed_sha384(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceNSS("acc-nss-sha384.example.com", "hmac-sha384"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "key_name", "acc-nss-sha384.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "algorithm", "hmac-sha384"),
				),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_allowed_sha512(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceNSS("acc-nss-sha512.example.com", "hmac-sha512"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "key_name", "acc-nss-sha512.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.nss", "algorithm", "hmac-sha512"),
				),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_blocked_md5(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccTSIGKeyResourceNSS("acc-nss-md5.example.com", "hmac-md5.sig-alg.reg.int"),
				ExpectError: regexp.MustCompile(`(not allowed in NSS mode|DNS-REQ-002.*crypto auth)`),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_blocked_sha1(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccTSIGKeyResourceNSS("acc-nss-sha1.example.com", "hmac-sha1"),
				ExpectError: regexp.MustCompile(`(not allowed in NSS mode|DNS-REQ-002.*crypto auth)`),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_blocked_sha256_128(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccTSIGKeyResourceNSS("acc-nss-sha256-128.example.com", "hmac-sha256-128"),
				ExpectError: regexp.MustCompile(`(not allowed in NSS mode|DNS-REQ-002.*crypto auth)`),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_blocked_sha384_192(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccTSIGKeyResourceNSS("acc-nss-sha384-192.example.com", "hmac-sha384-192"),
				ExpectError: regexp.MustCompile(`(not allowed in NSS mode|DNS-REQ-002.*crypto auth)`),
			},
		},
	})
}

func TestAccTSIGKeyResource_NSS_blocked_sha512_256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccTSIGKeyResourceNSS("acc-nss-sha512-256.example.com", "hmac-sha512-256"),
				ExpectError: regexp.MustCompile(`(not allowed in NSS mode|DNS-REQ-002.*crypto auth)`),
			},
		},
	})
}

func TestAccTSIGKeyDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyDataSourceBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_tsig_key.test", "key_name", "acc-ds.example.com"),
					resource.TestCheckResourceAttr("data.technitium_tsig_key.test", "algorithm", "hmac-sha256"),
					resource.TestCheckResourceAttrSet("data.technitium_tsig_key.test", "shared_secret"),
				),
			},
		},
	})
}

func testAccTSIGKeyDataSourceBasic() string {
	return testAccProviderHCL() + `
resource "technitium_tsig_key" "seed" {
  key_name      = "acc-ds.example.com"
  algorithm     = "hmac-sha256"
  shared_secret = "ZGF0YXNvdXJjZXRlc3RzZWNyZXQ="
}

data "technitium_tsig_key" "test" {
  key_name = technitium_tsig_key.seed.key_name
}
`
}

func testAccTSIGKeyResourceAlgorithm(algo string) string {
	keyName := fmt.Sprintf("acc-algo-%s.example.com", algo)
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "algo" {
  key_name  = %q
  algorithm = %q
}
`, keyName, algo)
}
