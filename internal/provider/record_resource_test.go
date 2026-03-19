// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRecordResource_A(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create
			{
				Config: testAccRecordA("rec-a-test.example.com", "www.rec-a-test.example.com", "192.0.2.10"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.web", "name", "www.rec-a-test.example.com"),
					resource.TestCheckResourceAttr("technitium_record.web", "type", "A"),
					resource.TestCheckResourceAttr("technitium_record.web", "value", "192.0.2.10"),
					resource.TestCheckResourceAttr("technitium_record.web", "ttl", "3600"),
				),
			},
			// Update value
			{
				Config: testAccRecordA("rec-a-test.example.com", "www.rec-a-test.example.com", "192.0.2.20"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.web", "value", "192.0.2.20"),
				),
			},
			// Import
			{
				ResourceName:            "technitium_record.web",
				ImportState:             true,
				ImportStateId:           "rec-a-test.example.com/www.rec-a-test.example.com/A",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"overwrite"},
			},
		},
	})
}

func TestAccRecordResource_CNAME(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordCNAME("rec-cname-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.alias", "type", "CNAME"),
					resource.TestCheckResourceAttr("technitium_record.alias", "value", "rec-cname-test.example.com"),
				),
			},
		},
	})
}

func TestAccRecordResource_TXT(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordTXT("rec-txt-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.spf", "type", "TXT"),
					resource.TestCheckResourceAttr("technitium_record.spf", "value", "v=spf1 -all"),
				),
			},
		},
	})
}

func TestAccRecordResource_AAAA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordAAAA("rec-aaaa-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.ipv6", "type", "AAAA"),
					resource.TestCheckResourceAttr("technitium_record.ipv6", "value", "2001:db8::1"),
				),
			},
		},
	})
}

func TestAccRecordResource_MX(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMX("rec-mx-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.mail", "type", "MX"),
					resource.TestCheckResourceAttr("technitium_record.mail", "value", "mail.rec-mx-test.example.com"),
					resource.TestCheckResourceAttr("technitium_record.mail", "priority", "10"),
				),
			},
		},
	})
}

func TestAccRecordResource_SRV(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordSRV("rec-srv-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.sip", "type", "SRV"),
					resource.TestCheckResourceAttr("technitium_record.sip", "value", "sip.rec-srv-test.example.com"),
					resource.TestCheckResourceAttr("technitium_record.sip", "priority", "10"),
					resource.TestCheckResourceAttr("technitium_record.sip", "weight", "60"),
					resource.TestCheckResourceAttr("technitium_record.sip", "port", "5060"),
				),
			},
		},
	})
}

func TestAccRecordResource_NS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordNS("rec-ns-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.ns", "type", "NS"),
					resource.TestCheckResourceAttr("technitium_record.ns", "value", "ns2.rec-ns-test.example.com"),
				),
			},
		},
	})
}

func TestAccRecordResource_PTR(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordPTR(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.ptr", "type", "PTR"),
					resource.TestCheckResourceAttr("technitium_record.ptr", "value", "web.rec-ptr-test.example.com"),
				),
			},
		},
	})
}

func TestAccRecordResource_CAA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordCAA("rec-caa-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.caa", "type", "CAA"),
					resource.TestCheckResourceAttr("technitium_record.caa", "value", "letsencrypt.org"),
					resource.TestCheckResourceAttr("technitium_record.caa", "caa_flags", "0"),
					resource.TestCheckResourceAttr("technitium_record.caa", "caa_tag", "issue"),
				),
			},
		},
	})
}

func TestAccRecordDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordDataSource("rec-ds-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_record.web", "value", "192.0.2.100"),
					resource.TestCheckResourceAttr("data.technitium_record.web", "ttl", "3600"),
				),
			},
		},
	})
}

func testAccRecordA(zone, name, ip string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "web" {
  zone  = technitium_zone.test.name
  name  = %q
  type  = "A"
  ttl   = 3600
  value = %q
}
`, testAccAPIToken(), zone, name, ip)
}

func testAccRecordCNAME(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "alias" {
  zone  = technitium_zone.test.name
  name  = "www.%s"
  type  = "CNAME"
  value = %q
}
`, testAccAPIToken(), zone, zone, zone)
}

func testAccRecordTXT(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "spf" {
  zone  = technitium_zone.test.name
  name  = %q
  type  = "TXT"
  value = "v=spf1 -all"
}
`, testAccAPIToken(), zone, zone)
}

func testAccRecordAAAA(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "ipv6" {
  zone  = technitium_zone.test.name
  name  = "www.%s"
  type  = "AAAA"
  value = "2001:db8::1"
}
`, testAccAPIToken(), zone, zone)
}

func testAccRecordMX(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "mail" {
  zone     = technitium_zone.test.name
  name     = %q
  type     = "MX"
  value    = "mail.%s"
  priority = 10
}
`, testAccAPIToken(), zone, zone, zone)
}

func testAccRecordSRV(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "sip" {
  zone     = technitium_zone.test.name
  name     = "_sip._tcp.%s"
  type     = "SRV"
  value    = "sip.%s"
  priority = 10
  weight   = 60
  port     = 5060
}
`, testAccAPIToken(), zone, zone, zone)
}

func testAccRecordNS(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "ns" {
  zone  = technitium_zone.test.name
  name  = %q
  type  = "NS"
  value = "ns2.%s"
}
`, testAccAPIToken(), zone, zone, zone)
}

func testAccRecordPTR() string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "reverse" {
  name = "2.0.192.in-addr.arpa"
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "ptr" {
  zone  = technitium_zone.reverse.name
  name  = "10.2.0.192.in-addr.arpa"
  type  = "PTR"
  value = "web.rec-ptr-test.example.com"
}
`, testAccAPIToken())
}

func testAccRecordCAA(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "caa" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "CAA"
  value     = "letsencrypt.org"
  caa_flags = 0
  caa_tag   = "issue"
}
`, testAccAPIToken(), zone, zone)
}

func testAccRecordDataSource(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "seed" {
  zone  = technitium_zone.test.name
  name  = "www.%s"
  type  = "A"
  value = "192.0.2.100"
}

data "technitium_record" "web" {
  zone = technitium_zone.test.name
  name = technitium_record.seed.name
  type = "A"
}
`, testAccAPIToken(), zone, zone)
}

func TestAccRecordResource_InputValidation_ARecordRejectsIPv6(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "technitium_record" "test" {
  zone  = "example.com"
  name  = "www.example.com"
  type  = "A"
  value = "2001:db8::1"
}`,
				ExpectError: regexp.MustCompile(`Invalid A record value`),
			},
		},
	})
}

func TestAccRecordResource_InputValidation_InvalidType(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "technitium_record" "test" {
  zone  = "example.com"
  name  = "www.example.com"
  type  = "INVALID"
  value = "192.0.2.1"
}`,
				ExpectError: regexp.MustCompile(`Invalid record type`),
			},
		},
	})
}

func TestAccRecordResource_InputValidation_CAAMissingTag(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "technitium_record" "test" {
  zone      = "example.com"
  name      = "example.com"
  type      = "CAA"
  value     = "letsencrypt.org"
  caa_flags = 0
}`,
				ExpectError: regexp.MustCompile(`CAA record missing required field: caa_tag`),
			},
		},
	})
}
