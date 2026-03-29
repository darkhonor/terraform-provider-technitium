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
					resource.TestMatchResourceAttr("technitium_record.web", "id",
						regexp.MustCompile(`^rec-a-test\.example\.com::www\.rec-a-test\.example\.com::A::192\.0\.2\.10$`)),
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
				ImportStateId:           "rec-a-test.example.com::www.rec-a-test.example.com::A::192.0.2.20",
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
					resource.TestMatchResourceAttr("technitium_record.mail", "id",
						regexp.MustCompile(`^rec-mx-test\.example\.com::rec-mx-test\.example\.com::MX::mail\.rec-mx-test\.example\.com:10$`)),
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
					resource.TestMatchResourceAttr("technitium_record.sip", "id",
						regexp.MustCompile(`^rec-srv-test\.example\.com::_sip\._tcp\.rec-srv-test\.example\.com::SRV::sip\.rec-srv-test\.example\.com:10:60:5060$`)),
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
					resource.TestMatchResourceAttr("technitium_record.caa", "id",
						regexp.MustCompile(`^rec-caa-test\.example\.com::rec-caa-test\.example\.com::CAA::letsencrypt\.org:0:issue$`)),
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

// --- Multi-Record Collision Tests (Tier 2) ---

func TestAccRecordResource_MultiA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiA("rec-multi-a.example.com", "rr.rec-multi-a.example.com", "10.20.99.1", "10.20.99.2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
					resource.TestCheckResourceAttr("technitium_record.a2", "value", "10.20.99.2"),
					resource.TestMatchResourceAttr("technitium_record.a1", "id",
						regexp.MustCompile(`::A::10\.20\.99\.1$`)),
					resource.TestMatchResourceAttr("technitium_record.a2", "id",
						regexp.MustCompile(`::A::10\.20\.99\.2$`)),
				),
			},
			// Re-apply — no drift expected
			{
				Config: testAccRecordMultiA("rec-multi-a.example.com", "rr.rec-multi-a.example.com", "10.20.99.1", "10.20.99.2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
					resource.TestCheckResourceAttr("technitium_record.a2", "value", "10.20.99.2"),
				),
			},
			// Update one record
			{
				Config: testAccRecordMultiA("rec-multi-a.example.com", "rr.rec-multi-a.example.com", "10.20.99.1", "10.20.99.3"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
					resource.TestCheckResourceAttr("technitium_record.a2", "value", "10.20.99.3"),
				),
			},
		},
	})
}

func testAccRecordMultiA(zone, name, ip1, ip2 string) string {
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

resource "technitium_record" "a1" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "A"
  value     = %q
  overwrite = false
}

resource "technitium_record" "a2" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "A"
  value     = %q
  overwrite = false
}
`, testAccAPIToken(), zone, name, ip1, name, ip2)
}

func TestAccRecordResource_MultiMX(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiMX("rec-multi-mx.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.mx1", "value", "mail1.rec-multi-mx.example.com"),
					resource.TestCheckResourceAttr("technitium_record.mx1", "priority", "10"),
					resource.TestCheckResourceAttr("technitium_record.mx2", "value", "mail2.rec-multi-mx.example.com"),
					resource.TestCheckResourceAttr("technitium_record.mx2", "priority", "20"),
				),
			},
			{
				Config: testAccRecordMultiMX("rec-multi-mx.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.mx1", "value", "mail1.rec-multi-mx.example.com"),
					resource.TestCheckResourceAttr("technitium_record.mx2", "value", "mail2.rec-multi-mx.example.com"),
				),
			},
		},
	})
}

func testAccRecordMultiMX(zone string) string {
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

resource "technitium_record" "mx1" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "MX"
  value     = "mail1.%s"
  priority  = 10
  overwrite = false
}

resource "technitium_record" "mx2" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "MX"
  value     = "mail2.%s"
  priority  = 20
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, zone, zone)
}

func TestAccRecordResource_MultiNS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiNS("rec-multi-ns.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.ns1", "value", "ns1.rec-multi-ns.example.com"),
					resource.TestCheckResourceAttr("technitium_record.ns2", "value", "ns2.rec-multi-ns.example.com"),
				),
			},
			{
				Config: testAccRecordMultiNS("rec-multi-ns.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.ns1", "value", "ns1.rec-multi-ns.example.com"),
					resource.TestCheckResourceAttr("technitium_record.ns2", "value", "ns2.rec-multi-ns.example.com"),
				),
			},
		},
	})
}

func testAccRecordMultiNS(zone string) string {
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

resource "technitium_record" "ns1" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "NS"
  value     = "ns1.%s"
  overwrite = false
}

resource "technitium_record" "ns2" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "NS"
  value     = "ns2.%s"
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, zone, zone)
}

func TestAccRecordResource_MultiCAA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiCAA("rec-multi-caa.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.caa_issue", "value", "letsencrypt.org"),
					resource.TestCheckResourceAttr("technitium_record.caa_issue", "caa_tag", "issue"),
					resource.TestCheckResourceAttr("technitium_record.caa_wild", "value", "letsencrypt.org"),
					resource.TestCheckResourceAttr("technitium_record.caa_wild", "caa_tag", "issuewild"),
				),
			},
			{
				Config: testAccRecordMultiCAA("rec-multi-caa.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.caa_issue", "caa_tag", "issue"),
					resource.TestCheckResourceAttr("technitium_record.caa_wild", "caa_tag", "issuewild"),
				),
			},
		},
	})
}

func testAccRecordMultiCAA(zone string) string {
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

resource "technitium_record" "caa_issue" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "CAA"
  value     = "letsencrypt.org"
  caa_flags = 0
  caa_tag   = "issue"
  overwrite = false
}

resource "technitium_record" "caa_wild" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "CAA"
  value     = "letsencrypt.org"
  caa_flags = 0
  caa_tag   = "issuewild"
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone)
}

// --- SRV Edge Case Tests ---

func TestAccRecordResource_MultiSRV_DifferentPorts(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiSRV("rec-multi-srv.example.com", 5060, 5061),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.srv1", "port", "5060"),
					resource.TestCheckResourceAttr("technitium_record.srv2", "port", "5061"),
				),
			},
			{
				Config: testAccRecordMultiSRV("rec-multi-srv.example.com", 5060, 5061),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.srv1", "port", "5060"),
					resource.TestCheckResourceAttr("technitium_record.srv2", "port", "5061"),
				),
			},
		},
	})
}

func testAccRecordMultiSRV(zone string, port1, port2 int) string {
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

resource "technitium_record" "srv1" {
  zone      = technitium_zone.test.name
  name      = "_sip._tcp.%s"
  type      = "SRV"
  value     = "sip.%s"
  priority  = 10
  weight    = 60
  port      = %d
  overwrite = false
}

resource "technitium_record" "srv2" {
  zone      = technitium_zone.test.name
  name      = "_sip._tcp.%s"
  type      = "SRV"
  value     = "sip.%s"
  priority  = 10
  weight    = 60
  port      = %d
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, port1, zone, zone, port2)
}

func TestAccRecordResource_MultiSRV_DifferentWeights(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiSRVWeights("rec-multi-srv-w.example.com", 60, 40),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.srv1", "weight", "60"),
					resource.TestCheckResourceAttr("technitium_record.srv2", "weight", "40"),
				),
			},
			{
				Config: testAccRecordMultiSRVWeights("rec-multi-srv-w.example.com", 60, 40),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.srv1", "weight", "60"),
					resource.TestCheckResourceAttr("technitium_record.srv2", "weight", "40"),
				),
			},
		},
	})
}

func testAccRecordMultiSRVWeights(zone string, weight1, weight2 int) string {
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

resource "technitium_record" "srv1" {
  zone      = technitium_zone.test.name
  name      = "_sip._tcp.%s"
  type      = "SRV"
  value     = "sip.%s"
  priority  = 10
  weight    = %d
  port      = 5060
  overwrite = false
}

resource "technitium_record" "srv2" {
  zone      = technitium_zone.test.name
  name      = "_sip._tcp.%s"
  type      = "SRV"
  value     = "sip.%s"
  priority  = 10
  weight    = %d
  port      = 5060
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, weight1, zone, zone, weight2)
}

// --- TXT Torture Tests ---

func TestAccRecordResource_MultiTXT(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiTXT("rec-multi-txt.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.spf", "value", "v=spf1 include:_spf.google.com ~all"),
					resource.TestCheckResourceAttr("technitium_record.dmarc", "value", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
					resource.TestCheckResourceAttr("technitium_record.verification", "value", "google-site-verification=abc123def456"),
				),
			},
			{
				Config: testAccRecordMultiTXT("rec-multi-txt.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.spf", "value", "v=spf1 include:_spf.google.com ~all"),
					resource.TestCheckResourceAttr("technitium_record.dmarc", "value", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
					resource.TestCheckResourceAttr("technitium_record.verification", "value", "google-site-verification=abc123def456"),
				),
			},
		},
	})
}

func testAccRecordMultiTXT(zone string) string {
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
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "v=spf1 include:_spf.google.com ~all"
  overwrite = false
}

resource "technitium_record" "dmarc" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
  overwrite = false
}

resource "technitium_record" "verification" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "google-site-verification=abc123def456"
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, zone)
}

func TestAccRecordResource_TXT_SpecialChars(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordTXTSpecialChars("rec-txt-special.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.with_colons", "value", "key::value::data"),
					resource.TestCheckResourceAttr("technitium_record.with_quotes", "value", `key="value"; other="data"`),
					resource.TestCheckResourceAttr("technitium_record.with_semicolons", "value", "v=spf1; redirect=_spf.example.com"),
				),
			},
			{
				Config: testAccRecordTXTSpecialChars("rec-txt-special.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.with_colons", "value", "key::value::data"),
					resource.TestCheckResourceAttr("technitium_record.with_quotes", "value", `key="value"; other="data"`),
				),
			},
		},
	})
}

func testAccRecordTXTSpecialChars(zone string) string {
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

resource "technitium_record" "with_colons" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "key::value::data"
  overwrite = false
}

resource "technitium_record" "with_quotes" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "key=\"value\"; other=\"data\""
  overwrite = false
}

resource "technitium_record" "with_semicolons" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "TXT"
  value     = "v=spf1; redirect=_spf.example.com"
  overwrite = false
}
`, testAccAPIToken(), zone, zone, zone, zone)
}

func TestAccRecordResource_TXT_LongValue(t *testing.T) {
	longValue := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
		"2vHhDhCmGQrYzFzDfPKRAhkjwHUhREFnYkEHIQfO2rjCqVYZShKMgrQOdDkEQ1GFBXNQ" +
		"3YPnjKJgLHsqXLz7GBNoaQzGC1RXNBEDQEOqPHS1ELGdKfrdSYZz2UtUWHbg8qLNkFBB" +
		"3PKOr7cLBHQFaO3tB8JMdN8zUGzMNMxT9wT3T1vL5TaYk7KtZfANPEtwED1K9z5FqD7U" +
		"meVfnDE8RqjRHFnJFAAKgVJMur4ggZTa"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordTXTLong("rec-txt-long.example.com", longValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.dkim", "value", longValue),
				),
			},
			{
				Config: testAccRecordTXTLong("rec-txt-long.example.com", longValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.dkim", "value", longValue),
				),
			},
		},
	})
}

func testAccRecordTXTLong(zone, value string) string {
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

resource "technitium_record" "dkim" {
  zone      = technitium_zone.test.name
  name      = "dkim._domainkey.%s"
  type      = "TXT"
  value     = %q
  overwrite = false
}
`, testAccAPIToken(), zone, zone, value)
}

// --- Lifecycle Edge Case Tests ---

func TestAccRecordResource_DestroyOneOfTwo(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiA("rec-destroy-one.example.com", "rr.rec-destroy-one.example.com", "10.20.99.1", "10.20.99.2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
					resource.TestCheckResourceAttr("technitium_record.a2", "value", "10.20.99.2"),
				),
			},
			{
				Config: testAccRecordSingleFromMultiA("rec-destroy-one.example.com", "rr.rec-destroy-one.example.com", "10.20.99.1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
				),
			},
		},
	})
}

func testAccRecordSingleFromMultiA(zone, name, ip string) string {
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

resource "technitium_record" "a1" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "A"
  value     = %q
  overwrite = false
}
`, testAccAPIToken(), zone, name, ip)
}

func TestAccRecordResource_ImportWithSiblings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordMultiA("rec-import-sib.example.com", "rr.rec-import-sib.example.com", "10.20.99.1", "10.20.99.2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.a1", "value", "10.20.99.1"),
					resource.TestCheckResourceAttr("technitium_record.a2", "value", "10.20.99.2"),
				),
			},
			{
				ResourceName:            "technitium_record.a2",
				ImportState:             true,
				ImportStateId:           "rec-import-sib.example.com::rr.rec-import-sib.example.com::A::10.20.99.2",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"overwrite"},
			},
		},
	})
}
