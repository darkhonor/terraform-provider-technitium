// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServerSettingsResource_STIGDefaults(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Apply STIG-hardened defaults
			{
				Config: testAccServerSettingsSTIG(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_server_settings.main", "id", "server-settings"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "dnssec_validation", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "recursion", "AllowOnlyForPrivateNetworks"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "qname_minimization", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "log_queries", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "logging_type", "FileAndConsole"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "max_log_file_days", "365"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarder_protocol", "Tls"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "enable_blocking", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "serve_stale", "true"),
					resource.TestCheckResourceAttrSet("technitium_server_settings.main", "version"),
				),
			},
			// Update a few settings
			{
				Config: testAccServerSettingsCustom(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_server_settings.main", "randomize_name", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "forwarder_protocol", "Https"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "udp_payload_size", "1400"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_server_settings.main",
				ImportState:       true,
				ImportStateId:     "server-settings",
				ImportStateVerify: true,
				// forwarder_protocol is only persisted by API when forwarders are configured
				ImportStateVerifyIgnore: []string{"forwarder_protocol"},
			},
		},
	})
}

func TestAccServerSettingsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccServerSettingsDataSource(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.technitium_server_settings.current", "version"),
					resource.TestCheckResourceAttr("data.technitium_server_settings.current", "dnssec_validation", "true"),
				),
			},
		},
	})
}

func testAccServerSettingsSTIG() string {
	return testAccProviderHCL() + `
resource "technitium_server_settings" "main" {
  dnssec_validation  = true
  recursion          = "AllowOnlyForPrivateNetworks"
  qname_minimization = true
  randomize_name     = true
  log_queries        = true
  logging_type       = "FileAndConsole"
  max_log_file_days  = 365
  enable_blocking    = true
  serve_stale        = true
  forwarder_protocol = "Tls"
}
`
}

func testAccServerSettingsCustom() string {
	return testAccProviderHCL() + `
resource "technitium_server_settings" "main" {
  dnssec_validation  = true
  recursion          = "AllowOnlyForPrivateNetworks"
  qname_minimization = true
  randomize_name     = true
  log_queries        = true
  logging_type       = "FileAndConsole"
  max_log_file_days  = 365
  enable_blocking    = true
  serve_stale        = true
  forwarder_protocol = "Https"
  udp_payload_size   = 1400
}
`
}

func testAccServerSettingsDataSource() string {
	return testAccProviderHCL() + `
data "technitium_server_settings" "current" {}
`
}

func TestAccServerSettingsResource_BlockingConfig(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccServerSettingsBlocking(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_server_settings.main", "enable_blocking", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "allow_txt_blocking_report", "true"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "blocking_type", "NxDomain"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "blocking_answer_ttl", "30"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "block_list_update_interval_hours", "24"),
				),
			},
			{
				Config: testAccServerSettingsBlockingUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_server_settings.main", "blocking_type", "CustomAddress"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "blocking_answer_ttl", "60"),
					resource.TestCheckResourceAttr("technitium_server_settings.main", "custom_blocking_addresses.#", "2"),
				),
			},
		},
	})
}

func TestAccServerSettingsResource_BlockingTypeValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccServerSettingsBlockingInvalidType(),
				ExpectError: regexp.MustCompile(`(?i)blocking_type|value must be one of`),
			},
		},
	})
}

func testAccServerSettingsBlocking() string {
	return testAccProviderHCL() + `resource "technitium_server_settings" "main" {
  enable_blocking              = true
  allow_txt_blocking_report    = true
  blocking_type                = "NxDomain"
  blocking_answer_ttl          = 30
  block_list_update_interval_hours = 24
}
`
}

func testAccServerSettingsBlockingUpdate() string {
	return testAccProviderHCL() + `resource "technitium_server_settings" "main" {
  enable_blocking              = true
  allow_txt_blocking_report    = true
  blocking_type                = "CustomAddress"
  blocking_answer_ttl          = 60
  custom_blocking_addresses    = ["0.0.0.0", "::"]
  block_list_update_interval_hours = 24
}
`
}

func testAccServerSettingsBlockingInvalidType() string {
	return testAccProviderHCL() + `resource "technitium_server_settings" "main" {
  blocking_type = "InvalidValue"
}
`
}
