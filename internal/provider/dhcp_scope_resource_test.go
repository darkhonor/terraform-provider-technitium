// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccDHCPScopeResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccDHCPScopeBasic("acc-scope-basic"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "id", "acc-scope-basic"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-basic"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "starting_address", "10.42.0.50"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "ending_address", "10.42.0.250"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "subnet_mask", "255.255.255.0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "enabled", "false"),
					// A minimal create omits the optional parameters, so the
					// server's own defaults must land in the computed attrs.
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_days", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_hours", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_minutes", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "dns_ttl", "900"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "ping_check_timeout", "1000"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "ping_check_retries", "2"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_dhcp_scope.test",
				ImportState:       true,
				ImportStateId:     "acc-scope-basic",
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDHCPScopeResource_fullOptions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeFull("acc-scope-full"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_name", "lab.example"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_search_list.#", "2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "domain_search_list.0", "lab.example"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "router_address", "10.43.0.1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "dns_servers.#", "2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "ntp_servers.0", "10.43.0.5"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "lease_time_days", "3"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.0.destination", "172.16.0.0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "static_routes.0.router", "10.43.0.2"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.0.starting_address", "10.43.0.50"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.0.hardware_address", "00-11-22-33-44-55"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.0.address", "10.43.0.100"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "generic_options.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "generic_options.0.code", "150"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "allow_only_reserved_leases", "true"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "ping_check_enabled", "true"),
				),
			},
			// Update: drop reservations/exclusions, change lease time and lists
			{
				Config: testAccDHCPScopeFullUpdated("acc-scope-full"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "lease_time_days", "7"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "dns_servers.#", "1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "exclusions.#", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "reserved_leases.#", "0"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.full", "allow_only_reserved_leases", "false"),
				),
			},
		},
	})
}

func TestAccDHCPScopeResource_rename(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeBasicNamed("acc-scope-rename-a", "10.44.0.50", "10.44.0.250"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-rename-a"),
				),
			},
			// Rename in place — same range, new name; must NOT destroy/recreate
			{
				Config: testAccDHCPScopeBasicNamed("acc-scope-rename-b", "10.44.0.50", "10.44.0.250"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "name", "acc-scope-rename-b"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "id", "acc-scope-rename-b"),
				),
			},
		},
	})
}

// Regression test: a scope update must not wipe standalone
// technitium_dhcp_reserved_lease reservations on that scope. Before the fix,
// DHCPScopeSet always sent reservedLeases (empty when the scope declared no
// inline reserved_leases) and the server treats it as the full replacement
// list, so the second step's scope update deleted the reservation server-side.
// The framework's post-apply empty-plan check then fails the step: the
// reserved lease's refresh finds it gone and plans a re-create.
func TestAccDHCPScopeResource_updatePreservesStandaloneLease(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeWithStandaloneLease("acc-scope-coexist", 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_days", "3"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.standalone", "ip_address", "10.48.0.100"),
				),
			},
			// Scope-only change; the standalone reservation must survive.
			{
				Config: testAccDHCPScopeWithStandaloneLease("acc-scope-coexist", 7),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_days", "7"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.standalone", "ip_address", "10.48.0.100"),
				),
			},
		},
	})
}

// A scope whose state was populated by the server (import, or an earlier
// apply) must not lose configuration the config file does not mention: an
// update from a minimal config may not reset router_address, domain_name, or
// lease times to zero values.
func TestAccDHCPScopeResource_minimalUpdatePreservesServerConfig(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeWithRouterAndDomain("acc-scope-minimal"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "router_address", "10.45.0.1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "domain_name", "minimal.example"),
				),
			},
			// Import with only required attributes declared in config.
			{
				ResourceName:      "technitium_dhcp_scope.test",
				ImportState:       true,
				ImportStateId:     "acc-scope-minimal",
				ImportStateVerify: true,
			},
			// Update from a config that declares only required attributes plus
			// the changed one: everything else must survive on the server.
			{
				Config: testAccDHCPScopeMinimalLeaseHours("acc-scope-minimal", 12),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "lease_time_hours", "12"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "router_address", "10.45.0.1"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "domain_name", "minimal.example"),
					testAccCheckScopeOnServer("acc-scope-minimal", func(scope *client.DHCPScope) error {
						if got := stringDeref(scope.RouterAddress); got != "10.45.0.1" {
							return fmt.Errorf("routerAddress erased by minimal update: got %q", got)
						}
						if got := stringDeref(scope.DomainName); got != "minimal.example" {
							return fmt.Errorf("domainName erased by minimal update: got %q", got)
						}
						return nil
					}),
				),
			},
		},
	})
}

// Removing the reserved_leases attribute from config (not just emptying it)
// must clear the server-side reservation list, not silently keep it.
func TestAccDHCPScopeResource_removeInlineReservedLeases(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeInlineLeases("acc-scope-rm-leases"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "reserved_leases.#", "1"),
					testAccCheckScopeOnServer("acc-scope-rm-leases", func(scope *client.DHCPScope) error {
						if len(scope.ReservedLeases) != 1 {
							return fmt.Errorf("got %d reserved leases server-side, want 1", len(scope.ReservedLeases))
						}
						return nil
					}),
				),
			},
			{
				Config: testAccDHCPScopeBasicNamed("acc-scope-rm-leases", "10.47.0.50", "10.47.0.250"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("technitium_dhcp_scope.test", "reserved_leases.#"),
					testAccCheckScopeOnServer("acc-scope-rm-leases", func(scope *client.DHCPScope) error {
						if len(scope.ReservedLeases) != 0 {
							return fmt.Errorf("got %d reserved leases server-side after removal, want 0", len(scope.ReservedLeases))
						}
						return nil
					}),
				),
			},
		},
	})
}

// Lowercase, colon-separated MACs and lowercase hex values are valid input;
// the server normalizes them, and the read-back must not flag the difference
// as drift or an inconsistent apply.
func TestAccDHCPScopeResource_lowercaseMACAndHexFormats(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPScopeLowercaseFormats("acc-scope-fmt"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "reserved_leases.0.hardware_address", "aa:bb:cc:dd:ee:46"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "vendor_info.0.information", "0a:2b:00:05"),
					resource.TestCheckResourceAttr("technitium_dhcp_scope.test", "generic_options.0.value", "0a:2b:00:05"),
				),
			},
		},
	})
}

func TestAccDHCPReservedLeaseResource_lowercaseMAC(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDHCPReservedLeaseLowercaseMAC("acc-scope-fmt-lease"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.fmt", "hardware_address", "aa:bb:cc:dd:ee:47"),
					resource.TestCheckResourceAttr("technitium_dhcp_reserved_lease.fmt", "ip_address", "10.49.0.101"),
				),
			},
		},
	})
}

// scopes/set is create-or-update on the server: Create must refuse to adopt
// an existing scope rather than silently overwrite its configuration.
func TestAccDHCPScopeResource_createExisting_Rejected(t *testing.T) {
	skipUnlessAcceptance(t)
	c, err := client.NewClient(acceptanceClientConfig())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()
	const name = "acc-scope-preexisting"
	if err := c.DHCPScopeSet(ctx, client.DHCPScope{
		Name:            name,
		StartingAddress: "10.52.0.50",
		EndingAddress:   "10.52.0.250",
		SubnetMask:      "255.255.255.0",
	}, ""); err != nil {
		t.Fatalf("pre-creating scope: %v", err)
	}
	t.Cleanup(func() { _ = c.DHCPScopeDelete(ctx, name) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccDHCPScopeBasicNamed(name, "10.52.0.50", "10.52.0.250"),
				ExpectError: regexp.MustCompile(`already exists`),
			},
		},
	})
}

// testAccCheckScopeOnServer fetches the named scope directly from the API,
// bypassing Terraform state, and runs check against it.
func testAccCheckScopeOnServer(name string, check func(*client.DHCPScope) error) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		c, err := client.NewClient(acceptanceClientConfig())
		if err != nil {
			return err
		}
		scope, err := c.DHCPScopeGet(context.Background(), name)
		if err != nil {
			return err
		}
		return check(scope)
	}
}

// stringDeref unwraps the client's optional string fields for assertions.
func stringDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func testAccDHCPScopeBasic(name string) string {
	return testAccDHCPScopeBasicNamed(name, "10.42.0.50", "10.42.0.250")
}

func testAccDHCPScopeBasicNamed(name, start, end string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = %q
  ending_address   = %q
  subnet_mask      = "255.255.255.0"
}
`, name, start, end)
}

func testAccDHCPScopeWithRouterAndDomain(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = "10.45.0.50"
  ending_address   = "10.45.0.250"
  subnet_mask      = "255.255.255.0"

  router_address = "10.45.0.1"
  domain_name    = "minimal.example"
}
`, name)
}

func testAccDHCPScopeMinimalLeaseHours(name string, leaseTimeHours int) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = "10.45.0.50"
  ending_address   = "10.45.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_hours = %d
}
`, name, leaseTimeHours)
}

func testAccDHCPScopeInlineLeases(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = "10.47.0.50"
  ending_address   = "10.47.0.250"
  subnet_mask      = "255.255.255.0"

  reserved_leases = [
    {
      hardware_address = "00-11-22-33-44-47"
      address          = "10.47.0.100"
    }
  ]
}
`, name)
}

func testAccDHCPScopeLowercaseFormats(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = "10.46.0.50"
  ending_address   = "10.46.0.250"
  subnet_mask      = "255.255.255.0"

  reserved_leases = [
    {
      hardware_address = "aa:bb:cc:dd:ee:46"
      address          = "10.46.0.100"
    }
  ]

  vendor_info = [
    {
      identifier  = "test-vendor"
      information = "0a:2b:00:05"
    }
  ]

  generic_options = [
    {
      code  = 150
      value = "0a:2b:00:05"
    }
  ]
}
`, name)
}

func testAccDHCPReservedLeaseLowercaseMAC(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "fmt" {
  name             = %q
  starting_address = "10.49.0.50"
  ending_address   = "10.49.0.250"
  subnet_mask      = "255.255.255.0"
}

resource "technitium_dhcp_reserved_lease" "fmt" {
  scope            = technitium_dhcp_scope.fmt.name
  hardware_address = "aa:bb:cc:dd:ee:47"
  ip_address       = "10.49.0.101"
}
`, name)
}

func testAccDHCPScopeWithStandaloneLease(name string, leaseTimeDays int) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "test" {
  name             = %q
  starting_address = "10.48.0.50"
  ending_address   = "10.48.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_days = %d
}

resource "technitium_dhcp_reserved_lease" "standalone" {
  scope            = technitium_dhcp_scope.test.name
  hardware_address = "00-AA-BB-CC-DD-48"
  ip_address       = "10.48.0.100"
  host_name        = "coexist"
}
`, name, leaseTimeDays)
}

func testAccDHCPScopeFull(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "full" {
  name             = %q
  starting_address = "10.43.0.50"
  ending_address   = "10.43.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_days    = 3
  ping_check_enabled = true

  domain_name        = "lab.example"
  domain_search_list = ["lab.example", "corp.example"]
  dns_updates        = true
  dns_ttl            = 600

  router_address = "10.43.0.1"
  dns_servers    = ["10.43.0.5", "10.43.0.6"]
  ntp_servers    = ["10.43.0.5"]

  static_routes = [
    {
      destination = "172.16.0.0"
      subnet_mask = "255.255.255.0"
      router      = "10.43.0.2"
    }
  ]

  exclusions = [
    {
      starting_address = "10.43.0.50"
      ending_address   = "10.43.0.60"
    }
  ]

  reserved_leases = [
    {
      host_name        = "printer"
      hardware_address = "00-11-22-33-44-55"
      address          = "10.43.0.100"
      comments         = "acc test reservation"
    }
  ]

  generic_options = [
    {
      code  = 150
      value = "0A:2B:00:05"
    }
  ]

  allow_only_reserved_leases = true
}
`, name)
}

func testAccDHCPScopeFullUpdated(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_dhcp_scope" "full" {
  name             = %q
  starting_address = "10.43.0.50"
  ending_address   = "10.43.0.250"
  subnet_mask      = "255.255.255.0"

  lease_time_days = 7

  domain_name        = "lab.example"
  domain_search_list = ["lab.example", "corp.example"]
  dns_updates        = true
  dns_ttl            = 600

  router_address = "10.43.0.1"
  dns_servers    = ["10.43.0.5"]
  ntp_servers    = ["10.43.0.5"]

  static_routes = [
    {
      destination = "172.16.0.0"
      subnet_mask = "255.255.255.0"
      router      = "10.43.0.2"
    }
  ]

  exclusions      = []
  reserved_leases = []

  allow_only_reserved_leases = false
}
`, name)
}
