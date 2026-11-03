// Copyright (c) 2026 Max Pfeiffer
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// testAccCheckUpdateSecurityPolicies compares the policies stored on the
// server, in the order the server reports them, with want.
func testAccCheckUpdateSecurityPolicies(t *testing.T, zone string, want []client.UpdateSecurityPolicy) resource.TestCheckFunc {
	return func(*terraform.State) error {
		z, err := testAccDirectClient(t).ZoneOptionsGet(context.Background(), zone)
		if err != nil {
			return err
		}
		got := z.UpdateSecurityPolicies
		if len(got) == 0 && len(want) == 0 {
			return nil
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("server updateSecurityPolicies = %+v, want %+v", got, want)
		}
		return nil
	}
}

func testAccSetUpdateSecurityPoliciesOutOfBand(t *testing.T, zone string, policies []client.UpdateSecurityPolicy) {
	err := testAccDirectClient(t).ZoneOptionsSet(context.Background(), zone, map[string]string{
		"updateSecurityPolicies": client.FormatUpdateSecurityPolicies(policies),
	})
	if err != nil {
		t.Fatalf("out-of-band update security policies: %v", err)
	}
}

// testAccZoneUpdatePoliciesConfig creates two TSIG keys and a zone with the
// given dynamic_update_security_policies expression.
func testAccZoneUpdatePoliciesConfig(zone, zoneType, policies string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "a" {
  key_name  = "acc-update-a.%[1]s"
  algorithm = "hmac-sha256"
}

# TSIG keys are stored as one server setting that every key resource reads,
# modifies and writes back, so keys created in parallel overwrite each other.
resource "technitium_tsig_key" "b" {
  key_name  = "acc-update-b.%[1]s"
  algorithm = "hmac-sha256"

  depends_on = [technitium_tsig_key.a]
}

resource "technitium_zone" "policies" {
  name                       = %[1]q
  type                       = %[2]q
  dynamic_update             = "UseSpecifiedNetworkACL"
  dynamic_update_network_acl = ["192.0.2.0/24"]

  dynamic_update_security_policies = %[3]s
}
`, zone, zoneType, policies)
}

func TestAccZoneResource_DynamicUpdateSecurityPolicies(t *testing.T) {
	const zone = "acc-update-policies.example.com"
	keyA := "acc-update-a." + zone
	keyB := "acc-update-b." + zone

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with two policies.
			{
				Config: testAccZoneUpdatePoliciesConfig(zone, "Primary", `[
    {
      tsig_key_name = technitium_tsig_key.a.key_name
      domain        = "*.`+zone+`"
      allowed_types = ["TXT"]
    },
    {
      tsig_key_name = technitium_tsig_key.b.key_name
      domain        = "`+zone+`"
      allowed_types = ["A", "AAAA"]
    },
  ]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.policies", "dynamic_update_security_policies.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("technitium_zone.policies", "dynamic_update_security_policies.*",
						map[string]string{"tsig_key_name": keyA, "domain": "*." + zone, "allowed_types.#": "1"}),
					resource.TestCheckTypeSetElemNestedAttrs("technitium_zone.policies", "dynamic_update_security_policies.*",
						map[string]string{"tsig_key_name": keyB, "domain": zone, "allowed_types.#": "2"}),
					testAccCheckUpdateSecurityPolicies(t, zone, []client.UpdateSecurityPolicy{
						{TsigKeyName: keyA, Domain: "*." + zone, AllowedTypes: []string{"TXT"}},
						{TsigKeyName: keyB, Domain: zone, AllowedTypes: []string{"A", "AAAA"}},
					}),
				),
			},
			// Update: change the allowed types and remove a policy.
			{
				Config: testAccZoneUpdatePoliciesConfig(zone, "Primary", `[
    {
      tsig_key_name = technitium_tsig_key.a.key_name
      domain        = "*.`+zone+`"
      allowed_types = ["TXT", "CNAME"]
    },
  ]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.policies", "dynamic_update_security_policies.#", "1"),
					resource.TestCheckTypeSetElemAttr("technitium_zone.policies",
						"dynamic_update_security_policies.0.allowed_types.*", "CNAME"),
					testAccCheckUpdateSecurityPolicies(t, zone, []client.UpdateSecurityPolicy{
						{TsigKeyName: keyA, Domain: "*." + zone, AllowedTypes: []string{"CNAME", "TXT"}},
					}),
				),
			},
			// A change made outside Terraform shows as drift and is reverted.
			{
				PreConfig: func() {
					testAccSetUpdateSecurityPoliciesOutOfBand(t, zone, []client.UpdateSecurityPolicy{
						{TsigKeyName: keyB, Domain: zone, AllowedTypes: []string{"ANY"}},
					})
				},
				Config: testAccZoneUpdatePoliciesConfig(zone, "Primary", `[
    {
      tsig_key_name = technitium_tsig_key.a.key_name
      domain        = "*.`+zone+`"
      allowed_types = ["TXT", "CNAME"]
    },
  ]`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("technitium_zone.policies", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckUpdateSecurityPolicies(t, zone, []client.UpdateSecurityPolicy{
					{TsigKeyName: keyA, Domain: "*." + zone, AllowedTypes: []string{"CNAME", "TXT"}},
				}),
			},
			// An empty set removes all policies.
			{
				Config: testAccZoneUpdatePoliciesConfig(zone, "Primary", `[]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.policies", "dynamic_update_security_policies.#", "0"),
					testAccCheckUpdateSecurityPolicies(t, zone, nil),
				),
			},
			// Import leaves the dynamic update options unmanaged, as before.
			{
				ResourceName:      "technitium_zone.policies",
				ImportState:       true,
				ImportStateId:     zone,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"dynamic_update",
					"dynamic_update_network_acl",
					"dynamic_update_security_policies",
				},
			},
		},
	})
}

func TestAccZoneResource_DynamicUpdateSecurityPolicies_Forwarder(t *testing.T) {
	const zone = "acc-update-policies-fwd.example.com"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneUpdatePoliciesConfig(zone, "Forwarder", `[
    {
      tsig_key_name = technitium_tsig_key.a.key_name
      domain        = "*.`+zone+`"
      allowed_types = ["TXT"]
    },
  ]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.policies", "dynamic_update_security_policies.#", "1"),
					testAccCheckUpdateSecurityPolicies(t, zone, []client.UpdateSecurityPolicy{
						{TsigKeyName: "acc-update-a." + zone, Domain: "*." + zone, AllowedTypes: []string{"TXT"}},
					}),
				),
			},
		},
	})
}

func TestAccZoneResource_DynamicUpdateSecurityPolicies_Rejected(t *testing.T) {
	const zone = "acc-update-policies-bad.example.com"
	tests := []struct {
		name     string
		zoneType string
		policies string
		err      *regexp.Regexp
	}{
		{
			name:     "zone type",
			zoneType: "Stub",
			policies: `[{ tsig_key_name = "acme", domain = "` + zone + `", allowed_types = ["TXT"] }]`,
			err:      regexp.MustCompile(`Invalid zone type for dynamic_update_security_policies`),
		},
		{
			name:     "duplicate key and domain",
			zoneType: "Primary",
			policies: `[
    { tsig_key_name = "acme", domain = "` + zone + `", allowed_types = ["TXT"] },
    { tsig_key_name = "acme", domain = "` + zone + `", allowed_types = ["A"] },
  ]`,
			err: regexp.MustCompile(`Duplicate dynamic update security policy`),
		},
		{
			name:     "uppercase domain",
			zoneType: "Primary",
			policies: `[{ tsig_key_name = "acme", domain = "WWW.` + zone + `", allowed_types = ["TXT"] }]`,
			err:      regexp.MustCompile(`must be a lowercase domain name`),
		},
		{
			name:     "lowercase type",
			zoneType: "Primary",
			policies: `[{ tsig_key_name = "acme", domain = "` + zone + `", allowed_types = ["txt"] }]`,
			err:      regexp.MustCompile(`must be an uppercase record type`),
		},
		{
			name:     "no types",
			zoneType: "Primary",
			policies: `[{ tsig_key_name = "acme", domain = "` + zone + `", allowed_types = [] }]`,
			err:      regexp.MustCompile(`at least 1`),
		},
		{
			name:     "missing TSIG key",
			zoneType: "Primary",
			policies: `[{ tsig_key_name = "nonexistent-key", domain = "` + zone + `", allowed_types = ["TXT"] }]`,
			err:      regexp.MustCompile(`TSIG key "nonexistent-key" not found`),
		},
		{
			name:     "domain outside the zone",
			zoneType: "Primary",
			policies: `[{ tsig_key_name = technitium_tsig_key.a.key_name, domain = "other.example.com", allowed_types = ["TXT"] }]`,
			err:      regexp.MustCompile(`must be part of the current zone`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      testAccZoneUpdatePoliciesConfig(zone, tt.zoneType, tt.policies),
						ExpectError: tt.err,
					},
				},
			})
		})
	}
}
