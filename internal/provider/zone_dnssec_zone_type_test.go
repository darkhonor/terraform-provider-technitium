// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// modifyPlanForZone runs ModifyPlan over a create plan (null prior state) for
// a zone of the given type, with or without a dnssec block.
func modifyPlanForZone(t *testing.T, zoneType types.String, dnssec *DNSSECModel) *resource.ModifyPlanResponse {
	t.Helper()
	ctx := context.Background()

	r := &ZoneResource{}
	schemaResp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	model := &ZoneResourceModel{
		Name:   types.StringValue("acc-zone-type.example.com"),
		Type:   zoneType,
		DNSSEC: dnssec,
		// Collection attributes need an explicit element type; a zero-value
		// types.List carries no element type and fails plan.Set.
		Notify:                   types.ListNull(types.StringType),
		AllowTransfer:            types.ListNull(types.StringType),
		ZoneTransferTsigKeyNames: types.ListNull(types.StringType),
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, model); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}
	config := tfsdk.Config{Schema: schemaResp.Schema, Raw: plan.Raw}

	resp := &resource.ModifyPlanResponse{Plan: tfsdk.Plan{Schema: schemaResp.Schema, Raw: plan.Raw}}
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{
		Plan:   plan,
		Config: config,
		State:  tfsdk.State{Schema: schemaResp.Schema}, // null: create
	}, resp)
	return resp
}

func signedDNSSEC() *DNSSECModel {
	return &DNSSECModel{
		Enabled:              types.BoolValue(true),
		Algorithm:            types.StringValue("ECDSA"),
		Curve:                types.StringValue("P384"),
		NxProof:              types.StringValue("NSEC3"),
		ChangeAcknowledgment: types.StringNull(),
	}
}

// Technitium signs Primary zones only. /api/zones/dnssec/sign answers
// "No such primary zone was found" for every other type, so a dnssec block on
// a non-Primary zone declares an intent the provider can never fulfil: the
// zone is never signed, refresh reports enabled=false, and the apply dies with
// "Provider produced inconsistent result after apply" (#100).
func TestZoneModifyPlan_DNSSECRejectedOnNonPrimaryZoneTypes(t *testing.T) {
	for _, zoneType := range []string{
		"Secondary",
		"Stub",
		"Forwarder",
		"Catalog",
		"SecondaryForwarder",
		"SecondaryCatalog",
	} {
		t.Run(zoneType, func(t *testing.T) {
			resp := modifyPlanForZone(t, types.StringValue(zoneType), signedDNSSEC())

			if !resp.Diagnostics.HasError() {
				t.Fatalf("a dnssec block on a %s zone must be refused at plan time; the zone can never be signed", zoneType)
			}

			var found bool
			for _, d := range resp.Diagnostics.Errors() {
				if d.Summary() == "Invalid zone type for dnssec" {
					found = true
					if !strings.Contains(d.Detail(), zoneType) {
						t.Errorf("diagnostic should name the offending zone type %q, got: %s", zoneType, d.Detail())
					}
					if !strings.Contains(d.Detail(), "Primary") {
						t.Errorf("diagnostic should name Primary as the valid type, got: %s", d.Detail())
					}
				}
			}
			if !found {
				t.Fatalf("expected an \"Invalid zone type for dnssec\" diagnostic, got: %v", resp.Diagnostics)
			}
		})
	}
}

// A dnssec block on a Primary zone is the supported case and must survive.
func TestZoneModifyPlan_DNSSECAllowedOnPrimary(t *testing.T) {
	resp := modifyPlanForZone(t, types.StringValue("Primary"), signedDNSSEC())

	for _, d := range resp.Diagnostics.Errors() {
		if d.Summary() == "Invalid zone type for dnssec" {
			t.Fatalf("dnssec on a Primary zone must not be refused, got: %s", d.Detail())
		}
	}
}

// Zones with no dnssec block are unaffected whatever their type.
func TestZoneModifyPlan_NoDNSSECBlockIsAlwaysFine(t *testing.T) {
	for _, zoneType := range []string{"Primary", "Secondary", "Stub", "Forwarder"} {
		t.Run(zoneType, func(t *testing.T) {
			resp := modifyPlanForZone(t, types.StringValue(zoneType), nil)

			for _, d := range resp.Diagnostics.Errors() {
				if d.Summary() == "Invalid zone type for dnssec" {
					t.Fatalf("a %s zone with no dnssec block must not be refused, got: %s", zoneType, d.Detail())
				}
			}
		})
	}
}

// type is Required but can be wired from another resource, so it may be
// unknown at plan time. Refusing on an unknown type would reject valid
// configurations that resolve to Primary at apply.
func TestZoneModifyPlan_DNSSECNotRejectedWhenZoneTypeUnknown(t *testing.T) {
	resp := modifyPlanForZone(t, types.StringUnknown(), signedDNSSEC())

	for _, d := range resp.Diagnostics.Errors() {
		if d.Summary() == "Invalid zone type for dnssec" {
			t.Fatalf("an unknown zone type must not be refused at plan time, got: %s", d.Detail())
		}
	}
}
