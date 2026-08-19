// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// newImportState builds an empty state backed by the record resource's real
// schema, so ImportState can be exercised without a live provider server.
func newImportState(t *testing.T, ctx context.Context) tfsdk.State {
	t.Helper()
	r := &RecordResource{}
	schemaResp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("schema error: %v", schemaResp.Diagnostics)
	}
	return tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil),
	}
}

// TestImportState_FWD covers the regression that made this worth testing at the
// state level rather than only at the parser: ImportState used to read the
// parser's shared string slot under the name caaTag and write it straight into
// the protocol attribute. It happened to work because FWD and CAA shared that
// slot, and nothing asserted the resulting state.
func TestImportState_FWD(t *testing.T) {
	ctx := context.Background()
	r := &RecordResource{}

	tests := []struct {
		name         string
		importID     string
		wantValue    string
		wantProtocol string
		wantPriority int64
		// wantDNSSEC nil means the attribute must be left null, which is what a
		// legacy 3-field import ID has to produce.
		wantDNSSEC *bool
	}{
		{
			name:         "4-field with dnssec true",
			importID:     ".::.::FWD::1.1.1.1:Udp:2:true",
			wantValue:    "1.1.1.1",
			wantProtocol: "Udp",
			wantPriority: 2,
			wantDNSSEC:   boolPtrForTest(true),
		},
		{
			name:         "4-field with dnssec false",
			importID:     ".::.::FWD::1.1.1.1:Udp:2:false",
			wantValue:    "1.1.1.1",
			wantProtocol: "Udp",
			wantPriority: 2,
			wantDNSSEC:   boolPtrForTest(false),
		},
		{
			name:         "legacy 3-field leaves dnssec_validation null",
			importID:     ".::.::FWD::1.1.1.1:Udp:2",
			wantValue:    "1.1.1.1",
			wantProtocol: "Udp",
			wantPriority: 2,
			wantDNSSEC:   nil,
		},
		{
			name:         "DoH forwarder containing colons",
			importID:     ".::.::FWD::https://cloudflare-dns.com/dns-query:Https:1:true",
			wantValue:    "https://cloudflare-dns.com/dns-query",
			wantProtocol: "Https",
			wantPriority: 1,
			wantDNSSEC:   boolPtrForTest(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := resource.ImportStateResponse{State: newImportState(t, ctx)}
			r.ImportState(ctx, resource.ImportStateRequest{ID: tc.importID}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("ImportState returned errors: %v", resp.Diagnostics)
			}

			var got RecordResourceModel
			if diags := resp.State.Get(ctx, &got); diags.HasError() {
				t.Fatalf("reading state: %v", diags)
			}

			if got.Type.ValueString() != "FWD" {
				t.Errorf("type = %q, want FWD", got.Type.ValueString())
			}
			if got.Value.ValueString() != tc.wantValue {
				t.Errorf("value = %q, want %q", got.Value.ValueString(), tc.wantValue)
			}
			if got.Protocol.ValueString() != tc.wantProtocol {
				t.Errorf("protocol = %q, want %q", got.Protocol.ValueString(), tc.wantProtocol)
			}
			if got.ForwarderPriority.ValueInt64() != tc.wantPriority {
				t.Errorf("forwarder_priority = %d, want %d", got.ForwarderPriority.ValueInt64(), tc.wantPriority)
			}

			if tc.wantDNSSEC == nil {
				if !got.DNSSECValidation.IsNull() {
					t.Errorf("dnssec_validation = %v, want null — a legacy import ID must not "+
						"fabricate a value, or the next plan shows spurious drift",
						got.DNSSECValidation.ValueBool())
				}
				return
			}
			if got.DNSSECValidation.IsNull() {
				t.Fatalf("dnssec_validation is null, want %v", *tc.wantDNSSEC)
			}
			if got.DNSSECValidation.ValueBool() != *tc.wantDNSSEC {
				t.Errorf("dnssec_validation = %v, want %v",
					got.DNSSECValidation.ValueBool(), *tc.wantDNSSEC)
			}
		})
	}
}

func boolPtrForTest(b bool) *bool { return &b }
