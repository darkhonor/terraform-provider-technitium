// Copyright (c) 2026 Dustin Sweigart
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// A rename that lands on the server must be persisted even when a follow-up
// call fails: state keeping the old name points at a scope that no longer
// exists, and the next refresh silently drops the resource.
func TestDHCPScopeUpdate_RenamePersistsNameOnLateFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/dhcp/scopes/set":
			if got := req.FormValue("newName"); got != "lan-new" {
				t.Errorf("newName = %q, want %q", got, "lan-new")
			}
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/dhcp/scopes/list":
			// reconcileEnabled's lookup fails after the rename landed.
			_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"temporary failure"}`)
		default:
			t.Errorf("unexpected request path: %s", req.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &DHCPScopeResource{client: c}

	ctx := context.Background()
	schemaResp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	nullList := types.ListNull(types.StringType)
	model := func(name string) *DHCPScopeResourceModel {
		return &DHCPScopeResourceModel{
			ID:                   types.StringValue(name),
			Name:                 types.StringValue(name),
			Enabled:              types.BoolValue(false),
			StartingAddress:      types.StringValue("10.0.0.50"),
			EndingAddress:        types.StringValue("10.0.0.250"),
			SubnetMask:           types.StringValue("255.255.255.0"),
			DomainSearchList:     nullList,
			DNSServers:           nullList,
			WINSServers:          nullList,
			NTPServers:           nullList,
			NTPServerDomainNames: nullList,
			CAPWAPAcIPAddresses:  nullList,
			TFTPServerAddresses:  nullList,
		}
	}

	tfPlan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := tfPlan.Set(ctx, model("lan-new")); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}
	tfState := tfsdk.State{Schema: schemaResp.Schema}
	if diags := tfState.Set(ctx, model("lan-old")); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	req := resource.UpdateRequest{Plan: tfPlan, State: tfState}
	// The framework seeds the response state with prior state and requires
	// explicit provider writes; mirror that here.
	resp := &resource.UpdateResponse{State: tfState}
	r.Update(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic from the failing follow-up call")
	}

	var saved DHCPScopeResourceModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if saved.Name.ValueString() != "lan-new" {
		t.Fatalf("persisted name = %q, want %q: the rename landed and state must track it", saved.Name.ValueString(), "lan-new")
	}
	if saved.ID.ValueString() != "lan-new" {
		t.Fatalf("persisted id = %q, want %q", saved.ID.ValueString(), "lan-new")
	}
}
