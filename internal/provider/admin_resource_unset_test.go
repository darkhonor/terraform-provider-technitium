// Copyright (c) 2026 Ujstor
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The /api/admin/sso/set and /api/admin/users/set endpoints retain the stored
// value for every omitted parameter, so removing an optional attribute from
// configuration must send an explicit empty value or the server keeps the old
// one and the post-apply read fails with "inconsistent result after apply".
// These tests pin that unset round-trip.

// Removing authority, scopes, and group_map from configuration must clear them
// on the server, while attributes that stay configured are sent unchanged and
// attributes null in both plan and state remain omitted.
func TestSSOUpdate_ClearsAttributesRemovedFromConfig(t *testing.T) {
	var mu sync.Mutex
	sent := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sso/set", func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		mu.Lock()
		for k := range req.PostForm {
			sent[k] = req.PostForm.Get(k)
		}
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
	})
	// The read after apply sees the clears already applied: authority and the
	// group map empty, scopes reset to the server default (clearing ssoScopes
	// does not empty the list — the server falls back to its default).
	mux.HandleFunc("/api/admin/sso/get", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"ssoEnabled":true,
			"ssoAuthority":null,
			"ssoClientId":"technitium-dns",
			"ssoClientSecret":"************",
			"ssoMetadataAddress":null,
			"ssoScopes":["openid","profile","email"],
			"ssoAllowSignup":false,
			"ssoAllowSignupOnlyForMappedUsers":true,
			"ssoGroupMap":[]
		}}`)
	})

	r := &SSOResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	priorScopes, diags := types.ListValueFrom(ctx, types.StringType, []string{"openid", "profile", "email", "groups"})
	if diags.HasError() {
		t.Fatalf("ListValueFrom: %v", diags)
	}
	priorGroupMap, diags := types.MapValueFrom(ctx, types.StringType, map[string]string{
		"dns-admins": "Administrators",
	})
	if diags.HasError() {
		t.Fatalf("MapValueFrom: %v", diags)
	}

	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &SSOResourceModel{
		ID:                            types.StringValue("sso"),
		Enabled:                       types.BoolValue(true),
		Authority:                     types.StringValue("https://keycloak.example.com/realms/master"),
		ClientID:                      types.StringValue("technitium-dns"),
		ClientSecret:                  types.StringValue("s3cr3t"),
		MetadataAddress:               types.StringNull(),
		Scopes:                        priorScopes,
		AllowSignup:                   types.BoolValue(false),
		AllowSignupOnlyForMappedUsers: types.BoolValue(true),
		GroupMap:                      priorGroupMap,
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, &SSOResourceModel{
		ID:                            types.StringValue("sso"),
		Enabled:                       types.BoolValue(true),
		Authority:                     types.StringNull(),
		ClientID:                      types.StringValue("technitium-dns"),
		ClientSecret:                  types.StringValue("s3cr3t"),
		MetadataAddress:               types.StringNull(),
		Scopes:                        types.ListNull(types.StringType),
		AllowSignup:                   types.BoolValue(false),
		AllowSignupOnlyForMappedUsers: types.BoolValue(true),
		GroupMap:                      types.MapNull(types.StringType),
	}); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}

	mu.Lock()
	for _, param := range []string{"ssoAuthority", "ssoScopes", "ssoGroupMap"} {
		got, ok := sent[param]
		if !ok {
			t.Errorf("%s was not sent; omitting it makes the server retain the removed value", param)
			continue
		}
		if got != "" {
			t.Errorf("%s = %q, want an explicit empty clear", param, got)
		}
	}
	if _, ok := sent["ssoMetadataAddress"]; ok {
		t.Error("ssoMetadataAddress must not be sent when it is null in both plan and state")
	}
	if got, want := sent["ssoClientId"], "technitium-dns"; got != want {
		t.Errorf("ssoClientId = %q, want the still-configured %q", got, want)
	}
	mu.Unlock()

	var saved SSOResourceModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if !saved.Authority.IsNull() {
		t.Errorf("authority read back as %q, want null after the clear", saved.Authority.ValueString())
	}
	if !saved.GroupMap.IsNull() {
		t.Errorf("group_map read back as %v, want null after the clear", saved.GroupMap)
	}
	// The server reports its default scopes after the reset; those must not
	// land in state for a null plan.
	if !saved.Scopes.IsNull() {
		t.Errorf("scopes read back as %v, want null (the server default must not overwrite an unset attribute)", saved.Scopes)
	}
	if got, want := saved.ClientSecret.ValueString(), "s3cr3t"; got != want {
		t.Errorf("client_secret = %q, want the configured value %q", got, want)
	}
}

// A group mapping present on the server while group_map is unset grants local
// group membership on every SSO login, so it must surface as drift in state
// rather than being skipped silently.
func TestSSORead_SurfacesGroupMapGrantedOutsideTerraform(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sso/get", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"ssoEnabled":true,
			"ssoAuthority":"https://keycloak.example.com/realms/master",
			"ssoClientId":"technitium-dns",
			"ssoClientSecret":"************",
			"ssoMetadataAddress":null,
			"ssoScopes":["openid","profile","email"],
			"ssoAllowSignup":false,
			"ssoAllowSignupOnlyForMappedUsers":true,
			"ssoGroupMap":[
				{"remoteGroup":"contractors","localGroup":"DNS Administrators"}
			]
		}}`)
	})

	r := &SSOResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &SSOResourceModel{
		ID:                            types.StringValue("sso"),
		Enabled:                       types.BoolValue(true),
		Authority:                     types.StringValue("https://keycloak.example.com/realms/master"),
		ClientID:                      types.StringValue("technitium-dns"),
		ClientSecret:                  types.StringValue("s3cr3t"),
		MetadataAddress:               types.StringNull(),
		Scopes:                        types.ListNull(types.StringType),
		AllowSignup:                   types.BoolValue(false),
		AllowSignupOnlyForMappedUsers: types.BoolValue(true),
		GroupMap:                      types.MapNull(types.StringType),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: state.Raw}}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}

	var saved SSOResourceModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if saved.GroupMap.IsNull() {
		t.Fatal("group_map stayed null; server-side mappings must be read back so they surface as drift")
	}
	var readBack map[string]string
	if diags := saved.GroupMap.ElementsAs(ctx, &readBack, false); diags.HasError() {
		t.Fatalf("group_map ElementsAs: %v", diags)
	}
	if got, want := readBack["contractors"], "DNS Administrators"; got != want {
		t.Errorf("group_map[contractors] = %q, want %q", got, want)
	}
}

// Removing display_name must reset it explicitly, and the server's fallback
// default (the username) must not be read back into the null attribute.
func TestUserUpdate_ClearsRemovedDisplayName(t *testing.T) {
	var mu sync.Mutex
	sent := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/users/set", func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		mu.Lock()
		for k := range req.PostForm {
			sent[k] = req.PostForm.Get(k)
		}
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
	})
	// After the reset the server reports the username as the display name —
	// its fallback default, not the cleared configuration value.
	mux.HandleFunc("/api/admin/users/get", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"username":"automation",
			"displayName":"automation",
			"disabled":false,
			"isSsoUser":false,
			"sessionTimeoutSeconds":1800,
			"memberOfGroups":["Administrators"]
		}}`)
	})

	r := &UserResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &UserResourceModel{
		ID:                    types.StringValue("automation"),
		Username:              types.StringValue("automation"),
		Password:              types.StringValue("pw"),
		DisplayName:           types.StringValue("Automation Bot"),
		MemberOfGroups:        types.SetNull(types.StringType),
		SessionTimeoutSeconds: types.Int64Value(1800),
		Disabled:              types.BoolValue(false),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, &UserResourceModel{
		ID:                    types.StringValue("automation"),
		Username:              types.StringValue("automation"),
		Password:              types.StringValue("pw"),
		DisplayName:           types.StringNull(),
		MemberOfGroups:        types.SetNull(types.StringType),
		SessionTimeoutSeconds: types.Int64Value(1800),
		Disabled:              types.BoolValue(false),
	}); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}

	mu.Lock()
	got, ok := sent["displayName"]
	if !ok {
		t.Error("displayName was not sent; omitting it makes the server retain the removed value")
	} else if got != "" {
		t.Errorf("displayName = %q, want an explicit empty reset", got)
	}
	if _, ok := sent["newPass"]; ok {
		t.Error("newPass must not be sent when the password is unchanged")
	}
	mu.Unlock()

	var saved UserResourceModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if !saved.DisplayName.IsNull() {
		t.Errorf("display_name read back as %q, want null (the server's username fallback must not overwrite an unset attribute)",
			saved.DisplayName.ValueString())
	}
}
