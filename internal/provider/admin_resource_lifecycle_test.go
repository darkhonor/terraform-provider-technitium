// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// newTestClient returns a client pointed at a test server.
func newTestClient(t *testing.T, handler http.Handler) *client.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// --- technitium_api_token ---------------------------------------------------
//
// The token is non-expiring and admin-scoped, so partial_token is the only
// handle Terraform has for revoking it. These tests pin the create/read/delete
// state transitions that keep that handle correct.

func newAPITokenResource(t *testing.T, handler http.Handler) (*APITokenResource, tfsdk.State) {
	t.Helper()
	r := &APITokenResource{client: newTestClient(t, handler)}

	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return r, tfsdk.State{Schema: schemaResp.Schema}
}

func apiTokenCreate(t *testing.T, r *APITokenResource, blank tfsdk.State) *resource.CreateResponse {
	t.Helper()
	plan := tfsdk.Plan{Schema: blank.Schema}
	if diags := plan.Set(context.Background(), &APITokenResourceModel{
		User:      types.StringValue("automation"),
		TokenName: types.StringValue("terraform"),
	}); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	resp := &resource.CreateResponse{State: tfsdk.State{Schema: blank.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	return resp
}

// The sessions list is authoritative for partial_token: when the server
// reports it, that value must be what lands in state.
func TestAPITokenCreate_StoresServerReportedPartialToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sessions/createToken", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"username":"automation","tokenName":"terraform",
			"token":"EXAMPLE-TOKEN-01-EXAMPLE-TOKEN-02"
		}}`)
	})
	mux.HandleFunc("/api/admin/sessions/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"sessions":[
			{"username":"admin","type":"Standard","partialToken":"aaaaaaaaaaaaaaaa","isCurrentSession":true},
			{"username":"automation","type":"ApiToken","tokenName":"terraform","partialToken":"EXAMPLE-TOKEN-01"}
		]}}`)
	})

	r, blank := newAPITokenResource(t, mux)
	resp := apiTokenCreate(t, r, blank)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	var saved APITokenResourceModel
	if diags := resp.State.Get(context.Background(), &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if got, want := saved.PartialToken.ValueString(), "EXAMPLE-TOKEN-01"; got != want {
		t.Errorf("partial_token = %q, want the server-reported %q", got, want)
	}
	if got, want := saved.ID.ValueString(), "automation/terraform"; got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	if got, want := saved.Token.ValueString(), "EXAMPLE-TOKEN-01-EXAMPLE-TOKEN-02"; got != want {
		t.Errorf("token = %q, want %q", got, want)
	}
}

// When the sessions list cannot identify the new token, the first 16
// characters are used. Technitium builds partialToken as Token[0..16) and
// matches deletes with StartsWith, so the prefix is the same value by
// construction.
func TestAPITokenCreate_FallsBackToTokenPrefixWhenSessionUnlisted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sessions/createToken", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"username":"automation","tokenName":"terraform",
			"token":"EXAMPLE-TOKEN-01-EXAMPLE-TOKEN-02"
		}}`)
	})
	mux.HandleFunc("/api/admin/sessions/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"Access was denied."}`)
	})

	r, blank := newAPITokenResource(t, mux)
	resp := apiTokenCreate(t, r, blank)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	var saved APITokenResourceModel
	if diags := resp.State.Get(context.Background(), &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if got, want := saved.PartialToken.ValueString(), "EXAMPLE-TOKEN-01"; got != want {
		t.Errorf("partial_token = %q, want the 16-character prefix %q", got, want)
	}
}

// A token revoked outside Terraform must drop out of state so the next plan
// recreates it, rather than leaving a resource whose delete would fail.
func TestAPITokenRead_RemovesStateWhenTokenRevokedServerSide(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sessions/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"sessions":[
			{"username":"admin","type":"Standard","partialToken":"aaaaaaaaaaaaaaaa","isCurrentSession":true}
		]}}`)
	})

	r, blank := newAPITokenResource(t, mux)
	state := blank
	if diags := state.Set(context.Background(), &APITokenResourceModel{
		ID:           types.StringValue("automation/terraform"),
		User:         types.StringValue("automation"),
		TokenName:    types.StringValue("terraform"),
		Token:        types.StringValue("EXAMPLE-TOKEN-01-EXAMPLE-TOKEN-02"),
		PartialToken: types.StringValue("EXAMPLE-TOKEN-01"),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	resp := &resource.ReadResponse{State: tfsdk.State{Schema: blank.Schema, Raw: state.Raw}}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("expected state removal for a token that no longer exists on the server")
	}
}

// Destroy must revoke using the partial token held in state, not a value
// recomputed at delete time.
func TestAPITokenDelete_SendsStoredPartialToken(t *testing.T) {
	var mu sync.Mutex
	var gotPartial string
	seen := false

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sessions/delete", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		gotPartial = req.URL.Query().Get("partialToken")
		seen = true
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
	})

	r, blank := newAPITokenResource(t, mux)
	state := blank
	if diags := state.Set(context.Background(), &APITokenResourceModel{
		ID:           types.StringValue("automation/terraform"),
		User:         types.StringValue("automation"),
		TokenName:    types.StringValue("terraform"),
		Token:        types.StringValue("EXAMPLE-TOKEN-01-EXAMPLE-TOKEN-02"),
		PartialToken: types.StringValue("EXAMPLE-TOKEN-01"),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: blank.Schema, Raw: state.Raw}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete: %v", resp.Diagnostics)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen {
		t.Fatal("Delete never called /api/admin/sessions/delete")
	}
	if want := "EXAMPLE-TOKEN-01"; gotPartial != want {
		t.Errorf("partialToken sent = %q, want the value stored in state %q", gotPartial, want)
	}
}

// --- technitium_sso ---------------------------------------------------------

// group_map and scopes use two different separators on the wire. This pins
// both encodings, including the sorted key order that keeps the group map
// stable across plans.
func TestSSOCreate_EncodesGroupMapSortedAndScopesPipeSeparated(t *testing.T) {
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
	mux.HandleFunc("/api/admin/sso/get", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"ssoEnabled":true,
			"ssoAuthority":"https://keycloak.example.com/realms/master",
			"ssoClientId":"technitium-dns",
			"ssoClientSecret":"************",
			"ssoMetadataAddress":null,
			"ssoScopes":["openid","profile","email","groups"],
			"ssoAllowSignup":true,
			"ssoAllowSignupOnlyForMappedUsers":true,
			"ssoGroupMap":[
				{"remoteGroup":"alpha-group","localGroup":"Administrators"},
				{"remoteGroup":"zeta-group","localGroup":"DNS Administrators"}
			]
		}}`)
	})

	r := &SSOResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	scopes, diags := types.ListValueFrom(ctx, types.StringType, []string{"openid", "profile", "email", "groups"})
	if diags.HasError() {
		t.Fatalf("ListValueFrom: %v", diags)
	}
	// Deliberately out of order: the encoder must sort by remote group.
	groupMap, diags := types.MapValueFrom(ctx, types.StringType, map[string]string{
		"zeta-group":  "DNS Administrators",
		"alpha-group": "Administrators",
	})
	if diags.HasError() {
		t.Fatalf("MapValueFrom: %v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, &SSOResourceModel{
		Enabled:                       types.BoolValue(true),
		Authority:                     types.StringValue("https://keycloak.example.com/realms/master"),
		ClientID:                      types.StringValue("technitium-dns"),
		ClientSecret:                  types.StringValue("s3cr3t"),
		MetadataAddress:               types.StringNull(),
		Scopes:                        scopes,
		AllowSignup:                   types.BoolValue(true),
		AllowSignupOnlyForMappedUsers: types.BoolValue(true),
		GroupMap:                      groupMap,
	}); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	mu.Lock()
	defer mu.Unlock()
	if got, want := sent["ssoGroupMap"], "alpha-group|Administrators|zeta-group|DNS Administrators"; got != want {
		t.Errorf("ssoGroupMap = %q, want %q", got, want)
	}
	if got, want := sent["ssoScopes"], "openid|profile|email|groups"; got != want {
		t.Errorf("ssoScopes = %q, want %q", got, want)
	}
	if got, want := sent["ssoEnabled"], "true"; got != want {
		t.Errorf("ssoEnabled = %q, want %q", got, want)
	}
	if _, ok := sent["ssoMetadataAddress"]; ok {
		t.Error("ssoMetadataAddress must not be sent when it is null in the plan")
	}

	var saved SSOResourceModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if got, want := saved.ID.ValueString(), "sso"; got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	// The server masks the secret, so state must keep the configured value.
	if got, want := saved.ClientSecret.ValueString(), "s3cr3t"; got != want {
		t.Errorf("client_secret = %q, want the configured value %q (the server's mask must not overwrite it)", got, want)
	}
	var readBack map[string]string
	if diags := saved.GroupMap.ElementsAs(ctx, &readBack, false); diags.HasError() {
		t.Fatalf("group_map ElementsAs: %v", diags)
	}
	if readBack["alpha-group"] != "Administrators" || readBack["zeta-group"] != "DNS Administrators" {
		t.Errorf("group_map read back as %v, want the two configured mappings", readBack)
	}
}

// --- technitium_cluster_secondary -------------------------------------------

// A node removed from the cluster out of band must drop out of state. This
// also pins the /api/admin/cluster/state response shape the read depends on.
func TestClusterSecondaryRead_RemovesStateWhenNodeNoLongerInCluster(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/cluster/state", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"clusterInitialized": true,
			"clusterDomain": "cluster.example.com",
			"dnsServerDomain": "ns1.example.com",
			"nodes": [
				{"id":1,"name":"ns1.example.com","url":"https://ns1.example.com","type":"Primary","state":"Online"}
			]
		}}`)
	})

	r := &ClusterSecondaryResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	ips, diags := types.ListValueFrom(ctx, types.StringType, []string{"192.0.2.20"})
	if diags.HasError() {
		t.Fatalf("ListValueFrom: %v", diags)
	}

	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &ClusterSecondaryResourceModel{
		ID:                      types.StringValue("ns2.example.com"),
		NodeName:                types.StringValue("ns2.example.com"),
		NodeURL:                 types.StringValue("https://ns2.example.com"),
		NodeToken:               types.StringValue("test-token"),
		NodeSkipTLSVerify:       types.BoolValue(false),
		NodeIPAddresses:         ips,
		PrimaryNodeURL:          types.StringValue("https://ns1.example.com"),
		PrimaryNodeIPAddress:    types.StringValue("192.0.2.10"),
		PrimaryNodeUsername:     types.StringValue("admin"),
		PrimaryNodePassword:     types.StringValue("admin"),
		IgnoreCertificateErrors: types.BoolValue(false),
		JoinTimeoutSeconds:      types.Int64Value(30),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: state.Raw}}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("expected state removal for a node that is no longer in the cluster")
	}
}

// A cluster that has been torn down entirely must also drop the secondary
// from state rather than reporting it as joined.
func TestClusterSecondaryRead_RemovesStateWhenClusterUninitialized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/cluster/state", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"clusterInitialized": false}}`)
	})

	r := &ClusterSecondaryResource{client: newTestClient(t, mux)}
	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ctx := context.Background()
	ips, diags := types.ListValueFrom(ctx, types.StringType, []string{"192.0.2.20"})
	if diags.HasError() {
		t.Fatalf("ListValueFrom: %v", diags)
	}

	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &ClusterSecondaryResourceModel{
		ID:                      types.StringValue("ns2.example.com"),
		NodeName:                types.StringValue("ns2.example.com"),
		NodeURL:                 types.StringValue("https://ns2.example.com"),
		NodeToken:               types.StringValue("test-token"),
		NodeSkipTLSVerify:       types.BoolValue(false),
		NodeIPAddresses:         ips,
		PrimaryNodeURL:          types.StringValue("https://ns1.example.com"),
		PrimaryNodeIPAddress:    types.StringValue("192.0.2.10"),
		PrimaryNodeUsername:     types.StringValue("admin"),
		PrimaryNodePassword:     types.StringValue("admin"),
		IgnoreCertificateErrors: types.BoolValue(false),
		JoinTimeoutSeconds:      types.Int64Value(30),
	}); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: state.Raw}}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("expected state removal when the cluster is no longer initialized")
	}
}
