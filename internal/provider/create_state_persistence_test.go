// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// newUserCreateHarness builds a UserResource wired to a test server, plus a
// Create request/response pair carrying the given plan.
func newUserCreateHarness(t *testing.T, plan *UserResourceModel, handler http.HandlerFunc) (*UserResource, resource.CreateRequest, *resource.CreateResponse) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &UserResource{client: c}

	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	tfPlan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := tfPlan.Set(context.Background(), plan); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	req := resource.CreateRequest{Plan: tfPlan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	return r, req, resp
}

// A user that exists on the server must never be left out of state. When
// UserCreate succeeds and the follow-up UserSet fails, the account is live;
// returning without writing state orphans it, and the next apply fails
// permanently with "user already exists".
func TestUserCreate_LateFailureStillPersistsState(t *testing.T) {
	plan := &UserResourceModel{
		Username:       types.StringValue("svc-terraform"),
		Password:       types.StringValue("correct-horse-battery-staple"),
		DisplayName:    types.StringValue("Terraform Service Account"),
		MemberOfGroups: types.SetNull(types.StringType),
		Disabled:       types.BoolValue(false),
	}

	r, req, resp := newUserCreateHarness(t, plan, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/admin/users/create":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/admin/users/get":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{
				"username":"svc-terraform",
				"displayName":"Terraform Service Account",
				"disabled":false,
				"sessionTimeoutSeconds":1800,
				"memberOfGroups":[]
			}}`)
		case "/api/admin/users/set":
			_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"Access was denied."}`)
		default:
			t.Errorf("unexpected request path: %s", req.URL.Path)
		}
	})

	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic when the follow-up configuration call fails")
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("user exists on the server but state was not written: the account is orphaned and the next apply will fail with \"user already exists\"")
	}

	var saved UserResourceModel
	if diags := resp.State.Get(context.Background(), &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if saved.ID.ValueString() != "svc-terraform" {
		t.Fatalf("persisted id = %q, want %q", saved.ID.ValueString(), "svc-terraform")
	}
	if saved.Username.ValueString() != "svc-terraform" {
		t.Fatalf("persisted username = %q, want %q", saved.Username.ValueString(), "svc-terraform")
	}
}

// resetOnFirstCall closes the connection with a TCP RST on its first
// invocation, reproducing a primary/secondary sync that drops the response
// after the server has already acted on the request.
func resetOnFirstCall(t *testing.T) (http.HandlerFunc, func() int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0

	h := func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()

		if n == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support hijacking")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0) // force RST rather than a clean FIN
			}
			_ = conn.Close()
			return
		}

		// The join already landed, so the server rejects the retry.
		_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"DNS Server is already part of a cluster."}`)
	}
	return h, func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

// A join that lands but whose response is lost to a connection reset must not
// be reported as a failure. The node is in the cluster; erroring out without
// writing state leaves it joined but unmanaged, and the blind retry then fails
// with "already part of a cluster".
func TestClusterSecondaryCreate_JoinLandedBeforeConnectionReset(t *testing.T) {
	joinHandler, joinCalls := resetOnFirstCall(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/cluster/initJoin", joinHandler)
	mux.HandleFunc("/api/admin/cluster/state", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"clusterInitialized": true,
			"clusterDomain": "cluster.example.com",
			"dnsServerDomain": "ns2.example.com",
			"nodes": [
				{"id":1,"name":"ns1.example.com","url":"https://ns1.example.com","type":"Primary","state":"Online"},
				{"id":2,"name":"ns2.example.com","url":"https://ns2.example.com","type":"Secondary","state":"Online"}
			]
		}}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &ClusterSecondaryResource{client: c}

	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	ips, diags := types.ListValueFrom(context.Background(), types.StringType, []string{"192.0.2.20"})
	if diags.HasError() {
		t.Fatalf("ListValueFrom: %v", diags)
	}

	plan := &ClusterSecondaryResourceModel{
		NodeURL:                 types.StringValue(srv.URL),
		NodeToken:               types.StringValue("test-token"),
		NodeSkipTLSVerify:       types.BoolValue(false),
		NodeIPAddresses:         ips,
		PrimaryNodeURL:          types.StringValue("https://ns1.example.com"),
		PrimaryNodeIPAddress:    types.StringValue("192.0.2.10"),
		PrimaryNodeUsername:     types.StringValue("admin"),
		PrimaryNodePassword:     types.StringValue("admin"),
		IgnoreCertificateErrors: types.BoolValue(false),
		JoinTimeoutSeconds:      types.Int64Value(30),
	}

	tfPlan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := tfPlan.Set(context.Background(), plan); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}

	req := resource.CreateRequest{Plan: tfPlan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("join landed on the server; Create must not report failure, got: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("node joined the cluster but state was not written: it is joined and unmanaged")
	}

	var saved ClusterSecondaryResourceModel
	if diags := resp.State.Get(context.Background(), &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	if saved.NodeName.ValueString() != "ns2.example.com" {
		t.Fatalf("node_name = %q, want %q", saved.NodeName.ValueString(), "ns2.example.com")
	}
	if n := joinCalls(); n != 1 {
		t.Fatalf("initJoin was called %d times; a landed join must not be blindly retried", n)
	}
}
