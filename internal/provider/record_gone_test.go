// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestIsRecordAlreadyGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// exact server message from the issue #88 report
		{"no such zone was found", errors.New(`getting records for "pve.example.internal" in zone "example.internal": technitium API error (status=error): No such zone was found: pve.example.internal`), true},
		{"no such record exists", errors.New("technitium API error (status=error): No such record exists"), true},
		{"zone does not exist", errors.New("Zone does not exist: example.internal"), true},
		{"zone was not found", errors.New("The zone was not found"), true},
		{"unrelated auth error", errors.New("technitium API error (status=invalid-token): Invalid token or session expired."), false},
		{"unrelated network error", errors.New(`Get "http://127.0.0.1:5380/api/zones/records/get": dial tcp 127.0.0.1:5380: connect: connection refused`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRecordAlreadyGone(tc.err); got != tc.want {
				t.Fatalf("isRecordAlreadyGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// newRecordReadHarness builds a RecordResource wired to a test server and a
// populated state for pve.example.internal, mirroring the issue #88 setup.
func newRecordReadHarness(t *testing.T, handler http.HandlerFunc) (*RecordResource, resource.ReadRequest, *resource.ReadResponse) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &RecordResource{client: c}

	schemaResp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(context.Background(), &RecordResourceModel{
		ID:    types.StringValue("example.internal::pve.example.internal::A::192.0.2.10"),
		Zone:  types.StringValue("example.internal"),
		Name:  types.StringValue("pve.example.internal"),
		Type:  types.StringValue("A"),
		Value: types.StringValue("192.0.2.10"),
		TTL:   types.Int64Value(3600),
	})
	if diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	req := resource.ReadRequest{State: state}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: state.Raw}}
	return r, req, resp
}

// Regression test for issue #88: a missing parent zone during refresh must
// remove the record from state instead of aborting with a hard error.
func TestRecordRead_MissingParentZoneRemovesState(t *testing.T) {
	r, req, resp := newRecordReadHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"No such zone was found: pve.example.internal"}`)
	})

	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no error diagnostics, got: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected state to be removed (null), got: %v", resp.State.Raw)
	}
}

// Errors other than not-found must still surface as diagnostics and keep the
// record in state.
func TestRecordRead_TransientErrorKeepsState(t *testing.T) {
	r, req, resp := newRecordReadHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"invalid-token","errorMessage":"Invalid token or session expired."}`)
	})

	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostics for a non-not-found failure")
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("state must not be removed on a transient error")
	}
}
