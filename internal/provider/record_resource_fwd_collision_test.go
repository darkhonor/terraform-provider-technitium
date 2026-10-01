// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// fakeFWDServer serves a fixed set of FWD records for fwd.example.com and
// records every mutation call, so a test can prove the collision guard refused
// BEFORE anything reached the server.
type fakeFWDServer struct {
	mu        sync.Mutex
	records   []map[string]interface{} // rData of each FWD record
	mutations []string                 // API paths of add/update/delete calls
}

func (f *fakeFWDServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch req.URL.Path {
		case "/api/zones/records/get":
			recs := make([]map[string]interface{}, 0, len(f.records))
			for _, rd := range f.records {
				recs = append(recs, map[string]interface{}{
					"name": "fwd.example.com", "type": "FWD", "ttl": 0, "disabled": false,
					"rData": rd, "lastModified": "2026-01-01T00:00:00Z",
				})
			}
			body, _ := json.Marshal(map[string]interface{}{
				"status":   "ok",
				"response": map[string]interface{}{"zone": map[string]interface{}{}, "records": recs},
			})
			_, _ = w.Write(body)
		case "/api/zones/records/add", "/api/zones/records/update", "/api/zones/records/delete":
			f.mutations = append(f.mutations, req.URL.Path)
			_, _ = w.Write([]byte(`{"status":"ok","response":{"addedRecord":{"name":"fwd.example.com","type":"FWD","rData":{}}}}`))
		default:
			t.Errorf("unexpected request path: %s", req.URL.Path)
		}
	}
}

func fwdRData(forwarder, protocol string, priority int, dnssec bool) map[string]interface{} {
	return map[string]interface{}{
		"forwarder": forwarder, "protocol": protocol, "priority": priority, "dnssecValidation": dnssec,
	}
}

// collidingPair is the pattern the documentation used to recommend: one
// forwarder over one protocol, told apart only by priority and validation.
func collidingPair() []map[string]interface{} {
	return []map[string]interface{}{
		fwdRData("1.1.1.1", "Udp", 1, true),
		fwdRData("1.1.1.1", "Udp", 2, false),
	}
}

func newFWDTestResource(t *testing.T, srv *fakeFWDServer) (*RecordResource, fwresource.SchemaResponse) {
	t.Helper()
	ts := httptest.NewServer(srv.handler(t))
	t.Cleanup(ts.Close)
	c, err := client.NewClient(client.ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &RecordResource{client: c}
	var schemaResp fwresource.SchemaResponse
	r.Schema(context.Background(), fwresource.SchemaRequest{}, &schemaResp)
	return r, schemaResp
}

func toState(t *testing.T, s fwresource.SchemaResponse, m *RecordResourceModel) tfsdk.State {
	t.Helper()
	st := tfsdk.State{Schema: s.Schema}
	if diags := st.Set(context.Background(), m); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}
	return st
}

func toPlan(t *testing.T, s fwresource.SchemaResponse, m *RecordResourceModel) tfsdk.Plan {
	t.Helper()
	p := tfsdk.Plan{Schema: s.Schema}
	if diags := p.Set(context.Background(), m); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}
	return p
}

func assertRefused(t *testing.T, srv *fakeFWDServer, errs []string) {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("expected the collision guard to refuse, got no error")
	}
	if !strings.Contains(errs[0], "1.1.1.1") || !strings.Contains(errs[0], "Udp") {
		t.Errorf("diagnostic does not name the colliding forwarder and protocol:\n%s", errs[0])
	}
	if len(srv.mutations) != 0 {
		t.Errorf("guard refused but the server still received %v", srv.mutations)
	}
}

// Measured against live Technitium 15.4 and 15.5.1: delete matches an FWD
// record on forwarder + protocol only, and removes the FIRST-CREATED match.
// Deleting the non-validating fallback of a priority-only pair therefore
// deleted the validating record instead. The provider must refuse.
func TestRecordDelete_FWDCollisionRefused(t *testing.T) {
	srv := &fakeFWDServer{records: collidingPair()}
	r, s := newFWDTestResource(t, srv)

	resp := &fwresource.DeleteResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Delete(context.Background(), fwresource.DeleteRequest{
		State: toState(t, s, fwdModel("1.1.1.1", "Udp", 2, boolPtrForTest(false))),
	}, resp)

	var errs []string
	for _, d := range resp.Diagnostics.Errors() {
		errs = append(errs, d.Summary()+": "+d.Detail())
	}
	assertRefused(t, srv, errs)
}

// Measured: a TTL-only update of one record of a colliding pair merged the two
// into one, and the validating record was the one that vanished.
func TestRecordUpdate_FWDCollisionRefused(t *testing.T) {
	srv := &fakeFWDServer{records: collidingPair()}
	r, s := newFWDTestResource(t, srv)

	state := fwdModel("1.1.1.1", "Udp", 2, boolPtrForTest(false))
	state.TTL = types.Int64Value(3600)
	plan := fwdModel("1.1.1.1", "Udp", 2, boolPtrForTest(false))
	plan.TTL = types.Int64Value(600)

	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Update(context.Background(), fwresource.UpdateRequest{
		State: toState(t, s, state), Plan: toPlan(t, s, plan),
	}, resp)

	var errs []string
	for _, d := range resp.Diagnostics.Errors() {
		errs = append(errs, d.Summary()+": "+d.Detail())
	}
	assertRefused(t, srv, errs)
}

// Moving a record onto a forwarder + protocol another record already uses
// would create the collision; refuse it before sending.
func TestRecordUpdate_FWDMoveOntoExistingRefused(t *testing.T) {
	srv := &fakeFWDServer{records: []map[string]interface{}{
		fwdRData("1.1.1.1", "Udp", 1, true),
		fwdRData("9.9.9.9", "Udp", 2, false),
	}}
	r, s := newFWDTestResource(t, srv)

	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Update(context.Background(), fwresource.UpdateRequest{
		State: toState(t, s, fwdModel("9.9.9.9", "Udp", 2, boolPtrForTest(false))),
		Plan:  toPlan(t, s, fwdModel("1.1.1.1", "Udp", 2, boolPtrForTest(false))),
	}, resp)

	var errs []string
	for _, d := range resp.Diagnostics.Errors() {
		errs = append(errs, d.Summary()+": "+d.Detail())
	}
	assertRefused(t, srv, errs)
}

// Technitium 15.5+ refuses the add server-side; 15.4 and earlier accept it
// and create the collision. The provider refuses on every version.
func TestRecordCreate_FWDCollisionRefused(t *testing.T) {
	srv := &fakeFWDServer{records: []map[string]interface{}{fwdRData("1.1.1.1", "Udp", 1, true)}}
	r, s := newFWDTestResource(t, srv)

	plan := fwdModel("1.1.1.1", "udp", 2, boolPtrForTest(false)) // protocol case differs: still the same record
	plan.Overwrite = types.BoolValue(false)

	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: toPlan(t, s, plan)}, resp)

	var errs []string
	for _, d := range resp.Diagnostics.Errors() {
		errs = append(errs, d.Summary()+": "+d.Detail())
	}
	if len(errs) == 0 {
		t.Fatal("expected the collision guard to refuse, got no error")
	}
	if len(srv.mutations) != 0 {
		t.Errorf("guard refused but the server still received %v", srv.mutations)
	}
}

// A distinct protocol is a distinct record; nothing to refuse.
func TestRecordDelete_FWDDistinctProtocolProceeds(t *testing.T) {
	srv := &fakeFWDServer{records: []map[string]interface{}{
		fwdRData("1.1.1.1", "Udp", 1, true),
		fwdRData("1.1.1.1", "Tcp", 2, false),
	}}
	r, s := newFWDTestResource(t, srv)

	resp := &fwresource.DeleteResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Delete(context.Background(), fwresource.DeleteRequest{
		State: toState(t, s, fwdModel("1.1.1.1", "Tcp", 2, boolPtrForTest(false))),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if len(srv.mutations) != 1 {
		t.Errorf("expected exactly one delete call, got %v", srv.mutations)
	}
}

// An unset protocol is Technitium's default, Udp, and must collide with an
// explicit Udp record.
func TestRecordDelete_FWDNullProtocolIsUdp(t *testing.T) {
	srv := &fakeFWDServer{records: collidingPair()}
	r, s := newFWDTestResource(t, srv)

	m := fwdModel("1.1.1.1", "", 2, nil)
	m.Protocol = types.StringNull()
	resp := &fwresource.DeleteResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Delete(context.Background(), fwresource.DeleteRequest{State: toState(t, s, m)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a null protocol to be treated as Udp and refused")
	}
	if len(srv.mutations) != 0 {
		t.Errorf("guard refused but the server still received %v", srv.mutations)
	}
}

// Operators who already followed the old guidance must hear about it on every
// refresh, before they try a destroy or update that would be refused.
func TestRecordRead_FWDCollisionWarns(t *testing.T) {
	srv := &fakeFWDServer{records: collidingPair()}
	r, s := newFWDTestResource(t, srv)

	state := toState(t, s, fwdModel("1.1.1.1", "Udp", 1, boolPtrForTest(true)))
	resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: s.Schema, Raw: state.Raw}}
	r.Read(context.Background(), fwresource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read must not fail on a collision, only warn: %v", resp.Diagnostics)
	}
	warns := resp.Diagnostics.Warnings()
	if len(warns) == 0 {
		t.Fatal("expected a collision warning on refresh")
	}
	if !strings.Contains(warns[0].Detail(), "terraform state rm") {
		t.Errorf("warning lacks the recovery instructions:\n%s", warns[0].Detail())
	}
}
