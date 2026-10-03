// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const soaFakeZone = "example.internal"

type zoneSOAFake struct {
	mu           sync.Mutex
	zoneType     string
	scheme       bool
	soaUpdates   int
	createParams url.Values
	failPath     string
	omitScheme   bool
	srv          *httptest.Server
}

func newZoneSOAFake(t *testing.T, zoneType string, scheme bool) *zoneSOAFake {
	t.Helper()
	f := &zoneSOAFake{zoneType: zoneType, scheme: scheme}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == f.failPath {
			_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"injected failure"}`)
			return
		}
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/api/zones/create":
			f.createParams = r.PostForm
			if r.PostForm.Get("useSoaSerialDateScheme") == "true" && f.zoneType == "Primary" {
				f.scheme = true
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"domain":%q}}`, soaFakeZone)
		case "/api/zones/options/get":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"name":%q,"type":%q,"disabled":false,"dnssecStatus":"Unsigned"}}`, soaFakeZone, f.zoneType)
		case "/api/zones/options/set":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/zones/list":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"zones":[{"name":%q,"soaSerial":7}]}}`, soaFakeZone)
		case "/api/zones/records/get":
			scheme := fmt.Sprintf(`,"useSerialDateScheme":%t`, f.scheme)
			if f.omitScheme {
				scheme = ""
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
				"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
				"serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900%s}}]}}`, scheme)
		case "/api/zones/records/update":
			f.soaUpdates++
			f.scheme = r.PostForm.Get("useSerialDateScheme") == "true"
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *zoneSOAFake) resource(t *testing.T) *ZoneResource {
	t.Helper()
	c, err := client.NewClient(client.ClientConfig{BaseURL: f.srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &ZoneResource{client: c}
}

func soaFakeModel(zoneType string, scheme types.Bool) *ZoneResourceModel {
	return &ZoneResourceModel{
		Name:                     types.StringValue(soaFakeZone),
		Type:                     types.StringValue(zoneType),
		SOASerialDateScheme:      scheme,
		Notify:                   types.ListNull(types.StringType),
		AllowTransfer:            types.ListNull(types.StringType),
		ZoneTransferTsigKeyNames: types.ListNull(types.StringType),
		QueryAccess:              types.StringNull(),
		QueryAccessNetworkACL:    types.ListNull(types.StringType),
		DynamicUpdate:            types.StringNull(),
		DynamicUpdateNetworkACL:  types.ListNull(types.StringType),
		SOASerial:                types.Int64Unknown(),
	}
}

func TestReadZoneState_SchemeFromSOA(t *testing.T) {
	for _, zt := range []string{"Primary", "Forwarder"} {
		for _, server := range []bool{true, false} {
			f := newZoneSOAFake(t, zt, server)
			m := soaFakeModel(zt, types.BoolValue(!server))
			if err := f.resource(t).readZoneState(context.Background(), m); err != nil {
				t.Fatalf("%s/%t: readZoneState: %v", zt, server, err)
			}
			if m.SOASerialDateScheme.ValueBool() != server {
				t.Errorf("%s: state = %t, server = %t", zt, m.SOASerialDateScheme.ValueBool(), server)
			}
		}
	}
}

func TestReadZoneState_UnmanagedTypesKeepConfiguredValue(t *testing.T) {
	for _, zt := range []string{"Secondary", "Stub"} {
		f := newZoneSOAFake(t, zt, true)
		r := f.resource(t)

		m := soaFakeModel(zt, types.BoolValue(false))
		if err := r.readZoneState(context.Background(), m); err != nil {
			t.Fatalf("%s: readZoneState: %v", zt, err)
		}
		if m.SOASerialDateScheme.ValueBool() {
			t.Errorf("%s: configured false was overwritten", zt)
		}

		m = soaFakeModel(zt, types.BoolNull())
		if err := r.readZoneState(context.Background(), m); err != nil {
			t.Fatalf("%s: readZoneState: %v", zt, err)
		}
		if !m.SOASerialDateScheme.Equal(types.BoolValue(true)) {
			t.Errorf("%s: null (import) = %v, want true", zt, m.SOASerialDateScheme)
		}
	}
}

func TestReadZoneState_AbsentSchemeFieldKeepsValue(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	f.omitScheme = true
	r := f.resource(t)

	m := soaFakeModel("Primary", types.BoolValue(false))
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if m.SOASerialDateScheme.ValueBool() {
		t.Error("configured false was overwritten")
	}

	m = soaFakeModel("Primary", types.BoolNull())
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if !m.SOASerialDateScheme.Equal(types.BoolValue(true)) {
		t.Errorf("null (import) = %v, want true", m.SOASerialDateScheme)
	}
}

func TestReadZoneState_SOAErrorPropagates(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	f.failPath = "/api/zones/records/get"
	m := soaFakeModel("Primary", types.BoolValue(true))
	if err := f.resource(t).readZoneState(context.Background(), m); err == nil {
		t.Fatal("expected error when the SOA read fails")
	}
}
func zoneSchema(t *testing.T, r *ZoneResource) resource.SchemaResponse {
	t.Helper()
	var s resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &s)
	return s
}

func runZoneCreate(t *testing.T, r *ZoneResource, plan *ZoneResourceModel) *resource.CreateResponse {
	t.Helper()
	s := zoneSchema(t, r)
	p := tfsdk.Plan{Schema: s.Schema}
	if d := p.Set(context.Background(), plan); d.HasError() {
		t.Fatalf("plan.Set: %v", d)
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: p}, resp)
	return resp
}

func runZoneUpdate(t *testing.T, r *ZoneResource, prior, plan *ZoneResourceModel) *resource.UpdateResponse {
	t.Helper()
	s := zoneSchema(t, r)
	p := tfsdk.Plan{Schema: s.Schema}
	if d := p.Set(context.Background(), plan); d.HasError() {
		t.Fatalf("plan.Set: %v", d)
	}
	st := tfsdk.State{Schema: s.Schema}
	if d := st.Set(context.Background(), prior); d.HasError() {
		t.Fatalf("state.Set: %v", d)
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Update(context.Background(), resource.UpdateRequest{Plan: p, State: st}, resp)
	return resp
}

func stateScheme(t *testing.T, st tfsdk.State) types.Bool {
	t.Helper()
	var m ZoneResourceModel
	if d := st.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("state.Get: %v", d)
	}
	return m.SOASerialDateScheme
}

func TestZoneCreate_ForwarderAppliesScheme(t *testing.T) {
	f := newZoneSOAFake(t, "Forwarder", false)
	resp := runZoneCreate(t, f.resource(t), soaFakeModel("Forwarder", types.BoolValue(true)))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}
	if !f.scheme || f.soaUpdates != 1 {
		t.Fatalf("server scheme = %t after %d updates, want true after 1", f.scheme, f.soaUpdates)
	}
	if !stateScheme(t, resp.State).ValueBool() {
		t.Fatal("state scheme = false, want true")
	}
}

func TestZoneCreate_PrimaryNoSOAWriteWhenCreateFlagTookEffect(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	resp := runZoneCreate(t, f.resource(t), soaFakeModel("Primary", types.BoolValue(true)))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}
	if f.createParams.Get("useSoaSerialDateScheme") != "true" || f.soaUpdates != 0 {
		t.Fatalf("create flag = %q, SOA updates = %d; want true, 0", f.createParams.Get("useSoaSerialDateScheme"), f.soaUpdates)
	}
}

func TestZoneCreate_LateFailurePersistsState(t *testing.T) {
	f := newZoneSOAFake(t, "Forwarder", false)
	f.failPath = "/api/zones/records/update"
	resp := runZoneCreate(t, f.resource(t), soaFakeModel("Forwarder", types.BoolValue(true)))
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error from the failed SOA update")
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("zone exists on the server but was left out of state")
	}
	if stateScheme(t, resp.State).ValueBool() {
		t.Fatal("persisted state must reflect the server (false)")
	}
}

func TestZoneUpdate_AppliesChangedScheme(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	resp := runZoneUpdate(t, f.resource(t),
		soaFakeModel("Primary", types.BoolValue(false)),
		soaFakeModel("Primary", types.BoolValue(true)))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}
	if !f.scheme || f.soaUpdates != 1 || !stateScheme(t, resp.State).ValueBool() {
		t.Fatalf("server = %t, updates = %d, state = %v", f.scheme, f.soaUpdates, stateScheme(t, resp.State))
	}
}

func TestZoneUpdate_UnchangedSchemeSendsNoSOAUpdate(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	resp := runZoneUpdate(t, f.resource(t),
		soaFakeModel("Primary", types.BoolValue(true)),
		soaFakeModel("Primary", types.BoolValue(true)))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}
	if f.soaUpdates != 0 {
		t.Fatalf("SOA updates = %d with plan equal to prior state, want 0", f.soaUpdates)
	}
	if stateScheme(t, resp.State).ValueBool() {
		t.Fatal("read-back must report the stale server value (false)")
	}
}

func TestZoneUpdate_SecondaryNeverWritesSOA(t *testing.T) {
	f := newZoneSOAFake(t, "Secondary", true)
	resp := runZoneUpdate(t, f.resource(t),
		soaFakeModel("Secondary", types.BoolValue(true)),
		soaFakeModel("Secondary", types.BoolValue(false)))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}
	if f.soaUpdates != 0 {
		t.Fatalf("SOA updates = %d on a Secondary zone, want 0", f.soaUpdates)
	}
}
func runZoneModifyPlan(t *testing.T, r *ZoneResource, cfg *ZoneResourceModel) *resource.ModifyPlanResponse {
	t.Helper()
	s := zoneSchema(t, r)
	st := tfsdk.State{Schema: s.Schema}
	if d := st.Set(context.Background(), cfg); d.HasError() {
		t.Fatalf("set: %v", d)
	}
	config := tfsdk.Config{Schema: s.Schema, Raw: st.Raw}
	plan := tfsdk.Plan{Schema: s.Schema, Raw: st.Raw}
	resp := &resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(context.Background(), resource.ModifyPlanRequest{Config: config, Plan: plan, State: tfsdk.State{Schema: s.Schema}}, resp)
	return resp
}

func TestZoneModifyPlan_WarnsOnUnmanagedExplicitFalse(t *testing.T) {
	r := &ZoneResource{}
	cases := []struct {
		zoneType string
		scheme   types.Bool
		warn     bool
	}{
		{"Secondary", types.BoolValue(false), true},
		{"Stub", types.BoolValue(false), true},
		{"Secondary", types.BoolValue(true), false},
		{"Stub", types.BoolNull(), false},
		{"Primary", types.BoolValue(false), false},
		{"Forwarder", types.BoolValue(false), false},
	}
	for _, c := range cases {
		resp := runZoneModifyPlan(t, r, soaFakeModel(c.zoneType, c.scheme))
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s/%v: %v", c.zoneType, c.scheme, resp.Diagnostics)
		}
		if got := resp.Diagnostics.WarningsCount() > 0; got != c.warn {
			t.Errorf("%s/%v: warning = %t, want %t", c.zoneType, c.scheme, got, c.warn)
		}
	}
}
