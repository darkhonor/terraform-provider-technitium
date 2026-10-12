// Copyright (c) 2026 Tristan Milnthorp
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func primariesList(t *testing.T, vals ...string) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), types.StringType, vals)
	if d.HasError() {
		t.Fatalf("ListValueFrom: %v", d)
	}
	return l
}

func primariesStrings(t *testing.T, l types.List) []string {
	t.Helper()
	var out []string
	if d := l.ElementsAs(context.Background(), &out, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	return out
}

// primariesModel is a create-time model for a zone of the given type.
func primariesModel(zoneType string, addrs types.List, proto types.String) *ZoneResourceModel {
	m := soaFakeModel(zoneType, types.BoolNull())
	m.PrimaryNameServerAddresses = addrs
	m.ZoneTransferProtocol = proto
	m.PrimaryZoneTransferTsigKeyName = types.StringNull()
	return m
}

// --- normalisation -----------------------------------------------------------

// Values below are the forms a running Technitium 15.x echoes back from
// zones/options/get after being given the bare address.
func TestSamePrimaryAddresses_ServerNormalisation(t *testing.T) {
	cases := []struct {
		name     string
		cfg, srv []string
		protocol string
		want     bool
	}{
		{"tcp bare", []string{"10.0.0.1"}, []string{"10.0.0.1"}, "Tcp", true},
		{"tls default port appended", []string{"10.0.0.1"}, []string{"10.0.0.1:853"}, "Tls", true},
		{"quic default port appended", []string{"10.0.0.1"}, []string{"10.0.0.1:853"}, "Quic", true},
		{"explicit default port", []string{"10.0.0.1:853"}, []string{"10.0.0.1:853"}, "Tls", true},
		{"tcp explicit 53", []string{"10.0.0.1:53"}, []string{"10.0.0.1"}, "Tcp", true},
		{"ipv6 gets brackets", []string{"2001:db8::1"}, []string{"[2001:db8::1]"}, "Tcp", true},
		{"ipv6 tls", []string{"2001:db8::1"}, []string{"[2001:db8::1]:853"}, "Tls", true},
		{"hostname case", []string{"DNS01.example.com"}, []string{"dns01.example.com"}, "Tcp", true},
		{"custom port kept", []string{"10.0.0.1:5353"}, []string{"10.0.0.1:5353"}, "Tcp", true},
		{"different port is drift", []string{"10.0.0.1"}, []string{"10.0.0.1:5353"}, "Tcp", false},
		{"different host is drift", []string{"10.0.0.1"}, []string{"10.0.0.2"}, "Tcp", false},
		{"order matters", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.2", "10.0.0.1"}, "Tcp", false},
		{"length differs", []string{"10.0.0.1"}, []string{"10.0.0.1", "10.0.0.2"}, "Tcp", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := samePrimaryAddresses(c.cfg, c.srv, c.protocol); got != c.want {
				t.Fatalf("samePrimaryAddresses(%v, %v, %s) = %t, want %t", c.cfg, c.srv, c.protocol, got, c.want)
			}
		})
	}
}

func TestResolvePrimaryAddresses(t *testing.T) {
	ctx := context.Background()

	// Equivalent to the server's value: the configured spelling is kept, so
	// there is no diff against the configuration.
	got := resolvePrimaryAddresses(ctx, primariesList(t, "10.0.0.1"), []string{"10.0.0.1:853"}, "Tls")
	if v := primariesStrings(t, got); len(v) != 1 || v[0] != "10.0.0.1" {
		t.Fatalf("equivalent value must keep the configured spelling, got %v", v)
	}

	// Real drift: the server's value wins.
	got = resolvePrimaryAddresses(ctx, primariesList(t, "10.0.0.1"), []string{"10.0.0.9:853"}, "Tls")
	if v := primariesStrings(t, got); len(v) != 1 || v[0] != "10.0.0.9:853" {
		t.Fatalf("drifted value must come from the server, got %v", v)
	}

	// Import: no prior value, so the server's value populates state.
	got = resolvePrimaryAddresses(ctx, types.ListNull(types.StringType), []string{"10.0.0.1"}, "Tcp")
	if v := primariesStrings(t, got); len(v) != 1 || v[0] != "10.0.0.1" {
		t.Fatalf("import must take the server value, got %v", v)
	}

	// Nothing reported: null, never an empty list.
	got = resolvePrimaryAddresses(ctx, primariesList(t, "10.0.0.1"), nil, "Tcp")
	if !got.IsNull() {
		t.Fatalf("no server addresses must read back null, got %v", got)
	}
}

func TestZoneTypeHelpers(t *testing.T) {
	for zt, want := range map[string][2]bool{ // {takes addresses, takes protocol}
		"Secondary":          {true, true},
		"SecondaryForwarder": {true, true},
		"SecondaryCatalog":   {true, true},
		"Stub":               {true, false},
		"Primary":            {false, false},
		"Forwarder":          {false, false},
		"Catalog":            {false, false},
	} {
		if got := takesPrimaryNameServers(zt); got != want[0] {
			t.Errorf("takesPrimaryNameServers(%s) = %t, want %t", zt, got, want[0])
		}
		if got := isSecondaryFamilyZoneType(zt); got != want[1] {
			t.Errorf("isSecondaryFamilyZoneType(%s) = %t, want %t", zt, got, want[1])
		}
	}
}

// --- schema ------------------------------------------------------------------

func TestZoneSchema_PrimaryNameServerAttributes(t *testing.T) {
	s := zoneSchema(t, &ZoneResource{}).Schema
	for _, name := range []string{"primary_name_server_addresses", "zone_transfer_protocol"} {
		a, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("attribute %q missing", name)
		}
		// Additive and not required: existing configurations keep working.
		if a.IsRequired() || !a.IsOptional() {
			t.Errorf("%s must be optional, not required", name)
		}
		// Computed so a Secondary's server-reported values never produce
		// "inconsistent result after apply" when the operator omits them.
		if !a.IsComputed() {
			t.Errorf("%s must be computed", name)
		}
	}
}

// --- ModifyPlan: plan-time validation ---------------------------------------

func hasErrorSummary(resp *resource.ModifyPlanResponse, summary string) bool {
	for _, d := range resp.Diagnostics.Errors() {
		if d.Summary() == summary {
			return true
		}
	}
	return false
}

func hasWarningSummary(resp *resource.ModifyPlanResponse, substr string) bool {
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), substr) {
			return true
		}
	}
	return false
}

func TestZoneModifyPlan_PrimaryAddressesRejectedOnNonTransferTypes(t *testing.T) {
	for _, zt := range []string{"Primary", "Forwarder", "Catalog"} {
		t.Run(zt, func(t *testing.T) {
			resp := runZoneModifyPlan(t, &ZoneResource{},
				primariesModel(zt, primariesList(t, "10.0.0.1"), types.StringNull()))
			if !hasErrorSummary(resp, "Invalid zone type for primary_name_server_addresses") {
				t.Fatalf("expected an error for %s, got: %v", zt, resp.Diagnostics)
			}
		})
	}
}

func TestZoneModifyPlan_PrimaryAddressesAcceptedOnTransferTypes(t *testing.T) {
	for _, zt := range []string{"Secondary", "SecondaryForwarder", "SecondaryCatalog", "Stub"} {
		t.Run(zt, func(t *testing.T) {
			resp := runZoneModifyPlan(t, &ZoneResource{},
				primariesModel(zt, primariesList(t, "10.0.0.1"), types.StringNull()))
			if hasErrorSummary(resp, "Invalid zone type for primary_name_server_addresses") {
				t.Fatalf("addresses must be accepted on %s, got: %v", zt, resp.Diagnostics)
			}
			if hasWarningSummary(resp, "No primary name servers") {
				t.Fatalf("no missing-primaries warning expected when addresses are set on %s", zt)
			}
		})
	}
}

func TestZoneModifyPlan_ProtocolOnlyOnSecondaryFamily(t *testing.T) {
	for zt, ok := range map[string]bool{
		"Secondary": true, "SecondaryForwarder": true, "SecondaryCatalog": true,
		"Stub": false, "Primary": false, "Forwarder": false, "Catalog": false,
	} {
		t.Run(zt, func(t *testing.T) {
			resp := runZoneModifyPlan(t, &ZoneResource{},
				primariesModel(zt, types.ListNull(types.StringType), types.StringValue("Tls")))
			got := hasErrorSummary(resp, "Invalid zone type for zone_transfer_protocol")
			if got == ok {
				t.Fatalf("%s: protocol error = %t, want %t (%v)", zt, got, !ok, resp.Diagnostics)
			}
		})
	}
}

// A Secondary with no primary can never load. It warns rather than errors
// because the API documents the parameter as optional (the server then tries
// to discover the primary itself), which works for publicly resolvable zones.
func TestZoneModifyPlan_SecondaryWithoutPrimariesWarnsOnCreate(t *testing.T) {
	for _, zt := range []string{"Secondary", "SecondaryForwarder", "SecondaryCatalog", "Stub"} {
		resp := runZoneModifyPlan(t, &ZoneResource{},
			primariesModel(zt, types.ListNull(types.StringType), types.StringNull()))
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s without primaries must not be an error: %v", zt, resp.Diagnostics)
		}
		if !hasWarningSummary(resp, "No primary name servers") {
			t.Errorf("%s without primaries should warn, got: %v", zt, resp.Diagnostics)
		}
	}
	for _, zt := range []string{"Primary", "Forwarder"} {
		resp := runZoneModifyPlan(t, &ZoneResource{},
			primariesModel(zt, types.ListNull(types.StringType), types.StringNull()))
		if hasWarningSummary(resp, "No primary name servers") {
			t.Errorf("%s must not warn about primaries", zt)
		}
	}
}

// --- request building and read-back -----------------------------------------

type primariesFake struct {
	mu           sync.Mutex
	zoneType     string
	addrs        []string
	protocol     string
	tsig         string
	createParams url.Values
	setParams    []url.Values
	srv          *httptest.Server
}

// newPrimariesFake mimics the server behaviours verified against a running
// Technitium: the first transfer happens in zones/create, options/set takes
// primaryZoneTransferProtocol, and the echoed addresses carry the protocol's
// default port.
func newPrimariesFake(t *testing.T, zoneType string) *primariesFake {
	t.Helper()
	f := &primariesFake{zoneType: zoneType}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/api/zones/create":
			f.createParams = r.PostForm
			f.addrs = splitNonEmpty(r.PostForm.Get("primaryNameServerAddresses"))
			f.protocol = r.PostForm.Get("zoneTransferProtocol")
			f.tsig = r.PostForm.Get("tsigKeyName")
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{"domain":"home.example.com"}}`)
		case "/api/zones/options/set":
			f.setParams = append(f.setParams, r.PostForm)
			if v := r.PostForm.Get("primaryNameServerAddresses"); v != "" {
				f.addrs = splitNonEmpty(v)
			}
			if v := r.PostForm.Get("primaryZoneTransferProtocol"); v != "" {
				f.protocol = v
			}
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/zones/options/get":
			echoed := make([]string, 0, len(f.addrs))
			for _, a := range f.addrs {
				if (f.protocol == "Tls" || f.protocol == "Quic") && !strings.Contains(a, ":") {
					a += ":853"
				}
				echoed = append(echoed, fmt.Sprintf("%q", a))
			}
			proto := f.protocol
			if proto == "" {
				proto = "Tcp"
			}
			body := fmt.Sprintf(`"name":"home.example.com","type":%q,"disabled":false,"dnssecStatus":"Unsigned"`, f.zoneType)
			if f.zoneType != "Primary" {
				body += fmt.Sprintf(`,"primaryNameServerAddresses":[%s]`, strings.Join(echoed, ","))
				if f.zoneType != "Stub" {
					body += fmt.Sprintf(`,"primaryZoneTransferProtocol":%q,"primaryZoneTransferTsigKeyName":%q`, proto, f.tsig)
				}
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{%s}}`, body)
		case "/api/zones/list":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{"zones":[{"name":"home.example.com","soaSerial":7}]}}`)
		case "/api/zones/records/get": // SOA read for Primary zones
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
				"primaryNameServer":"ns1.example.com","responsiblePerson":"hostadmin@example.com",
				"serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900,"useSerialDateScheme":true}}]}}`)
		case "/api/zones/records/update":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"unexpected"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func (f *primariesFake) resource(t *testing.T) *ZoneResource {
	t.Helper()
	c, err := client.NewClient(client.ClientConfig{BaseURL: f.srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &ZoneResource{client: c}
}

func planFor(zoneType string, addrs types.List, proto types.String) *ZoneResourceModel {
	m := primariesModel(zoneType, addrs, proto)
	m.Name = types.StringValue("home.example.com")
	return m
}

func TestZoneCreate_SecondarySendsPrimariesOnCreate(t *testing.T) {
	f := newPrimariesFake(t, "Secondary")
	plan := planFor("Secondary", primariesList(t, "10.0.10.12", "10.0.10.13"), types.StringValue("Tls"))
	plan.PrimaryZoneTransferTsigKeyName = types.StringNull() // key validation needs a server; covered by acceptance
	resp := runZoneCreate(t, f.resource(t), plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("create: %v", resp.Diagnostics)
	}
	want := map[string]string{
		"type":                       "Secondary",
		"primaryNameServerAddresses": "10.0.10.12,10.0.10.13",
		"zoneTransferProtocol":       "Tls",
	}
	for k, v := range want {
		if f.createParams.Get(k) != v {
			t.Errorf("create param %q = %q, want %q (%v)", k, f.createParams.Get(k), v, f.createParams)
		}
	}

	// The server echoes "10.0.10.12:853"; state must keep the configured value
	// so a re-plan is empty.
	var got ZoneResourceModel
	if d := resp.State.Get(context.Background(), &got); d.HasError() {
		t.Fatalf("state: %v", d)
	}
	if v := primariesStrings(t, got.PrimaryNameServerAddresses); len(v) != 2 || v[0] != "10.0.10.12" || v[1] != "10.0.10.13" {
		t.Errorf("state addresses = %v, want the configured values", v)
	}
	if got.ZoneTransferProtocol.ValueString() != "Tls" {
		t.Errorf("state protocol = %q, want Tls", got.ZoneTransferProtocol.ValueString())
	}
}

func TestZoneCreate_UnsetProtocolReadsServerDefault(t *testing.T) {
	f := newPrimariesFake(t, "Secondary")
	plan := planFor("Secondary", primariesList(t, "10.0.10.12"), types.StringUnknown())
	resp := runZoneCreate(t, f.resource(t), plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("create: %v", resp.Diagnostics)
	}
	if f.createParams.Has("zoneTransferProtocol") {
		t.Errorf("unset protocol must not be sent on create: %v", f.createParams)
	}
	var got ZoneResourceModel
	resp.State.Get(context.Background(), &got)
	if got.ZoneTransferProtocol.ValueString() != "Tcp" {
		t.Errorf("state protocol = %q, want the server default Tcp", got.ZoneTransferProtocol.ValueString())
	}
}

func TestZoneCreate_PrimaryZoneSendsNothingAndReadsNull(t *testing.T) {
	f := newPrimariesFake(t, "Primary")
	plan := planFor("Primary", types.ListUnknown(types.StringType), types.StringUnknown())
	resp := runZoneCreate(t, f.resource(t), plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("create: %v", resp.Diagnostics)
	}
	for _, k := range []string{"primaryNameServerAddresses", "zoneTransferProtocol", "tsigKeyName"} {
		if f.createParams.Has(k) {
			t.Errorf("Primary create must not send %q: %v", k, f.createParams)
		}
	}
	for _, p := range f.setParams {
		if p.Has("primaryNameServerAddresses") || p.Has("primaryZoneTransferProtocol") {
			t.Errorf("Primary options/set must not carry primaries or protocol: %v", p)
		}
	}
	var got ZoneResourceModel
	resp.State.Get(context.Background(), &got)
	if !got.PrimaryNameServerAddresses.IsNull() || !got.ZoneTransferProtocol.IsNull() {
		t.Errorf("Primary zone must read back null (no perpetual diff): %v / %v",
			got.PrimaryNameServerAddresses, got.ZoneTransferProtocol)
	}
}

func TestZoneUpdate_SendsPrimariesAndProtocolViaOptionsSet(t *testing.T) {
	f := newPrimariesFake(t, "Secondary")
	f.addrs = []string{"10.0.10.12"}
	f.protocol = "Tcp"
	r := f.resource(t)

	prior := planFor("Secondary", primariesList(t, "10.0.10.12"), types.StringValue("Tcp"))
	plan := planFor("Secondary", primariesList(t, "10.0.10.12", "10.0.10.13"), types.StringValue("Quic"))
	resp := runZoneUpdate(t, r, prior, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}

	var sent url.Values
	for _, p := range f.setParams {
		if p.Has("primaryNameServerAddresses") {
			sent = p
		}
	}
	if sent == nil {
		t.Fatalf("update never sent primaryNameServerAddresses: %v", f.setParams)
	}
	if sent.Get("primaryNameServerAddresses") != "10.0.10.12,10.0.10.13" {
		t.Errorf("addresses = %q", sent.Get("primaryNameServerAddresses"))
	}
	// options/set spells it primaryZoneTransferProtocol, not zoneTransferProtocol.
	if sent.Get("primaryZoneTransferProtocol") != "Quic" {
		t.Errorf("primaryZoneTransferProtocol = %q, want Quic (%v)", sent.Get("primaryZoneTransferProtocol"), sent)
	}
	if sent.Has("zoneTransferProtocol") {
		t.Errorf("options/set must not use the create-only name zoneTransferProtocol: %v", sent)
	}
}

// Importing a zone has no prior state: the server's values populate it, which
// is what makes ImportStateVerify and adoption of an existing secondary work.
func TestReadZoneState_ImportPopulatesFromServer(t *testing.T) {
	f := newPrimariesFake(t, "Secondary")
	f.addrs = []string{"10.0.10.12"}
	f.protocol = "Tls"
	r := f.resource(t)

	m := planFor("Secondary", types.ListNull(types.StringType), types.StringNull())
	m.SOASerial = types.Int64Null()
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if v := primariesStrings(t, m.PrimaryNameServerAddresses); len(v) != 1 || v[0] != "10.0.10.12:853" {
		t.Errorf("imported addresses = %v, want the server's spelling", v)
	}
	if m.ZoneTransferProtocol.ValueString() != "Tls" {
		t.Errorf("imported protocol = %q", m.ZoneTransferProtocol.ValueString())
	}
}

func TestReadZoneState_StubHasAddressesButNoProtocol(t *testing.T) {
	f := newPrimariesFake(t, "Stub")
	f.addrs = []string{"10.0.10.12"}
	r := f.resource(t)

	m := planFor("Stub", types.ListNull(types.StringType), types.StringNull())
	m.SOASerial = types.Int64Null()
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if m.PrimaryNameServerAddresses.IsNull() {
		t.Error("a Stub zone's primaries must be read back")
	}
	if !m.ZoneTransferProtocol.IsNull() {
		t.Errorf("a Stub zone has no transfer protocol, got %q", m.ZoneTransferProtocol.ValueString())
	}
}

// The plan modifier must null the computed attributes on types that do not
// take them, rather than leave "(known after apply)" on every Primary plan.
func TestZoneModifyPlan_NonTransferTypeNullsComputedAttributes(t *testing.T) {
	ctx := context.Background()
	r := &ZoneResource{}
	s := zoneSchema(t, r)

	cfg := primariesModel("Primary", types.ListNull(types.StringType), types.StringNull())
	st := tfsdk.State{Schema: s.Schema}
	if d := st.Set(ctx, cfg); d.HasError() {
		t.Fatalf("set: %v", d)
	}
	planModel := primariesModel("Primary", types.ListUnknown(types.StringType), types.StringUnknown())
	plan := tfsdk.Plan{Schema: s.Schema}
	if d := plan.Set(ctx, planModel); d.HasError() {
		t.Fatalf("plan set: %v", d)
	}
	resp := &resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{
		Config: tfsdk.Config{Schema: s.Schema, Raw: st.Raw},
		Plan:   plan,
		State:  tfsdk.State{Schema: s.Schema},
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan: %v", resp.Diagnostics)
	}
	var out ZoneResourceModel
	if d := resp.Plan.Get(ctx, &out); d.HasError() {
		t.Fatalf("plan get: %v", d)
	}
	if !out.PrimaryNameServerAddresses.IsNull() || !out.ZoneTransferProtocol.IsNull() {
		t.Errorf("Primary plan must carry null, got %v / %v", out.PrimaryNameServerAddresses, out.ZoneTransferProtocol)
	}
}
