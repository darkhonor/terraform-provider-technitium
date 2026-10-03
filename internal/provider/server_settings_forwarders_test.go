// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func settingsSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	(&ServerSettingsResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	return resp
}

func settingsModel(forwarders types.List, protocol types.String) ServerSettingsResourceModel {
	null := types.ListNull(types.StringType)
	return ServerSettingsResourceModel{
		RecursionNetworkACL:         null,
		BlockingBypassList:          null,
		CustomBlockingAddresses:     null,
		BlockListUrls:               null,
		Forwarders:                  forwarders,
		ZoneTransferAllowedNetworks: null,
		NotifyAllowedNetworks:       null,
		WebServiceLocalAddresses:    null,
		ForwarderProtocol:           protocol,
	}
}

func stringList(t *testing.T, v ...string) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), types.StringType, v)
	if d.HasError() {
		t.Fatal(d)
	}
	return l
}

func newForwardersFixture(t *testing.T, cfg, plan ServerSettingsResourceModel, state *ServerSettingsResourceModel) (tfsdk.Config, tfsdk.Plan, tfsdk.State) {
	t.Helper()
	ctx := context.Background()
	s := settingsSchema(t).Schema
	c := tfsdk.Plan{Schema: s}
	if d := c.Set(ctx, &cfg); d.HasError() {
		t.Fatal(d)
	}
	p := tfsdk.Plan{Schema: s}
	if d := p.Set(ctx, &plan); d.HasError() {
		t.Fatal(d)
	}
	st := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if state != nil {
		if d := st.Set(ctx, state); d.HasError() {
			t.Fatal(d)
		}
	}
	return tfsdk.Config{Schema: s, Raw: c.Raw}, p, st
}

func runForwardersValidator(t *testing.T, cfg ServerSettingsResourceModel) *validator.ListResponse {
	t.Helper()
	config, _, _ := newForwardersFixture(t, cfg, cfg, nil)
	req := validator.ListRequest{Path: path.Root("forwarders"), Config: config, ConfigValue: cfg.Forwarders}
	resp := &validator.ListResponse{}
	forwardersValidator{}.ValidateList(context.Background(), req, resp)
	return resp
}

func TestForwardersValidator_LossyInputIsErrorAtIndex(t *testing.T) {
	resp := runForwardersValidator(t, settingsModel(stringList(t, "9.9.9.9", "1.1.1.1:53"), types.StringValue("Tls")))
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error")
	}
	d := resp.Diagnostics.Errors()[0]
	withPath, ok := d.(interface{ Path() path.Path })
	if !ok || !withPath.Path().Equal(path.Root("forwarders").AtListIndex(1)) {
		t.Errorf("diagnostic not attached to forwarders[1]: %v", d)
	}
	if !strings.Contains(d.Detail(), "port 53") {
		t.Errorf("detail = %q", d.Detail())
	}
}

func TestForwardersValidator_NullProtocolUsesTlsDefault(t *testing.T) {
	if resp := runForwardersValidator(t, settingsModel(stringList(t, "1.1.1.1:53"), types.StringNull())); !resp.Diagnostics.HasError() {
		t.Error("expected the Tls default to reject port 53")
	}
}

func TestForwardersValidator_AcceptsValidAndSkipsUnknown(t *testing.T) {
	if resp := runForwardersValidator(t, settingsModel(stringList(t, "1.1.1.1", "dns.example.test:853"), types.StringValue("Tls"))); resp.Diagnostics.HasError() {
		t.Errorf("unexpected: %v", resp.Diagnostics)
	}
	if resp := runForwardersValidator(t, settingsModel(stringList(t, "1.1.1.1:53"), types.StringUnknown())); resp.Diagnostics.HasError() {
		t.Errorf("unknown protocol must not be validated: %v", resp.Diagnostics)
	}
	l, _ := types.ListValue(types.StringType, []attr.Value{types.StringValue("1.1.1.1"), types.StringUnknown()})
	if resp := runForwardersValidator(t, settingsModel(l, types.StringValue("Tls"))); resp.Diagnostics.HasError() {
		t.Errorf("unknown element must be skipped: %v", resp.Diagnostics)
	}
}

func TestReconcileForwarders_EquivalentServerSpellings(t *testing.T) {
	cases := []struct{ configured, server, protocol string }{
		{"1.1.1.1", "1.1.1.1:53", "Udp"},
		{"dns.example.test", "DNS.Example.Test:853", "Tls"},
		{"tcp://1.1.1.1", "tcp://1.1.1.1", "Tcp"},
		{"tls://1.1.1.1", "tcp://1.1.1.1", "Tcp"},
		{"udp://1.1.1.1:5353", "1.1.1.1:5353", "Tls"},
		{"tcp://1.1.1.1", "1.1.1.1", "Udp"},
		{"udp://1.1.1.1:5353", "https://1.1.1.1:5353/dns-query", "Https"},
		{"dns.example.test:853 ([2606:4700:4700::1111])", "dns.example.test:853 ([2606:4700:4700::1111])", "Tls"},
	}
	for _, tc := range cases {
		got := reconcileForwarders(context.Background(), stringList(t, tc.configured), []string{tc.server}, tc.protocol)
		if g := strings.Join(listStrings(t, got), ","); g != tc.configured {
			t.Errorf("%s %q vs server %q: state = %q, want configured spelling", tc.protocol, tc.configured, tc.server, g)
		}
	}
	if got := reconcileForwarders(context.Background(), stringList(t, "1.1.1.2"), []string{"1.1.1.1:53"}, "Udp"); strings.Join(listStrings(t, got), ",") != "1.1.1.1:53" {
		t.Errorf("a different endpoint must be reported as drift, got %v", got)
	}
}

func TestReconcileForwarders(t *testing.T) {
	configured := stringList(t, "1.1.1.1", "9.9.9.9")
	cases := []struct {
		name   string
		in     types.List
		server []string
		want   []string
		null   bool
	}{
		{"server canonical form keeps configured spelling", configured, []string{"1.1.1.1:853", "9.9.9.9:853"}, []string{"1.1.1.1", "9.9.9.9"}, false},
		{"different server value is drift", configured, []string{"8.8.8.8:853", "9.9.9.9:853"}, []string{"8.8.8.8:853", "9.9.9.9:853"}, false},
		{"different length is drift", configured, []string{"1.1.1.1:853"}, []string{"1.1.1.1:853"}, false},
		{"unmanaged stays null", types.ListNull(types.StringType), []string{"1.1.1.1:853"}, nil, true},
		{"configured element the normalizer rejects takes the server list", stringList(t, "1.1.1.1:53"), []string{"1.1.1.1:853"}, []string{"1.1.1.1:853"}, false},
		{"unknown configured list takes the server list", types.ListUnknown(types.StringType), []string{"1.1.1.1:853"}, []string{"1.1.1.1:853"}, false},
	}
	for _, tc := range cases {
		got := reconcileForwarders(context.Background(), tc.in, tc.server, "Tls")
		if tc.null {
			if !got.IsNull() {
				t.Errorf("%s: got %v, want null", tc.name, got)
			}
			continue
		}
		if g := strings.Join(listStrings(t, got), ","); g != strings.Join(tc.want, ",") {
			t.Errorf("%s: got %s, want %v", tc.name, g, tc.want)
		}
	}
}

func runProtocolModifier(t *testing.T, cfg, plan ServerSettingsResourceModel, state *ServerSettingsResourceModel) *planmodifier.StringResponse {
	t.Helper()
	config, p, st := newForwardersFixture(t, cfg, plan, state)
	stateValue := types.StringNull()
	if state != nil {
		stateValue = state.ForwarderProtocol
	}
	req := planmodifier.StringRequest{
		Path: path.Root("forwarder_protocol"), Config: config, Plan: p, State: st,
		ConfigValue: cfg.ForwarderProtocol, PlanValue: plan.ForwarderProtocol, StateValue: stateValue,
	}
	resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
	forwarderProtocolModifier{}.PlanModifyString(context.Background(), req, resp)
	return resp
}

func TestForwarderProtocolModifier_SetWithoutForwardersWarns(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	resp := runProtocolModifier(t, cfg, cfg, nil)
	if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
		t.Errorf("diagnostics = %v, want one warning", resp.Diagnostics)
	}
	if resp.PlanValue.ValueString() != "Tls" {
		t.Errorf("plan = %v", resp.PlanValue)
	}
}

func TestForwarderProtocolModifier_UnknownConfigIsLeftAlone(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringUnknown())
	resp := runProtocolModifier(t, cfg, cfg, nil)
	if resp.Diagnostics.HasError() || !resp.PlanValue.IsUnknown() {
		t.Errorf("plan = %v diags = %v", resp.PlanValue, resp.Diagnostics)
	}
}

func TestOmitUnmanagedForwarders(t *testing.T) {
	params := map[string]string{"forwarderProtocol": "Udp", "serveStale": "true"}
	omitUnmanagedForwarders(params, types.ListNull(types.StringType))
	if _, ok := params["forwarderProtocol"]; ok {
		t.Error("forwarderProtocol sent while forwarders unmanaged")
	}
	if params["serveStale"] != "true" {
		t.Error("unrelated parameter removed")
	}
	managed := map[string]string{"forwarders": "1.1.1.1:853", "forwarderProtocol": "Tls"}
	omitUnmanagedForwarders(managed, stringList(t, "1.1.1.1"))
	if len(managed) != 2 {
		t.Errorf("managed params changed: %v", managed)
	}
}

func settingsServer(t *testing.T, forwarders []string, protocol string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/settings/set", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
	})
	mux.HandleFunc("/api/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		fw := "[]"
		if len(forwarders) > 0 {
			fw = `["` + strings.Join(forwarders, `","`) + `"]`
		}
		_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"forwarders":%s,"forwarderProtocol":%q}}`, fw, protocol)
	})
	return mux
}

func TestServerSettingsCreate_RejectsLossyForwardersResolvedAtApply(t *testing.T) {
	ctx := context.Background()
	called := false
	mux := settingsServer(t, nil, "Tls")
	mux.HandleFunc("/api/settings/set/", func(http.ResponseWriter, *http.Request) {})
	srv := http.NewServeMux()
	srv.HandleFunc("/api/settings/set", func(w http.ResponseWriter, r *http.Request) {
		called = true
		mux.ServeHTTP(w, r)
	})
	srv.Handle("/", mux)
	r := &ServerSettingsResource{client: newTestClient(t, srv)}
	cfg := settingsModel(stringList(t, "1.1.1.1:53"), types.StringValue("Tls"))
	config, p, _ := newForwardersFixture(t, cfg, cfg, nil)
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: p.Schema}}
	r.Create(ctx, resource.CreateRequest{Config: config, Plan: p}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a forwarder error")
	}
	if called {
		t.Error("settings were sent despite an invalid forwarder")
	}
}

func TestReadState_ForwardersKeepConfiguredSpelling(t *testing.T) {
	ctx := context.Background()
	r := &ServerSettingsResource{client: newTestClient(t, settingsServer(t, []string{"1.1.1.1:853"}, "Tls"))}
	m := settingsModel(stringList(t, "1.1.1.1"), types.StringValue("Tls"))
	if err := r.readState(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(listStrings(t, m.Forwarders), ","); g != "1.1.1.1" {
		t.Errorf("forwarders = %s, want configured spelling", g)
	}
}

func TestReadState_ProtocolFollowsServerOnlyWhileForwardersManaged(t *testing.T) {
	ctx := context.Background()
	r := &ServerSettingsResource{client: newTestClient(t, settingsServer(t, []string{"1.1.1.1"}, "Udp"))}
	unmanaged := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	if err := r.readState(ctx, &unmanaged); err != nil {
		t.Fatal(err)
	}
	if !unmanaged.Forwarders.IsNull() || unmanaged.ForwarderProtocol.ValueString() != "Tls" {
		t.Errorf("unmanaged: forwarders=%v protocol=%v, want null and the planned Tls", unmanaged.Forwarders, unmanaged.ForwarderProtocol)
	}
	managed := settingsModel(stringList(t, "1.1.1.1"), types.StringValue("Tls"))
	if err := r.readState(ctx, &managed); err != nil {
		t.Fatal(err)
	}
	if managed.ForwarderProtocol.ValueString() != "Udp" {
		t.Errorf("managed: protocol = %v, want the server's Udp", managed.ForwarderProtocol)
	}
}

func listStrings(t *testing.T, l types.List) []string {
	t.Helper()
	var out []string
	if d := l.ElementsAs(context.Background(), &out, false); d.HasError() {
		t.Fatal(d)
	}
	return out
}
