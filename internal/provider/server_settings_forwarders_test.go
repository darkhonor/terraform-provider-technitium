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
	prior := settingsModel(types.ListNull(types.StringType), types.StringValue("Udp"))
	for name, st := range map[string]*ServerSettingsResourceModel{"no prior state": nil, "prior state": &prior} {
		resp := runProtocolModifier(t, cfg, cfg, st)
		if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
			t.Errorf("%s: diagnostics = %v, want one warning", name, resp.Diagnostics)
		}
		if resp.PlanValue.ValueString() != "Tls" {
			t.Errorf("%s: plan = %v", name, resp.PlanValue)
		}
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
	params := map[string]string{"forwarders": "1.1.1.1:853", "forwarderProtocol": "Udp", "serveStale": "true"}
	omitUnmanagedForwarders(params, types.ListNull(types.StringType))
	if _, ok := params["forwarders"]; ok {
		t.Error("forwarders sent while unmanaged")
	}
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
