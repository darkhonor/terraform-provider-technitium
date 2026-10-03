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

func runForwardersModifier(t *testing.T, cfg, plan ServerSettingsResourceModel, state *ServerSettingsResourceModel) *planmodifier.ListResponse {
	t.Helper()
	config, p, st := newForwardersFixture(t, cfg, plan, state)
	stateValue := types.ListNull(types.StringType)
	if state != nil {
		stateValue = state.Forwarders
	}
	req := planmodifier.ListRequest{
		Path: path.Root("forwarders"), Config: config, Plan: p, State: st,
		ConfigValue: cfg.Forwarders, PlanValue: plan.Forwarders, StateValue: stateValue,
	}
	resp := &planmodifier.ListResponse{PlanValue: req.PlanValue}
	canonicalForwardersModifier{}.PlanModifyList(context.Background(), req, resp)
	return resp
}

func listStrings(t *testing.T, l types.List) []string {
	t.Helper()
	var out []string
	if d := l.ElementsAs(context.Background(), &out, false); d.HasError() {
		t.Fatal(d)
	}
	return out
}

func TestCanonicalForwardersModifier_PlansCanonicalList(t *testing.T) {
	cfg := settingsModel(stringList(t, "1.1.1.1", "9.9.9.9"), types.StringValue("Tls"))
	resp := runForwardersModifier(t, cfg, cfg, nil)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if got := strings.Join(listStrings(t, resp.PlanValue), ","); got != "1.1.1.1:853,9.9.9.9:853" {
		t.Errorf("plan = %s", got)
	}
}

func TestCanonicalForwardersModifier_ConfigNullPlansPriorState(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringNull())
	plan := settingsModel(types.ListNull(types.StringType), types.StringValue("Udp"))
	prior := settingsModel(stringList(t, "1.1.1.1:853"), types.StringValue("Tls"))
	resp := runForwardersModifier(t, cfg, plan, &prior)
	if got := strings.Join(listStrings(t, resp.PlanValue), ","); got != "1.1.1.1:853" {
		t.Errorf("plan = %s, want prior state", got)
	}
}

func TestCanonicalForwardersModifier_ConfigNullNoStateIsUnknown(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringNull())
	plan := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	if resp := runForwardersModifier(t, cfg, plan, nil); !resp.PlanValue.IsUnknown() {
		t.Errorf("plan = %v, want unknown", resp.PlanValue)
	}
}

func TestCanonicalForwardersModifier_UnknownProtocolIsUnknown(t *testing.T) {
	cfg := settingsModel(stringList(t, "1.1.1.1"), types.StringUnknown())
	if resp := runForwardersModifier(t, cfg, cfg, nil); !resp.PlanValue.IsUnknown() {
		t.Errorf("plan = %v, want unknown", resp.PlanValue)
	}
}

func TestCanonicalForwardersModifier_UnknownElementIsUnknown(t *testing.T) {
	l, _ := types.ListValue(types.StringType, []attr.Value{types.StringValue("1.1.1.1"), types.StringUnknown()})
	cfg := settingsModel(l, types.StringValue("Tls"))
	if resp := runForwardersModifier(t, cfg, cfg, nil); !resp.PlanValue.IsUnknown() {
		t.Errorf("plan = %v, want unknown", resp.PlanValue)
	}
}

func TestCanonicalForwardersModifier_LossyInputIsError(t *testing.T) {
	cfg := settingsModel(stringList(t, "9.9.9.9", "1.1.1.1:53"), types.StringValue("Tls"))
	resp := runForwardersModifier(t, cfg, cfg, nil)
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

func TestForwarderProtocolModifier_UnsetFollowsPriorState(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringNull())
	plan := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	prior := settingsModel(stringList(t, "1.1.1.1"), types.StringValue("Udp"))
	if resp := runProtocolModifier(t, cfg, plan, &prior); resp.PlanValue.ValueString() != "Udp" {
		t.Errorf("plan = %v, want prior Udp", resp.PlanValue)
	}
	if resp := runProtocolModifier(t, cfg, plan, nil); !resp.PlanValue.IsUnknown() {
		t.Errorf("create plan = %v, want unknown", resp.PlanValue)
	}
}

func TestForwarderProtocolModifier_SetWithoutForwardersWarns(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	prior := settingsModel(stringList(t), types.StringValue("Tls"))
	for name, st := range map[string]*ServerSettingsResourceModel{"no prior state": nil, "no server forwarders": &prior} {
		resp := runProtocolModifier(t, cfg, cfg, st)
		if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
			t.Errorf("%s: diagnostics = %v, want one warning", name, resp.Diagnostics)
		}
		if resp.PlanValue.ValueString() != "Tls" {
			t.Errorf("%s: plan = %v", name, resp.PlanValue)
		}
	}
}

func TestForwarderProtocolModifier_SetWithoutForwardersConflictIsError(t *testing.T) {
	cfg := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	prior := settingsModel(stringList(t, "1.1.1.1"), types.StringValue("Udp"))
	if resp := runProtocolModifier(t, cfg, cfg, &prior); !resp.Diagnostics.HasError() {
		t.Error("expected an error when the server's forwarders use a different protocol")
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

func TestServerSettingsUpdate_StaleForwardersIsClearError(t *testing.T) {
	ctx := context.Background()
	r := &ServerSettingsResource{client: newTestClient(t, settingsServer(t, []string{"1.1.1.1"}, "Udp"))}
	cfg := settingsModel(types.ListNull(types.StringType), types.StringNull())
	plan := settingsModel(stringList(t), types.StringValue("Tls"))
	plan.ID = types.StringValue("server-settings")
	prior := plan
	config, p, st := newForwardersFixture(t, cfg, plan, &prior)
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: p.Schema}}
	r.Update(ctx, resource.UpdateRequest{Config: config, Plan: p, State: st}, resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "forwarder") {
		t.Fatalf("diagnostics = %v, want a clear forwarder error", resp.Diagnostics)
	}
}

func TestServerSettingsCreate_ServerForwardersProtocolMismatchIsClearError(t *testing.T) {
	ctx := context.Background()
	r := &ServerSettingsResource{client: newTestClient(t, settingsServer(t, []string{"1.1.1.1"}, "Udp"))}
	cfg := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	config, p, _ := newForwardersFixture(t, cfg, cfg, nil)
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: p.Schema}}
	r.Create(ctx, resource.CreateRequest{Config: config, Plan: p}, resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "forwarder") {
		t.Fatalf("diagnostics = %v, want a clear forwarder error", resp.Diagnostics)
	}
}

func TestReadState_ForwardersAlwaysFromServer(t *testing.T) {
	ctx := context.Background()
	r := &ServerSettingsResource{client: newTestClient(t, settingsServer(t, nil, "Tls"))}
	m := settingsModel(types.ListNull(types.StringType), types.StringValue("Tls"))
	if err := r.readState(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if m.Forwarders.IsNull() || len(m.Forwarders.Elements()) != 0 {
		t.Errorf("forwarders = %v, want empty list from server", m.Forwarders)
	}
}
