// Copyright (c) 2026 Max Pfeiffer
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
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const policyFakeZone = "example.internal"

// policyObject builds one element of dynamic_update_security_policies.
func policyObject(t *testing.T, keyName, domain types.String, allowedTypes ...string) attr.Value {
	t.Helper()
	typesSet, diags := types.SetValueFrom(context.Background(), types.StringType, allowedTypes)
	if diags.HasError() {
		t.Fatalf("SetValueFrom: %v", diags)
	}
	obj, diags := types.ObjectValue(updateSecurityPolicyAttrTypes, map[string]attr.Value{
		"tsig_key_name": keyName,
		"domain":        domain,
		"allowed_types": typesSet,
	})
	if diags.HasError() {
		t.Fatalf("ObjectValue: %v", diags)
	}
	return obj
}

func policySet(t *testing.T, policies ...attr.Value) types.Set {
	t.Helper()
	set, diags := types.SetValue(updateSecurityPolicyType, policies)
	if diags.HasError() {
		t.Fatalf("SetValue: %v", diags)
	}
	return set
}

func policyFakeModel(zoneType string, policies types.Set) *ZoneResourceModel {
	m := soaFakeModel(zoneType, types.BoolValue(true))
	m.Name = types.StringValue(policyFakeZone)
	m.DynamicUpdateSecurityPolicies = policies
	return m
}

// zonePolicyFake is a Technitium API fake that records the zone options sent
// to /api/zones/options/set and answers /api/zones/options/get with the
// configured policies.
type zonePolicyFake struct {
	mu            sync.Mutex
	setParams     url.Values
	policiesJSON  string
	tsigKeys      []string
	settingsCalls int
	srv           *httptest.Server
}

func newZonePolicyFake(t *testing.T) *zonePolicyFake {
	t.Helper()
	f := &zonePolicyFake{policiesJSON: "[]"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/api/zones/options/set":
			f.setParams = r.PostForm
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/zones/options/get":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"name":%q,"type":"Primary","disabled":false,
				"dnssecStatus":"Unsigned","updateSecurityPolicies":%s}}`, policyFakeZone, f.policiesJSON)
		case "/api/zones/list":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"zones":[{"name":%q,"soaSerial":1}]}}`, policyFakeZone)
		case "/api/zones/records/get":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
				"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
				"serial":1,"refresh":900,"retry":300,"expire":604800,"minimum":900,"useSerialDateScheme":true}}]}}`)
		case "/api/settings/get":
			f.settingsCalls++
			keys := make([]string, 0, len(f.tsigKeys))
			for _, k := range f.tsigKeys {
				keys = append(keys, fmt.Sprintf(`{"keyName":%q,"sharedSecret":"c2VjcmV0","algorithmName":"hmac-sha256"}`, k))
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"tsigKeys":[%s]}}`, strings.Join(keys, ","))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *zonePolicyFake) resource(t *testing.T) *ZoneResource {
	t.Helper()
	c, err := client.NewClient(client.ClientConfig{BaseURL: f.srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &ZoneResource{client: c}
}

func TestUpdateSecurityPolicyPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern interface{ MatchString(string) bool }
		valid   []string
		invalid []string
	}{
		{
			name:    "tsig_key_name",
			pattern: updatePolicyKeyNamePattern,
			valid:   []string{"acme", "cert-manager-whitebox", "key_1.example.internal"},
			invalid: []string{"", "Acme", "key.example.internal.", "key|other", "key name"},
		},
		{
			name:    "domain",
			pattern: updatePolicyDomainPattern,
			valid:   []string{"example.internal", "*.example.internal", "_acme-challenge.www.example.internal"},
			invalid: []string{"", "Example.internal", "example.internal.", "www.*.example.internal", "*", "a|b"},
		},
		{
			name:    "allowed_types",
			pattern: updatePolicyTypePattern,
			valid:   []string{"TXT", "A", "AAAA", "ANY", "TLSA"},
			invalid: []string{"", "txt", "TXT,A", "TXT|A", " TXT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, v := range tt.valid {
				if !tt.pattern.MatchString(v) {
					t.Errorf("%q must be accepted", v)
				}
			}
			for _, v := range tt.invalid {
				if tt.pattern.MatchString(v) {
					t.Errorf("%q must be rejected", v)
				}
			}
		})
	}
}

// The API request must not depend on set iteration order.
func TestUpdateSecurityPoliciesFromSet_SortsPoliciesAndTypes(t *testing.T) {
	set := policySet(t,
		policyObject(t, types.StringValue("key-b"), types.StringValue("example.internal"), "TXT"),
		policyObject(t, types.StringValue("key-a"), types.StringValue("www.example.internal"), "TXT", "AAAA", "A"),
		policyObject(t, types.StringValue("key-a"), types.StringValue("*.example.internal"), "TXT"),
	)

	policies, diags := updateSecurityPoliciesFromSet(context.Background(), set)
	if diags.HasError() {
		t.Fatalf("updateSecurityPoliciesFromSet: %v", diags)
	}

	got := client.FormatUpdateSecurityPolicies(policies)
	want := "key-a|*.example.internal|TXT|key-a|www.example.internal|A,AAAA,TXT|key-b|example.internal|TXT"
	if got != want {
		t.Fatalf("policies = %q, want %q", got, want)
	}
}

// Technitium keeps duplicate record types of a policy, which a set cannot hold.
func TestUpdateSecurityPoliciesToSet_RemovesDuplicateTypes(t *testing.T) {
	set, diags := updateSecurityPoliciesToSet(context.Background(), []client.UpdateSecurityPolicy{
		{TsigKeyName: "key-a", Domain: "example.internal", AllowedTypes: []string{"TXT", "TXT", "A"}},
	})
	if diags.HasError() {
		t.Fatalf("updateSecurityPoliciesToSet: %v", diags)
	}

	want := policySet(t, policyObject(t, types.StringValue("key-a"), types.StringValue("example.internal"), "TXT", "A"))
	if !set.Equal(want) {
		t.Fatalf("set = %v, want %v", set, want)
	}
}

func TestUpdateSecurityPoliciesToSet_EmptyIsEmptySet(t *testing.T) {
	set, diags := updateSecurityPoliciesToSet(context.Background(), nil)
	if diags.HasError() {
		t.Fatalf("updateSecurityPoliciesToSet: %v", diags)
	}
	if set.IsNull() || len(set.Elements()) != 0 {
		t.Fatalf("set = %v, want an empty set", set)
	}
}

func TestSetZoneOptions_UpdateSecurityPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policies func(t *testing.T) types.Set
		want     string
		wantSent bool
	}{
		{
			name: "policies are sent",
			policies: func(t *testing.T) types.Set {
				return policySet(t,
					policyObject(t, types.StringValue("acme"), types.StringValue("*.example.internal"), "TXT"))
			},
			want:     "acme|*.example.internal|TXT",
			wantSent: true,
		},
		{
			name:     "an empty set clears the policies",
			policies: func(t *testing.T) types.Set { return policySet(t) },
			want:     "false",
			wantSent: true,
		},
		{
			name:     "null leaves the policies unmanaged",
			policies: func(*testing.T) types.Set { return types.SetNull(updateSecurityPolicyType) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newZonePolicyFake(t)
			m := policyFakeModel("Primary", tt.policies(t))
			// disabled is always sent, so the request is made in every case.
			m.Disabled = types.BoolValue(false)

			if err := f.resource(t).setZoneOptions(context.Background(), m); err != nil {
				t.Fatalf("setZoneOptions: %v", err)
			}

			_, sent := f.setParams["updateSecurityPolicies"]
			if sent != tt.wantSent {
				t.Fatalf("updateSecurityPolicies sent = %t, want %t (params: %v)", sent, tt.wantSent, f.setParams)
			}
			if got := f.setParams.Get("updateSecurityPolicies"); sent && got != tt.want {
				t.Fatalf("updateSecurityPolicies = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadZoneState_UpdateSecurityPolicies(t *testing.T) {
	f := newZonePolicyFake(t)
	f.policiesJSON = `[{"tsigKeyName":"acme","domain":"*.example.internal","allowedTypes":["TXT","TXT"]}]`
	r := f.resource(t)

	// Managed: the server value replaces the prior value, so drift shows.
	m := policyFakeModel("Primary", policySet(t))
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	want := policySet(t, policyObject(t, types.StringValue("acme"), types.StringValue("*.example.internal"), "TXT"))
	if !m.DynamicUpdateSecurityPolicies.Equal(want) {
		t.Fatalf("policies = %v, want %v", m.DynamicUpdateSecurityPolicies, want)
	}

	// Unmanaged: null stays null whatever the server reports.
	m = policyFakeModel("Primary", types.SetNull(updateSecurityPolicyType))
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if !m.DynamicUpdateSecurityPolicies.IsNull() {
		t.Fatalf("unmanaged policies = %v, want null", m.DynamicUpdateSecurityPolicies)
	}
}

func TestValidateTsigKeyReferences_UpdateSecurityPolicies(t *testing.T) {
	f := newZonePolicyFake(t)
	f.tsigKeys = []string{"key-a"}
	r := f.resource(t)

	// key-a is referenced twice but looked up once; key-b does not exist.
	m := policyFakeModel("Primary", policySet(t,
		policyObject(t, types.StringValue("key-a"), types.StringValue("example.internal"), "TXT"),
		policyObject(t, types.StringValue("key-a"), types.StringValue("*.example.internal"), "TXT"),
		policyObject(t, types.StringValue("key-b"), types.StringValue("www.example.internal"), "TXT"),
	))
	var diags diag.Diagnostics
	r.validateTsigKeyReferences(context.Background(), m, &diags)

	if f.settingsCalls != 2 {
		t.Errorf("TSIG key lookups = %d, want 2 (one per distinct key)", f.settingsCalls)
	}
	if diags.ErrorsCount() != 1 {
		t.Fatalf("errors = %d, want 1: %v", diags.ErrorsCount(), diags)
	}
	if d := diags.Errors()[0]; d.Summary() != "TSIG key not found" || !strings.Contains(d.Detail(), `"key-b"`) {
		t.Fatalf("unexpected diagnostic: %s: %s", d.Summary(), d.Detail())
	}
}

// modifyPlanWithPolicies runs ModifyPlan over a create plan for a zone of the
// given type with the given dynamic_update_security_policies.
func modifyPlanWithPolicies(t *testing.T, zoneType types.String, policies types.Set) *resource.ModifyPlanResponse {
	t.Helper()
	m := policyFakeModel("Primary", policies)
	m.Type = zoneType
	return modifyPlanForModel(t, m, false)
}

// modifyPlanForModel runs ModifyPlan over a plan for m. For an update the
// prior state equals the plan, otherwise the state is null (create).
func modifyPlanForModel(t *testing.T, m *ZoneResourceModel, update bool) *resource.ModifyPlanResponse {
	t.Helper()
	ctx := context.Background()

	r := &ZoneResource{}
	schemaResp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, m); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}
	state := tfsdk.State{Schema: schemaResp.Schema}
	if update {
		state.Raw = plan.Raw
	}

	resp := &resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{
		Plan:   plan,
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: plan.Raw},
		State:  state,
	}, resp)
	return resp
}

func hasErrorSummary(diags diag.Diagnostics, summary string) bool {
	for _, d := range diags.Errors() {
		if d.Summary() == summary {
			return true
		}
	}
	return false
}

func TestZoneModifyPlan_UpdateSecurityPoliciesZoneTypes(t *testing.T) {
	const summary = "Invalid zone type for dynamic_update_security_policies"
	for _, tt := range []struct {
		zoneType types.String
		valid    bool
	}{
		{types.StringValue("Primary"), true},
		{types.StringValue("Forwarder"), true},
		// The type may come from another resource; it is checked once known.
		{types.StringUnknown(), true},
		{types.StringValue("Secondary"), false},
		{types.StringValue("Stub"), false},
		{types.StringValue("Catalog"), false},
		{types.StringValue("SecondaryForwarder"), false},
		{types.StringValue("SecondaryCatalog"), false},
	} {
		t.Run(tt.zoneType.String(), func(t *testing.T) {
			policies := policySet(t,
				policyObject(t, types.StringValue("acme"), types.StringValue("*.example.internal"), "TXT"))
			resp := modifyPlanWithPolicies(t, tt.zoneType, policies)

			if got := hasErrorSummary(resp.Diagnostics, summary); got == tt.valid {
				t.Fatalf("%q error = %t, want %t: %v", summary, got, !tt.valid, resp.Diagnostics)
			}
		})
	}
}

// Policies on a zone type that does not support them are fine when unset.
func TestZoneModifyPlan_UpdateSecurityPoliciesUnsetOnSecondary(t *testing.T) {
	resp := modifyPlanWithPolicies(t, types.StringValue("Secondary"), types.SetNull(updateSecurityPolicyType))
	if hasErrorSummary(resp.Diagnostics, "Invalid zone type for dynamic_update_security_policies") {
		t.Fatalf("unset policies must not be refused: %v", resp.Diagnostics)
	}
}

// Technitium merges policies with the same key and domain, which would show
// up as an inconsistent result after apply.
func TestZoneModifyPlan_DuplicateUpdateSecurityPolicies(t *testing.T) {
	const summary = "Duplicate dynamic update security policy"

	resp := modifyPlanWithPolicies(t, types.StringValue("Primary"), policySet(t,
		policyObject(t, types.StringValue("acme"), types.StringValue("example.internal"), "TXT"),
		policyObject(t, types.StringValue("acme"), types.StringValue("example.internal"), "A"),
	))
	if !hasErrorSummary(resp.Diagnostics, summary) {
		t.Fatalf("expected %q, got: %v", summary, resp.Diagnostics)
	}

	// The same key for another domain, or another key for the same domain,
	// is a separate policy.
	resp = modifyPlanWithPolicies(t, types.StringValue("Primary"), policySet(t,
		policyObject(t, types.StringValue("acme"), types.StringValue("example.internal"), "TXT"),
		policyObject(t, types.StringValue("acme"), types.StringValue("*.example.internal"), "TXT"),
		policyObject(t, types.StringValue("other"), types.StringValue("example.internal"), "TXT"),
	))
	if hasErrorSummary(resp.Diagnostics, summary) {
		t.Fatalf("distinct policies must not be refused: %v", resp.Diagnostics)
	}

	// Unknown values are skipped; they are checked once known.
	resp = modifyPlanWithPolicies(t, types.StringValue("Primary"), policySet(t,
		policyObject(t, types.StringUnknown(), types.StringValue("example.internal"), "TXT"),
		policyObject(t, types.StringUnknown(), types.StringValue("example.internal"), "A"),
	))
	if hasErrorSummary(resp.Diagnostics, summary) {
		t.Fatalf("unknown key names must not be refused: %v", resp.Diagnostics)
	}
}

// Policies have no effect while dynamic updates are denied, which is the
// server default for a new zone.
func TestZoneModifyPlan_UpdateSecurityPoliciesWarnWhenDenied(t *testing.T) {
	const summary = "dynamic_update_security_policies have no effect"
	for _, tt := range []struct {
		name          string
		dynamicUpdate types.String
		update        bool
		empty         bool
		warn          bool
	}{
		{name: "create with dynamic_update unset", dynamicUpdate: types.StringNull(), warn: true},
		{name: "create with Deny", dynamicUpdate: types.StringValue("Deny"), warn: true},
		{name: "update with Deny", dynamicUpdate: types.StringValue("Deny"), update: true, warn: true},
		{name: "create with Allow", dynamicUpdate: types.StringValue("Allow")},
		{name: "create with UseSpecifiedNetworkACL", dynamicUpdate: types.StringValue("UseSpecifiedNetworkACL")},
		// Unset on an existing zone leaves the server value unmanaged.
		{name: "update with dynamic_update unset", dynamicUpdate: types.StringNull(), update: true},
		{name: "unknown dynamic_update", dynamicUpdate: types.StringUnknown()},
		// An empty set only clears the policies.
		{name: "empty policies with Deny", dynamicUpdate: types.StringValue("Deny"), empty: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policies := policySet(t,
				policyObject(t, types.StringValue("acme"), types.StringValue("*.example.internal"), "TXT"))
			if tt.empty {
				policies = policySet(t)
			}
			m := policyFakeModel("Primary", policies)
			m.DynamicUpdate = tt.dynamicUpdate

			resp := modifyPlanForModel(t, m, tt.update)

			var warned bool
			for _, d := range resp.Diagnostics.Warnings() {
				if d.Summary() == summary {
					warned = true
				}
			}
			if warned != tt.warn {
				t.Fatalf("%q warning = %t, want %t: %v", summary, warned, tt.warn, resp.Diagnostics)
			}
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected errors: %v", resp.Diagnostics.Errors())
			}
		})
	}
}
