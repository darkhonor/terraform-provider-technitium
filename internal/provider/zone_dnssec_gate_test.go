// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// signedP256 returns the common signed-state input; tests mutate copies.
func signedP256() dnssecGateInput {
	return dnssecGateInput{
		StateSigned:    true,
		StateAlgorithm: "ECDSA", StateCurve: "P256", StateNxProof: "NSEC3",
		PlanEnabled:   true,
		PlanAlgorithm: "ECDSA", PlanCurve: "P256", PlanNxProof: "NSEC3",
	}
}

func postures(spec string) []string {
	if spec == "any" {
		return []string{"", "warn", "silent", "strict"}
	}
	return strings.Split(spec, "|")
}

type gateCase struct {
	row      string
	postures string // "any" or pipe-separated; "" element = no-block
	mutate   func(*dnssecGateInput)
	action   string
	errSub   string // "" = expect no errors; else exactly one error containing this
	warnSubs []string
	// notErrSub asserts the error does NOT contain this substring (17b/17d-ii: never the parameter identity)
	notErrSub string
}

func TestEvaluateDNSSECGate(t *testing.T) {
	cases := []gateCase{
		{row: "1", postures: "any", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.StateAlgorithm, in.StateCurve, in.StateNxProof = "", "", ""
		}, action: "sign"},
		{row: "1b", postures: "|warn|strict", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.StateAlgorithm, in.StateCurve, in.StateNxProof = "", "", ""
			in.Acknowledgment = "unsigned"
		}, action: "sign", warnSubs: []string{"should be removed"}},
		{row: "1c", postures: "silent", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.StateAlgorithm, in.StateCurve, in.StateNxProof = "", "", ""
			in.Acknowledgment = "unsigned"
		}, action: "sign"},
		{row: "2", postures: "|warn", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false }, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "3", postures: "silent", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false }, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "4", postures: "strict", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false }, action: "none", errSub: "Unsigning requires acknowledgment under strict enforcement"},
		{row: "5", postures: "strict", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false; in.Acknowledgment = "unsigned" }, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "6", postures: "any", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384" }, action: "none", errSub: "ECDSA/P384"},
		{row: "7", postures: "|warn|silent", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384"; in.Acknowledgment = "ECDSA/P384" }, action: "resign", warnSubs: []string{"WDNS-22-000055"}},
		{row: "8", postures: "strict", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384"; in.Acknowledgment = "ECDSA/P384" }, action: "resign", warnSubs: []string{"WDNS-22-000055"}},
		{row: "9", postures: "any", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384"; in.Acknowledgment = "ECDSA/P256" }, action: "none", errSub: "ECDSA/P384"},
		{row: "9b", postures: "|warn|strict", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384"; in.Acknowledgment = "unsigned" }, action: "none", errSub: "ECDSA/P384", warnSubs: []string{"should be removed"}},
		{row: "9c", postures: "silent", mutate: func(in *dnssecGateInput) { in.PlanCurve = "P384"; in.Acknowledgment = "unsigned" }, action: "none", errSub: "ECDSA/P384"},
		{row: "10", postures: "any", mutate: func(in *dnssecGateInput) { in.PlanNxProof = "NSEC" }, action: "convert_nxproof"},
		{row: "11", postures: "any", mutate: func(in *dnssecGateInput) {}, action: "none"},
		{row: "12", postures: "|warn|strict", mutate: func(in *dnssecGateInput) { in.Acknowledgment = "unsigned" }, action: "none", warnSubs: []string{"should be removed"}},
		{row: "13", postures: "silent", mutate: func(in *dnssecGateInput) { in.Acknowledgment = "unsigned" }, action: "none"},
		{row: "14", postures: "any", mutate: func(in *dnssecGateInput) { in.Acknowledgment = "ECDSA/P256" }, action: "none"},
		{row: "15", postures: "any", mutate: func(in *dnssecGateInput) { in.StateSigned = false; in.PlanEnabled = false }, action: "none"},
		{row: "15b", postures: "|warn|strict", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.PlanEnabled = false
			in.Acknowledgment = "unsigned"
		}, action: "none", warnSubs: []string{"should be removed"}},
		{row: "15c", postures: "silent", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.PlanEnabled = false
			in.Acknowledgment = "unsigned"
		}, action: "none"},
		{row: "16", postures: "|warn|silent", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false; in.Acknowledgment = "unsigned" }, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "17a", postures: "|warn|silent", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false; in.PlanCurve = "P384" }, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "17b", postures: "strict", mutate: func(in *dnssecGateInput) { in.PlanEnabled = false; in.PlanCurve = "P384" }, action: "none", errSub: `"unsigned"`, notErrSub: "ECDSA/P384"},
		{row: "17c", postures: "strict", mutate: func(in *dnssecGateInput) {
			in.PlanEnabled = false
			in.PlanCurve = "P384"
			in.Acknowledgment = "unsigned"
		}, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "17d-i", postures: "|warn|silent", mutate: func(in *dnssecGateInput) {
			in.PlanEnabled = false
			in.PlanCurve = "P384"
			in.Acknowledgment = "ECDSA/P384"
		}, action: "unsign", warnSubs: []string{"4.2.1.2"}},
		{row: "17d-ii", postures: "strict", mutate: func(in *dnssecGateInput) {
			in.PlanEnabled = false
			in.PlanCurve = "P384"
			in.Acknowledgment = "ECDSA/P384"
		}, action: "none", errSub: `"unsigned"`, notErrSub: "ECDSA/P384"},
		{row: "rsa-nodelta", postures: "any", mutate: func(in *dnssecGateInput) {
			in.StateAlgorithm, in.StateCurve = "RSA", ""
			in.PlanAlgorithm, in.PlanCurve = "RSA", "P256" // schema default is vestigial for RSA
		}, action: "none"},
		{row: "unknown-signed-defers-with-warning", postures: "any", mutate: func(in *dnssecGateInput) {
			in.PlanEnabled = false // would otherwise unsign/gate
			in.Acknowledgment = "unsigned"
			in.HasUnknown = true
		}, action: "none", warnSubs: []string{"deferred"}},
		{row: "unknown-unsigned-silent-defer", postures: "any", mutate: func(in *dnssecGateInput) {
			in.StateSigned = false
			in.StateAlgorithm, in.StateCurve, in.StateNxProof = "", "", ""
			in.HasUnknown = true
		}, action: "none"},
		{row: "invalid-target-never-resigns", postures: "any", mutate: func(in *dnssecGateInput) {
			in.PlanAlgorithm, in.PlanCurve = "EDDSA", "P256" // dropped curve line + default
			in.Acknowledgment = "EDDSA/P256"                 // even acknowledged: never destructive
		}, action: "none", errSub: "not a signable combination"},
		{row: "18", postures: "any", mutate: func(in *dnssecGateInput) { in.IsReplace = true; in.PlanCurve = "P384"; in.Acknowledgment = "unsigned" }, action: "none"},
	}
	for _, tc := range cases {
		for _, posture := range postures(tc.postures) {
			name := "row" + tc.row + "_posture_" + posture
			if posture == "" {
				name = "row" + tc.row + "_posture_noblock"
			}
			t.Run(name, func(t *testing.T) {
				in := signedP256()
				tc.mutate(&in)
				in.Posture = posture
				res := evaluateDNSSECGate(in)
				if res.Action != tc.action {
					t.Fatalf("action = %q, want %q", res.Action, tc.action)
				}
				if tc.errSub == "" {
					if len(res.Errors) != 0 {
						t.Fatalf("expected no errors, got %v", res.Errors)
					}
				} else {
					if len(res.Errors) != 1 {
						t.Fatalf("expected exactly one error, got %v", res.Errors)
					}
					full := res.Errors[0].Summary + " " + res.Errors[0].Detail
					if !strings.Contains(full, tc.errSub) {
						t.Fatalf("error %q does not contain %q", full, tc.errSub)
					}
					if tc.notErrSub != "" && strings.Contains(full, tc.notErrSub) {
						t.Fatalf("error %q must NOT contain %q", full, tc.notErrSub)
					}
				}
				if len(res.Warnings) != len(tc.warnSubs) {
					t.Fatalf("expected %d warnings, got %v", len(tc.warnSubs), res.Warnings)
				}
				for i, sub := range tc.warnSubs {
					full := res.Warnings[i].Summary + " " + res.Warnings[i].Detail
					if !strings.Contains(full, sub) {
						t.Fatalf("warning %q does not contain %q", full, sub)
					}
				}
			})
		}
	}
}

func TestDNSSECTargetIdentity(t *testing.T) {
	for _, tc := range []struct{ alg, curve, want string }{
		{"RSA", "P256", "RSA"},
		{"ECDSA", "P384", "ECDSA/P384"},
		{"EDDSA", "ED25519", "EDDSA/ED25519"},
	} {
		if got := dnssecTargetIdentity(tc.alg, tc.curve); got != tc.want {
			t.Fatalf("dnssecTargetIdentity(%q,%q) = %q, want %q", tc.alg, tc.curve, got, tc.want)
		}
	}
}

func TestDNSSECIdentityValid(t *testing.T) {
	for _, tc := range []struct {
		alg, curve string
		want       bool
	}{
		{"ECDSA", "P256", true}, {"ECDSA", "P384", true},
		{"ECDSA", "ED25519", false}, {"ECDSA", "ED448", false},
		{"EDDSA", "ED25519", true}, {"EDDSA", "ED448", true},
		{"EDDSA", "P256", false}, {"EDDSA", "P384", false},
		{"RSA", "P256", true}, {"RSA", "", true},
		{"DSA", "", false},
	} {
		if got := dnssecIdentityValid(tc.alg, tc.curve); got != tc.want {
			t.Fatalf("dnssecIdentityValid(%q,%q) = %v, want %v", tc.alg, tc.curve, got, tc.want)
		}
	}
}

func TestApplyGateDiags(t *testing.T) {
	res := dnssecGateResult{
		Errors:   []gateDiag{{Summary: "e1", Detail: "d1"}},
		Warnings: []gateDiag{{Summary: "w1", Detail: "d2"}, {Summary: "w2", Detail: "d3"}},
	}
	var d diag.Diagnostics
	applyGateDiags(res, &d)
	if d.ErrorsCount() != 1 || d.WarningsCount() != 2 {
		t.Fatalf("got %d errors / %d warnings, want 1 / 2", d.ErrorsCount(), d.WarningsCount())
	}
}

func TestApplyGateErrors(t *testing.T) {
	res := dnssecGateResult{
		Errors:   []gateDiag{{Summary: "e1", Detail: "d1"}},
		Warnings: []gateDiag{{Summary: "w1", Detail: "d2"}},
	}
	var d diag.Diagnostics
	applyGateErrors(res, &d)
	if d.ErrorsCount() != 1 {
		t.Fatalf("got %d errors, want 1", d.ErrorsCount())
	}
	if d.WarningsCount() != 0 {
		t.Fatalf("apply-time conversion must emit errors only; got %d warnings", d.WarningsCount())
	}
}

func TestGateInputFromModels(t *testing.T) {
	mkModel := func(name, ztype string, dnssec *DNSSECModel, status string) *ZoneResourceModel {
		return &ZoneResourceModel{
			Name:         types.StringValue(name),
			Type:         types.StringValue(ztype),
			DNSSEC:       dnssec,
			DNSSECStatus: types.StringValue(status),
		}
	}
	block := func(enabled bool, alg, curve, nx, ack string) *DNSSECModel {
		m := &DNSSECModel{
			Enabled:   types.BoolValue(enabled),
			Algorithm: types.StringValue(alg),
			Curve:     types.StringValue(curve),
			NxProof:   types.StringValue(nx),
		}
		if ack == "" {
			m.ChangeAcknowledgment = types.StringNull()
		} else {
			m.ChangeAcknowledgment = types.StringValue(ack)
		}
		return m
	}

	t.Run("plan_dnssec_nil_maps_to_unsign_branch", func(t *testing.T) {
		plan := mkModel("z.test", "Primary", nil, "")
		state := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "SignedWithNSEC3")
		in := gateInputFromModels(plan, state, "warn")
		if in.PlanEnabled {
			t.Fatal("plan.DNSSEC nil must map to PlanEnabled=false")
		}
		res := evaluateDNSSECGate(in)
		if res.Action != "unsign" {
			t.Fatalf("expected unsign routing, got %q", res.Action)
		}
	})
	t.Run("state_dnssec_nil_unsigned_no_panic_sign_path", func(t *testing.T) {
		plan := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		state := mkModel("z.test", "Primary", nil, "Unsigned")
		in := gateInputFromModels(plan, state, "warn") // must not panic
		res := evaluateDNSSECGate(in)
		if res.Action != "sign" {
			t.Fatalf("expected sign, got %q", res.Action)
		}
	})
	t.Run("state_dnssec_nil_signed_fails_closed", func(t *testing.T) {
		plan := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		state := mkModel("z.test", "Primary", nil, "SignedWithNSEC3")
		in := gateInputFromModels(plan, state, "warn")
		res := evaluateDNSSECGate(in)
		if len(res.Errors) != 1 {
			t.Fatalf("signed state with nil dnssec model must fail closed (refusal), got %v", res)
		}
	})
	t.Run("unknown_curve_sets_has_unknown", func(t *testing.T) {
		d := block(true, "ECDSA", "P256", "NSEC3", "")
		d.Curve = types.StringUnknown()
		plan := mkModel("z.test", "Primary", d, "")
		state := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "SignedWithNSEC3")
		if in := gateInputFromModels(plan, state, "warn"); !in.HasUnknown {
			t.Fatal("unknown curve must set HasUnknown")
		}
	})
	t.Run("unknown_any_attribute_sets_has_unknown", func(t *testing.T) {
		for _, name := range []string{"enabled", "algorithm", "curve", "nx_proof", "change_acknowledgment"} {
			d := block(true, "ECDSA", "P256", "NSEC3", "")
			switch name {
			case "enabled":
				d.Enabled = types.BoolUnknown()
			case "algorithm":
				d.Algorithm = types.StringUnknown()
			case "curve":
				d.Curve = types.StringUnknown()
			case "nx_proof":
				d.NxProof = types.StringUnknown()
			case "change_acknowledgment":
				d.ChangeAcknowledgment = types.StringUnknown()
			}
			plan := mkModel("z.test", "Primary", d, "")
			state := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "SignedWithNSEC3")
			if in := gateInputFromModels(plan, state, "warn"); !in.HasUnknown {
				t.Fatalf("unknown %s must set HasUnknown", name)
			}
		}
	})
	t.Run("acknowledgment_null_maps_to_empty", func(t *testing.T) {
		plan := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		state := mkModel("z.test", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "SignedWithNSEC3")
		if in := gateInputFromModels(plan, state, ""); in.Acknowledgment != "" {
			t.Fatalf("null acknowledgment must map to empty, got %q", in.Acknowledgment)
		}
	})
	t.Run("is_replace_case_insensitive_name", func(t *testing.T) {
		plan := mkModel("Example.COM", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		state := mkModel("example.com", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "SignedWithNSEC3")
		if in := gateInputFromModels(plan, state, ""); in.IsReplace {
			t.Fatal("case-only name difference must NOT be a replace")
		}
		plan2 := mkModel("other.com", "Primary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		if in := gateInputFromModels(plan2, state, ""); !in.IsReplace {
			t.Fatal("name change must be a replace")
		}
		plan3 := mkModel("example.com", "Secondary", block(true, "ECDSA", "P256", "NSEC3", ""), "")
		if in := gateInputFromModels(plan3, state, ""); !in.IsReplace {
			t.Fatal("type change must be a replace")
		}
	})
}

func TestPosture_Derivation(t *testing.T) {
	for _, tc := range []struct {
		name string
		pd   *TechnitiumProviderData
		want string
	}{
		{"nil_provider_data", nil, ""},
		{"no_block", &TechnitiumProviderData{}, ""},
		{"enabled_unset_silent", &TechnitiumProviderData{STIGEnabled: false, Enforcement: "silent"}, "silent"},
		{"enabled_unset_strict", &TechnitiumProviderData{STIGEnabled: false, Enforcement: "strict"}, "strict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ZoneResource{providerData: tc.pd}
			if got := r.posture(); got != tc.want {
				t.Fatalf("posture() = %q, want %q", got, tc.want)
			}
		})
	}
}
