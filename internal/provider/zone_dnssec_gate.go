// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// dnssecGateInput is the posture-scaled DNSSEC change gate's input (issue
// #96). All values derive from declared config and prior state — never from
// live reads — so the gate stays a pure function.
type dnssecGateInput struct {
	StateSigned                              bool // state.DNSSECStatus not "Unsigned"/""
	StateAlgorithm, StateCurve, StateNxProof string
	PlanEnabled                              bool
	PlanAlgorithm, PlanCurve, PlanNxProof    string
	Acknowledgment                           string // plan.DNSSEC.ChangeAcknowledgment ("" when null)
	Posture                                  string // "" (no stig_compliance block) | "warn" | "silent" | "strict"
	IsReplace                                bool   // plan name/type differ from state; gate returns none immediately
}

type gateDiag struct{ Summary, Detail string }

type dnssecGateResult struct {
	Action   string // "none" | "sign" | "unsign" | "resign" | "convert_nxproof"
	Errors   []gateDiag
	Warnings []gateDiag
}

// dnssecTargetIdentity is the declared-config transition identity: bare
// "RSA" for RSA (it has no curve — the schema curve default is vestigial
// there), "ALGORITHM/CURVE" otherwise, and the literal "unsigned" for the
// unsign path (composed by callers, not here).
func dnssecTargetIdentity(algorithm, curve string) string {
	if algorithm == "RSA" {
		return "RSA"
	}
	return algorithm + "/" + curve
}

const goingInsecureSummary = "DNSSEC will be removed from this zone"
const keyRegenSummary = "DNSSEC keys will be regenerated"
const removalSummary = "Stale DNSSEC change acknowledgment should be removed"

func goingInsecureWarning(zoneRef string) gateDiag {
	return gateDiag{
		Summary: goingInsecureSummary,
		Detail: fmt.Sprintf("Unsigning %s breaks its chain of trust instantly for any validator holding a "+
			"trust anchor or resolving through a published DS record. Remove any published parent DS record "+
			"and wait out its TTL before unsigning, and withdraw distributed trust anchors "+
			"(RFC 6781, Section 4.2.1.2).", zoneRef),
	}
}

func keyRegenWarning(zoneRef string) gateDiag {
	return gateDiag{
		Summary: keyRegenSummary,
		Detail: fmt.Sprintf("The acknowledged re-sign of %s destroys and regenerates its signing keys. "+
			"Export the new DS records and redistribute trust anchors that reference the previous KSK "+
			"(WDNS-22-000055/WDNS-22-000056).", zoneRef),
	}
}

func removalWarning(zoneRef string) gateDiag {
	return gateDiag{
		Summary: removalSummary,
		Detail: fmt.Sprintf("change_acknowledgment = \"unsigned\" on %s has no unsign pending; it is standing "+
			"consent that will authorize a future unsign of this zone and should be removed.", zoneRef),
	}
}

// evaluateDNSSECGate implements the normative evaluation order from the
// issue-96 plan. The list order is the evaluation order.
func evaluateDNSSECGate(in dnssecGateInput) dnssecGateResult {
	res := dnssecGateResult{Action: "none"}
	zoneRef := "this zone"

	// Rule 1: replace plans are the deferred issue-#99 surface — return
	// before every other rule, including the rule-7 removal warning.
	if in.IsReplace {
		return res
	}

	switch {
	case !in.StateSigned && in.PlanEnabled: // Rule 2
		res.Action = "sign"
	case !in.StateSigned && !in.PlanEnabled: // Rule 3
		res.Action = "none"
	case in.StateSigned && !in.PlanEnabled: // Rule 4: unsign branch; parameter deltas ignored
		if in.Posture == "strict" && in.Acknowledgment != "unsigned" {
			res.Errors = append(res.Errors, gateDiag{
				Summary: "Unsigning requires acknowledgment under strict enforcement",
				Detail: "This zone is signed and stig_compliance enforcement is \"strict\": removing DNSSEC " +
					"breaks the chain of trust and is blocked until you declare " +
					"change_acknowledgment = \"unsigned\" on the zone's dnssec block. Remove any published " +
					"parent DS record and wait out its TTL first, and withdraw distributed trust anchors " +
					"(RFC 6781, Section 4.2.1.2). Do not lower global enforcement to proceed.",
			})
		} else {
			res.Action = "unsign"
			res.Warnings = append(res.Warnings, goingInsecureWarning(zoneRef))
		}
	default: // StateSigned && PlanEnabled — rules 5 and 6
		algoChanged := in.PlanAlgorithm != in.StateAlgorithm || in.PlanCurve != in.StateCurve
		nxChanged := in.PlanNxProof != in.StateNxProof
		switch {
		case algoChanged:
			target := dnssecTargetIdentity(in.PlanAlgorithm, in.PlanCurve)
			if in.Acknowledgment == target {
				res.Action = "resign"
				res.Warnings = append(res.Warnings, keyRegenWarning(zoneRef))
			} else {
				res.Errors = append(res.Errors, gateDiag{
					Summary: "In-place DNSSEC parameter change requires acknowledgment",
					Detail: fmt.Sprintf("Changing the signing algorithm/curve of a signed zone destroys and "+
						"regenerates its keys; the server has no in-place change. Either declare "+
						"change_acknowledgment = %q to authorize an unsign/re-sign to the new parameters "+
						"(DS records and trust anchors must then be re-exported), or follow the manual "+
						"procedure: set dnssec.enabled = false, apply, then re-enable with the new "+
						"parameters (under strict enforcement that first step needs "+
						"change_acknowledgment = \"unsigned\").", target),
				})
			}
		case nxChanged: // Rule 5: in-place conversion — no keys change, no gate
			res.Action = "convert_nxproof"
		default: // Rule 6: explicit terminal — no delta, no action
			res.Action = "none"
		}
	}

	// Rule 7: orthogonal removal warning for a surviving/premature unsign
	// acknowledgment — appended after action selection, suppressed under
	// silent only.
	if in.Acknowledgment == "unsigned" && res.Action != "unsign" && in.Posture != "silent" {
		res.Warnings = append(res.Warnings, removalWarning(zoneRef))
	}
	return res
}

// applyGateDiags is the ModifyPlan-only conversion point: errors AND warnings.
func applyGateDiags(res dnssecGateResult, d *diag.Diagnostics) {
	for _, e := range res.Errors {
		d.AddError(e.Summary, e.Detail)
	}
	for _, w := range res.Warnings {
		d.AddWarning(w.Summary, w.Detail)
	}
}

// applyGateErrors is the Update conversion point — errors only. Apply-time
// warning re-emission is deliberately suppressed: this notice family is
// plan-time per the issue-96 spec, and ModifyPlan already emitted them.
func applyGateErrors(res dnssecGateResult, d *diag.Diagnostics) {
	for _, e := range res.Errors {
		d.AddError(e.Summary, e.Detail)
	}
}

// gateInputFromModels maps plan/state models to gate input. It guards BOTH
// dnssec pointers: plan.DNSSEC nil (block removed) maps to PlanEnabled=false;
// state.DNSSEC nil (zone created without a dnssec block — readZoneState
// leaves the pointer nil for unsigned zones) maps to empty state params, and
// routing then rides StateSigned. An unguarded read here panics during
// terraform plan. The signed+nil fail-closed refusal is emergent from the
// empty state params meeting the delta check — no extra flag needed.
func gateInputFromModels(plan, state *ZoneResourceModel, posture string) dnssecGateInput {
	in := dnssecGateInput{Posture: posture}
	status := state.DNSSECStatus.ValueString()
	in.StateSigned = status != "" && status != "Unsigned"
	if state.DNSSEC != nil {
		in.StateAlgorithm = state.DNSSEC.Algorithm.ValueString()
		in.StateCurve = state.DNSSEC.Curve.ValueString()
		in.StateNxProof = state.DNSSEC.NxProof.ValueString()
	}
	if plan.DNSSEC != nil {
		in.PlanEnabled = plan.DNSSEC.Enabled.ValueBool()
		in.PlanAlgorithm = plan.DNSSEC.Algorithm.ValueString()
		in.PlanCurve = plan.DNSSEC.Curve.ValueString()
		in.PlanNxProof = plan.DNSSEC.NxProof.ValueString()
		in.Acknowledgment = plan.DNSSEC.ChangeAcknowledgment.ValueString()
	}
	// EqualFold: readZoneState normalizes names and zone matching is
	// case-insensitive (zone_resource.go:541); a case-only difference must
	// not read as a replace.
	in.IsReplace = !strings.EqualFold(plan.Name.ValueString(), state.Name.ValueString()) ||
		plan.Type.ValueString() != state.Type.ValueString()
	return in
}

// posture resolves the enforcement posture for gate evaluation. It keys on
// Enforcement, never STIGEnabled: `enabled` is Optional with no default, so
// a stig_compliance block that sets enforcement without enabled must still
// carry its posture (plan-review round-1 critical 4).
func (r *ZoneResource) posture() string {
	if r.providerData == nil {
		return ""
	}
	return r.providerData.Enforcement
}
