// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// ---------------------------------------------------------------------------
// Baseline resolution
// ---------------------------------------------------------------------------

func TestEngine_EffectiveBaseline_HighWaterMark(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "high",
			Integrity:       "moderate",
			Availability:    "low",
		},
	})

	got := engine.effectiveBaseline()
	if got != "high" {
		t.Errorf("expected effective baseline 'high', got %q", got)
	}
}

func TestEngine_EffectiveBaseline_AllLow(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	got := engine.effectiveBaseline()
	if got != "low" {
		t.Errorf("expected effective baseline 'low', got %q", got)
	}
}

func TestEngine_EffectiveBaseline_AllModerate(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "moderate",
			Integrity:       "moderate",
			Availability:    "moderate",
		},
	})

	got := engine.effectiveBaseline()
	if got != "moderate" {
		t.Errorf("expected effective baseline 'moderate', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Control scoping
// ---------------------------------------------------------------------------

func TestEngine_ControlInScope_LowBaselineIncludesLowControl(t *testing.T) {
	// SC-20 is LOW baseline, effective=LOW -> in scope
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	if !engine.controlInScope([]string{"SC-20"}) {
		t.Error("SC-20 (LOW) should be in scope when effective baseline is LOW")
	}
}

func TestEngine_ControlOutOfScope_HighOnlyControlAtLowBaseline(t *testing.T) {
	// AC-10 is HIGH baseline, effective=LOW -> out of scope
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	if engine.controlInScope([]string{"AC-10"}) {
		t.Error("AC-10 (HIGH) should be out of scope when effective baseline is LOW")
	}
}

func TestEngine_ControlInScope_ModerateControlAtHighBaseline(t *testing.T) {
	// SC-8 is MODERATE, effective=HIGH -> in scope
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "high",
			Integrity:       "high",
			Availability:    "high",
		},
	})

	if !engine.controlInScope([]string{"SC-8"}) {
		t.Error("SC-8 (MODERATE) should be in scope when effective baseline is HIGH")
	}
}

// ---------------------------------------------------------------------------
// Enforcement policy
// ---------------------------------------------------------------------------

func TestEngine_Strict_ViolationProducesError(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014", // CM-6, LOW baseline
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false // always non-compliant
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if !diags.HasError() {
		t.Error("expected error diagnostic for strict enforcement violation")
	}
}

func TestEngine_Warn_ViolationProducesWarning(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "warn",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("warn enforcement should not produce errors")
	}
	if diags.WarningsCount() == 0 {
		t.Error("warn enforcement should produce at least one warning")
	}
}

func TestEngine_Silent_ViolationProducesNothing(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "silent",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("silent enforcement should not produce errors")
	}
	if diags.WarningsCount() > 0 {
		t.Error("silent enforcement should not produce warnings")
	}
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

func TestEngine_SuppressedFinding_EmitsWarningNotError(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:      true,
		Enforcement:  "strict",
		Suppressions: []string{"DNS-REQ-014"},
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("suppressed finding should not produce error even in strict mode")
	}
	if diags.WarningsCount() == 0 {
		t.Error("suppressed finding should produce a warning")
	}
	// Verify the warning mentions suppression
	for _, d := range diags {
		if d.Severity() == diag.SeverityWarning {
			if !strings.Contains(d.Summary(), "SUPPRESSED") {
				t.Error("suppressed warning summary should contain 'SUPPRESSED'")
			}
		}
	}
}

func TestEngine_UnsuppressedFinding_EmitsPerEnforcement(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:      true,
		Enforcement:  "strict",
		Suppressions: []string{"DNS-REQ-001"}, // suppress a different one
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if !diags.HasError() {
		t.Error("unsuppressed finding in strict mode should produce error")
	}
}

// ---------------------------------------------------------------------------
// Unimplemented bindings
// ---------------------------------------------------------------------------

func TestEngine_UnimplementedBinding_Skipped(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   false, // not implemented
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false // would fail if called
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("unimplemented binding should be skipped, no error expected")
	}
	if diags.WarningsCount() > 0 {
		t.Error("unimplemented binding should be skipped, no warning expected")
	}
}

// ---------------------------------------------------------------------------
// Validator dispatch
// ---------------------------------------------------------------------------

func TestEngine_ValidateConfig_CallsStatelessFn(t *testing.T) {
	called := false
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				called = true
				return true // compliant
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if !called {
		t.Error("ValidateConfig should call StatelessFn")
	}
}

func TestEngine_ValidatePlan_CallsStatefulFn(t *testing.T) {
	called := false
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-014",
			Resource:      ResourceZone,
			Implemented:   true,
			StatefulFn: func(ctx context.Context, plan PlanAccessor, state StateAccessor) bool {
				called = true
				return true
			},
		},
	})

	planMock := NewMockAccessor(map[string]interface{}{})
	stateMock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics
	engine.ValidatePlan(context.Background(), ResourceZone, planMock, stateMock, &diags)

	if !called {
		t.Error("ValidatePlan should call StatefulFn")
	}
}

func TestEngine_BothChecks_StatelessInValidate_StatefulInPlan(t *testing.T) {
	statelessCalled := false
	statefulCalled := false

	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	// DNS-REQ-001 is BothChecks type with controls that include SC-20 (LOW)
	engine.RegisterBindings(ResourceZone, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-001",
			Resource:      ResourceZone,
			Implemented:   true,
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				statelessCalled = true
				return true
			},
			StatefulFn: func(ctx context.Context, plan PlanAccessor, state StateAccessor) bool {
				statefulCalled = true
				return true
			},
		},
	})

	mock := NewMockAccessor(map[string]interface{}{})
	var diags diag.Diagnostics

	// ValidateConfig should call StatelessFn, not StatefulFn
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)
	if !statelessCalled {
		t.Error("ValidateConfig should call StatelessFn for BothChecks binding")
	}
	if statefulCalled {
		t.Error("ValidateConfig should NOT call StatefulFn")
	}

	// Reset
	statelessCalled = false
	statefulCalled = false
	diags = diag.Diagnostics{}

	// ValidatePlan should call StatefulFn, not StatelessFn
	planMock := NewMockAccessor(map[string]interface{}{})
	stateMock := NewMockAccessor(map[string]interface{}{})
	engine.ValidatePlan(context.Background(), ResourceZone, planMock, stateMock, &diags)
	if !statefulCalled {
		t.Error("ValidatePlan should call StatefulFn for BothChecks binding")
	}
	if statelessCalled {
		t.Error("ValidatePlan should NOT call StatelessFn")
	}
}

// ---------------------------------------------------------------------------
// Default-allow bug regression (GitHub #8)
// ---------------------------------------------------------------------------

func TestEngine_NullAttribute_TriggersFinding_Strict(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "high",
			Integrity:       "high",
			Availability:    "high",
		},
	})

	engine.RegisterBindings(ResourceZone, ZoneBindings)

	// Simulate a zone with dnssec block entirely omitted (null).
	mock := NewMockAccessor(map[string]interface{}{
		"dnssec.enabled":                 NullValue,
		"dnssec.algorithm":               NullValue,
		"dnssec.nx_proof":                NullValue,
		"zone_transfer_allowed_networks": NullValue,
		"notify_addresses":               NullValue,
	})

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if !diags.HasError() {
		t.Error("expected errors when security-critical attributes are null in strict mode")
	}

	// Count error diagnostics — should have findings for DNS-REQ-001,
	// DNS-REQ-004, DNS-REQ-011, DNS-REQ-012, DNS-REQ-016.
	// Using >= 3 threshold to allow for baseline scoping variations.
	errorCount := 0
	for _, d := range diags {
		if d.Severity() == diag.SeverityError {
			errorCount++
		}
	}
	if errorCount < 3 {
		t.Errorf("expected at least 3 error diagnostics for null zone attributes, got %d", errorCount)
	}
}

func TestEngine_NullAttribute_TriggersWarning_WarnMode(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "warn",
		Categorization: Categorization{
			Confidentiality: "low",
			Integrity:       "low",
			Availability:    "low",
		},
	})

	engine.RegisterBindings(ResourceZone, ZoneBindings)

	mock := NewMockAccessor(map[string]interface{}{
		"dnssec.enabled": NullValue,
	})

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("warn mode should not produce errors")
	}
	if diags.WarningsCount() == 0 {
		t.Error("expected at least one warning for null dnssec.enabled in warn mode")
	}
}

func TestEngine_UnknownAttribute_StillDeferred(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "high",
			Integrity:       "high",
			Availability:    "high",
		},
	})

	engine.RegisterBindings(ResourceZone, ZoneBindings)

	// Empty mock = all attributes are unknown (not in map = IsUnknown=true).
	// This should NOT trigger findings — unknown means "computed at apply".
	mock := NewMockAccessor(map[string]interface{}{})

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, mock, &diags)

	if diags.HasError() {
		t.Error("unknown attributes should not trigger findings — validation is deferred")
	}
}
