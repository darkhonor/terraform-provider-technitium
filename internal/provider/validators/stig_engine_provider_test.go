// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func TestEngine_ValidateProvider_EmitsFindings(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled: true, Enforcement: "strict",
		Categorization: Categorization{Confidentiality: "moderate", Integrity: "moderate", Availability: "moderate"},
	})
	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{RequirementID: "DNS-REQ-028", Resource: TargetProvider, Attributes: []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool { return false },
			Implemented: true},
	})
	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{"skip_tls_verify": true})
	engine.ValidateProvider(context.Background(), accessor, &diags)
	if !diags.HasError() {
		t.Error("strict enforcement should produce error")
	}
}

func TestEngine_ValidateProvider_WarnMode(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled: true, Enforcement: "warn",
		Categorization: Categorization{Confidentiality: "moderate", Integrity: "moderate", Availability: "moderate"},
	})
	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{RequirementID: "DNS-REQ-028", Resource: TargetProvider, Attributes: []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool { return false },
			Implemented: true},
	})
	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{"skip_tls_verify": true})
	engine.ValidateProvider(context.Background(), accessor, &diags)
	if diags.HasError() {
		t.Error("warn mode should not produce errors")
	}
	if len(diags.Warnings()) == 0 {
		t.Error("warn mode should produce warnings")
	}
}

func TestEngine_ValidateProvider_Suppressed(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled: true, Enforcement: "strict", Suppressions: []string{"DNS-REQ-028"},
		Categorization: Categorization{Confidentiality: "moderate", Integrity: "moderate", Availability: "moderate"},
	})
	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{RequirementID: "DNS-REQ-028", Resource: TargetProvider, Attributes: []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool { return false },
			Implemented: true},
	})
	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{"skip_tls_verify": true})
	engine.ValidateProvider(context.Background(), accessor, &diags)
	if diags.HasError() {
		t.Error("suppressed finding in strict mode should be warning, not error")
	}
}

func TestEngine_ValidateProvider_Disabled(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: false})
	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{RequirementID: "DNS-REQ-028", Resource: TargetProvider, Attributes: []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool { return false },
			Implemented: true},
	})
	var diags diag.Diagnostics
	engine.ValidateProvider(context.Background(), NewMockAccessor(nil), &diags)
	if diags.HasError() || len(diags.Warnings()) > 0 {
		t.Error("disabled engine should produce no diagnostics")
	}
}
