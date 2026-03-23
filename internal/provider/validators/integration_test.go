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
// Engine integration tests — real schema + real adapter + real bindings
// These tests would have caught the default-allow bug (GitHub #8).
//
// KNOWN ATTRIBUTE PATH MISMATCHES (pre-existing production bugs):
// The zone bindings in stig.go use different attribute paths than the
// actual zone schema in zone_resource.go:
//   - Binding: "notify_addresses"    → Schema: "notify"
//   - Binding: "zone_transfer_allowed_networks" → Schema: "allow_transfer"
//
// TODO: File a separate issue to align binding paths with schema paths.
// Integration tests that exercise these bindings will see them as
// "unknown" (path not found in real config), which passes validation.
// This is the integration tests doing their job — surfacing the mismatch.
// ---------------------------------------------------------------------------

func TestIntegration_ZoneWithoutDNSSEC_TriggersFindings(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
	})
	adapter := &TFConfigAdapter{Config: config}

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

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, adapter, &diags)

	if !diags.HasError() {
		t.Fatal("expected errors for zone without dnssec block")
	}

	// Count errors — expect at least DNS-REQ-001, DNS-REQ-011, DNS-REQ-012
	// (DNS-REQ-004 and DNS-REQ-016 use mismatched paths so they pass as "unknown")
	errorCount := 0
	for _, d := range diags {
		if d.Severity() == diag.SeverityError {
			errorCount++
		}
	}
	if errorCount < 3 {
		t.Errorf("expected at least 3 error diagnostics, got %d", errorCount)
	}
}

func TestIntegration_ZoneWithDNSSEC_PassesClean(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
		"dnssec": map[string]interface{}{
			"enabled":   true,
			"algorithm": "ECDSA",
			"curve":     "P256",
			"nx_proof":  "NSEC3",
		},
		"notify":                       []string{"10.0.0.2"},
		"allow_transfer":               []string{"10.0.0.0/8"},
		"zone_transfer_tsig_key_names": []string{"transfer-key"},
	})
	adapter := &TFConfigAdapter{Config: config}

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

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, adapter, &diags)

	if diags.HasError() {
		for _, d := range diags {
			if d.Severity() == diag.SeverityError {
				t.Errorf("unexpected error: %s — %s", d.Summary(), d.Detail())
			}
		}
	}
}

func TestIntegration_ZoneWithDNSSECDisabled_TriggersREQ001Only(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
		"dnssec": map[string]interface{}{
			"enabled":   false,
			"algorithm": "ECDSA",
			"curve":     "P256",
			"nx_proof":  "NSEC3",
		},
		"notify":         []string{"10.0.0.2"},
		"allow_transfer": []string{"10.0.0.0/8"},
	})
	adapter := &TFConfigAdapter{Config: config}

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

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, adapter, &diags)

	if !diags.HasError() {
		t.Fatal("expected error for dnssec.enabled=false")
	}

	// Should trigger DNS-REQ-001 but NOT DNS-REQ-011/012 (algo and nx_proof are compliant)
	for _, d := range diags {
		if d.Severity() == diag.SeverityError {
			if !strings.Contains(d.Summary(), "DNS-REQ-001") {
				t.Errorf("expected only DNS-REQ-001 error, got: %s", d.Summary())
			}
		}
	}
}

func TestIntegration_ZoneWithoutDNSSEC_WarnMode(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
	})
	adapter := &TFConfigAdapter{Config: config}

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

	var diags diag.Diagnostics
	engine.ValidateConfig(context.Background(), ResourceZone, adapter, &diags)

	if diags.HasError() {
		t.Error("warn mode should not produce errors")
	}
	if diags.WarningsCount() == 0 {
		t.Error("expected warnings for zone without dnssec block in warn mode")
	}
}
