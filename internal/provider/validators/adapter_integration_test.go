// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import "testing"

// ---------------------------------------------------------------------------
// TFConfigAdapter integration tests — real tfsdk.Config objects
// ---------------------------------------------------------------------------

func TestTFConfigAdapter_IsNull_NullNestedBlock(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
	})
	adapter := &TFConfigAdapter{Config: config}

	if !adapter.IsNull("dnssec") {
		t.Error("expected dnssec block to be null when omitted")
	}
	if !adapter.IsNull("dnssec.enabled") {
		t.Error("expected dnssec.enabled to be null when parent block omitted")
	}
	if adapter.IsUnknown("dnssec.enabled") {
		t.Error("expected dnssec.enabled to NOT be unknown (it's null, not unknown)")
	}
}

func TestTFConfigAdapter_GetBool_PresentNestedBlock(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
		"dnssec": map[string]interface{}{
			"enabled":   true,
			"algorithm": "ECDSA",
			"curve":     "P256",
			"nx_proof":  "NSEC3",
		},
	})
	adapter := &TFConfigAdapter{Config: config}

	val, ok := adapter.GetBool("dnssec.enabled")
	if !ok || !val {
		t.Errorf("expected dnssec.enabled=true, got val=%v ok=%v", val, ok)
	}

	algo, ok := adapter.GetString("dnssec.algorithm")
	if !ok || algo != "ECDSA" {
		t.Errorf("expected dnssec.algorithm=ECDSA, got %q ok=%v", algo, ok)
	}
}

func TestTFConfigAdapter_GetString_TopLevelAttribute(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
	})
	adapter := &TFConfigAdapter{Config: config}

	name, ok := adapter.GetString("name")
	if !ok || name != "example.com" {
		t.Errorf("expected name='example.com', got %q ok=%v", name, ok)
	}
}

func TestTFConfigAdapter_IsNull_OmittedOptionalAttribute(t *testing.T) {
	config := BuildTestConfig(t, zoneResourceSchema(), map[string]interface{}{
		"name": "example.com",
		"type": "Primary",
		// notify, allow_transfer intentionally omitted
	})
	adapter := &TFConfigAdapter{Config: config}

	if !adapter.IsNull("notify") {
		t.Error("expected notify to be null when omitted")
	}
	if !adapter.IsNull("allow_transfer") {
		t.Error("expected allow_transfer to be null when omitted")
	}
}
