// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"testing"
)

func TestRegistry_RegisterAndRetrieve(t *testing.T) {
	r := NewRegistry()
	rule := ValidationRule{
		Name:        "test_rule",
		Description: "A test rule",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return nil
		},
	}
	r.Register(rule)

	rules := r.RulesFor(ResourceRecord)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "test_rule" {
		t.Errorf("expected rule name 'test_rule', got '%s'", rules[0].Name)
	}
}

func TestRegistry_RulesForUnknownResource(t *testing.T) {
	r := NewRegistry()
	rules := r.RulesFor(ResourceRecord)
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules for unregistered resource, got %d", len(rules))
	}
}

func TestRegistry_MultipleRulesPerResource(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 3; i++ {
		r.Register(ValidationRule{
			Name:     "rule_" + string(rune('a'+i)),
			Resource: ResourceRecord,
			Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
				return nil
			},
		})
	}
	rules := r.RulesFor(ResourceRecord)
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
}

func TestRegistry_IsolatesByResource(t *testing.T) {
	r := NewRegistry()
	r.Register(ValidationRule{
		Name:     "record_rule",
		Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return nil
		},
	})
	r.Register(ValidationRule{
		Name:     "zone_rule",
		Resource: ResourceZone,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return nil
		},
	})

	recordRules := r.RulesFor(ResourceRecord)
	zoneRules := r.RulesFor(ResourceZone)
	if len(recordRules) != 1 || recordRules[0].Name != "record_rule" {
		t.Errorf("record rules mismatch")
	}
	if len(zoneRules) != 1 || zoneRules[0].Name != "zone_rule" {
		t.Errorf("zone rules mismatch")
	}
}

func TestMockAccessor_GetString(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type":  "A",
		"value": "192.0.2.1",
	})
	val, ok := m.GetString("type")
	if !ok || val != "A" {
		t.Errorf("expected (A, true), got (%s, %v)", val, ok)
	}
	_, ok = m.GetString("missing")
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestMockAccessor_GetInt64(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"priority": int64(10),
	})
	val, ok := m.GetInt64("priority")
	if !ok || val != 10 {
		t.Errorf("expected (10, true), got (%d, %v)", val, ok)
	}
	_, ok = m.GetInt64("missing")
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestMockAccessor_GetBool(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"enabled": true,
	})
	val, ok := m.GetBool("enabled")
	if !ok || val != true {
		t.Errorf("expected (true, true), got (%v, %v)", val, ok)
	}
}

func TestMockAccessor_GetStringList(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"names": []string{"a", "b"},
	})
	val, ok := m.GetStringList("names")
	if !ok || len(val) != 2 {
		t.Errorf("expected 2-element list, got %v", val)
	}
}

func TestRunRules_CollectsFindings(t *testing.T) {
	r := NewRegistry()
	r.Register(ValidationRule{
		Name:     "always_fail",
		Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return []Finding{{
				Attribute: "value",
				Summary:   "bad value",
				Detail:    "fix it",
			}}
		},
	})
	r.Register(ValidationRule{
		Name:     "always_pass",
		Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return nil
		},
	})

	m := NewMockAccessor(map[string]interface{}{})
	findings := r.RunRules(context.Background(), ResourceRecord, m)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Summary != "bad value" {
		t.Errorf("unexpected summary: %s", findings[0].Summary)
	}
}

func TestRunRules_EmptyForValidInput(t *testing.T) {
	r := NewRegistry()
	r.Register(ValidationRule{
		Name:     "always_pass",
		Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			return nil
		},
	})

	m := NewMockAccessor(map[string]interface{}{})
	findings := r.RunRules(context.Background(), ResourceRecord, m)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDefaultRegistry_HasAllRecordRules(t *testing.T) {
	r := DefaultRegistry()
	rules := r.RulesFor(ResourceRecord)

	expectedNames := map[string]bool{
		"record_type":         false,
		"a_record_ipv4":       false,
		"aaaa_record_ipv6":    false,
		"cname_record_fqdn":   false,
		"mx_record":           false,
		"ns_record_fqdn":      false,
		"ptr_record_hostname": false,
		"srv_record":          false,
		"txt_record_nonempty": false,
		"caa_record":          false,
	}

	for _, rule := range rules {
		if _, exists := expectedNames[rule.Name]; !exists {
			t.Errorf("unexpected rule: %s", rule.Name)
		}
		expectedNames[rule.Name] = true
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("missing expected rule: %s", name)
		}
	}
}

func TestDefaultRegistry_EndToEnd_ValidA(t *testing.T) {
	r := DefaultRegistry()
	m := NewMockAccessor(map[string]interface{}{
		"type":  "A",
		"value": "192.0.2.1",
	})
	findings := r.RunRules(context.Background(), ResourceRecord, m)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for valid A record, got %d: %v", len(findings), findings)
	}
}

func TestDefaultRegistry_EndToEnd_InvalidA(t *testing.T) {
	r := DefaultRegistry()
	m := NewMockAccessor(map[string]interface{}{
		"type":  "A",
		"value": "2001:db8::1",
	})
	findings := r.RunRules(context.Background(), ResourceRecord, m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for IPv6 in A record, got %d: %v", len(findings), findings)
	}
}

func TestDefaultRegistry_EndToEnd_InvalidType(t *testing.T) {
	r := DefaultRegistry()
	m := NewMockAccessor(map[string]interface{}{
		"type":  "INVALID",
		"value": "whatever",
	})
	findings := r.RunRules(context.Background(), ResourceRecord, m)
	// Only the type validator should fire; type-specific validators skip unknown types
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for invalid type, got %d: %v", len(findings), findings)
	}
}
