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
