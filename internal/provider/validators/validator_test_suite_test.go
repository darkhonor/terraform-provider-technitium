// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// ValidatorTestSuite — declarative test helper for STIG validators
//
// Generates 4 standard test cases per validator (compliant, noncompliant,
// null, unknown) from a single declaration. Supports NullCompliant flag
// for optional attributes and CustomCases escape hatch for multi-attribute
// validators.
// ---------------------------------------------------------------------------

// ValidatorTestCase declares the required test coverage for a stateless validator.
//
// For single-attribute validators, set Attribute + CompliantVal + NonCompliantVal
// to generate 4 standard test cases automatically.
//
// For multi-attribute validators (e.g., validateRecursionACL which reads both
// "recursion" and "recursion_network_acl"), leave Attribute empty to suppress
// generated cases and express all scenarios through CustomCases.
type ValidatorTestCase struct {
	Name            string
	Fn              StatelessValidator
	Attribute       string // empty = custom-only mode
	CompliantVal    interface{}
	NonCompliantVal interface{}
	NullCompliant   bool
	CustomCases     []CustomTestCase
}

// CustomTestCase allows hand-written cases alongside generated ones.
type CustomTestCase struct {
	Name      string
	Attrs     map[string]interface{}
	Compliant bool
}

// StatefulValidatorTestCase is the equivalent for stateful validators.
// Generated cases populate the plan mock with test values and provide an
// empty state mock. If a future validator reads from state, use
// StatefulCustomTestCase with separate PlanAttrs/StateAttrs maps.
type StatefulValidatorTestCase struct {
	Name            string
	Fn              StatefulValidator
	Attribute       string
	CompliantVal    interface{}
	NonCompliantVal interface{}
	NullCompliant   bool
	CustomCases     []StatefulCustomTestCase
}

// StatefulCustomTestCase allows hand-written cases for stateful validators
// that need to set different values on plan vs state.
type StatefulCustomTestCase struct {
	Name       string
	PlanAttrs  map[string]interface{}
	StateAttrs map[string]interface{}
	Compliant  bool
}

// RunValidatorTests generates and runs all test cases for a stateless validator.
func RunValidatorTests(t *testing.T, tc ValidatorTestCase) {
	t.Helper()

	// Generated cases (only when Attribute is set)
	if tc.Attribute != "" {
		t.Run(tc.Name+"/compliant", func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{tc.Attribute: tc.CompliantVal})
			if !tc.Fn(context.Background(), m) {
				t.Errorf("expected compliant for %s=%v", tc.Attribute, tc.CompliantVal)
			}
		})

		t.Run(tc.Name+"/noncompliant", func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{tc.Attribute: tc.NonCompliantVal})
			if tc.Fn(context.Background(), m) {
				t.Errorf("expected noncompliant for %s=%v", tc.Attribute, tc.NonCompliantVal)
			}
		})

		t.Run(tc.Name+"/null", func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{tc.Attribute: NullValue})
			result := tc.Fn(context.Background(), m)
			if tc.NullCompliant && !result {
				t.Errorf("expected compliant when %s is null (NullCompliant=true)", tc.Attribute)
			}
			if !tc.NullCompliant && result {
				t.Errorf("expected noncompliant when %s is null (NullCompliant=false)", tc.Attribute)
			}
		})

		t.Run(tc.Name+"/unknown", func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{})
			if !tc.Fn(context.Background(), m) {
				t.Errorf("expected compliant when %s is unknown (deferred)", tc.Attribute)
			}
		})
	}

	// Custom cases
	for _, cc := range tc.CustomCases {
		t.Run(tc.Name+"/"+cc.Name, func(t *testing.T) {
			m := NewMockAccessor(cc.Attrs)
			result := tc.Fn(context.Background(), m)
			if cc.Compliant && !result {
				t.Errorf("expected compliant for custom case %q", cc.Name)
			}
			if !cc.Compliant && result {
				t.Errorf("expected noncompliant for custom case %q", cc.Name)
			}
		})
	}
}

// RunStatefulValidatorTests generates and runs all test cases for a stateful validator.
func RunStatefulValidatorTests(t *testing.T, tc StatefulValidatorTestCase) {
	t.Helper()

	if tc.Attribute != "" {
		t.Run(tc.Name+"/compliant", func(t *testing.T) {
			plan := NewMockAccessor(map[string]interface{}{tc.Attribute: tc.CompliantVal})
			state := NewMockAccessor(map[string]interface{}{})
			if !tc.Fn(context.Background(), plan, state) {
				t.Errorf("expected compliant for %s=%v", tc.Attribute, tc.CompliantVal)
			}
		})

		t.Run(tc.Name+"/noncompliant", func(t *testing.T) {
			plan := NewMockAccessor(map[string]interface{}{tc.Attribute: tc.NonCompliantVal})
			state := NewMockAccessor(map[string]interface{}{})
			if tc.Fn(context.Background(), plan, state) {
				t.Errorf("expected noncompliant for %s=%v", tc.Attribute, tc.NonCompliantVal)
			}
		})

		t.Run(tc.Name+"/null", func(t *testing.T) {
			plan := NewMockAccessor(map[string]interface{}{tc.Attribute: NullValue})
			state := NewMockAccessor(map[string]interface{}{})
			result := tc.Fn(context.Background(), plan, state)
			if tc.NullCompliant && !result {
				t.Errorf("expected compliant when %s is null", tc.Attribute)
			}
			if !tc.NullCompliant && result {
				t.Errorf("expected noncompliant when %s is null", tc.Attribute)
			}
		})

		t.Run(tc.Name+"/unknown", func(t *testing.T) {
			plan := NewMockAccessor(map[string]interface{}{})
			state := NewMockAccessor(map[string]interface{}{})
			if !tc.Fn(context.Background(), plan, state) {
				t.Errorf("expected compliant when %s is unknown", tc.Attribute)
			}
		})
	}

	for _, cc := range tc.CustomCases {
		t.Run(tc.Name+"/"+cc.Name, func(t *testing.T) {
			plan := NewMockAccessor(cc.PlanAttrs)
			state := NewMockAccessor(cc.StateAttrs)
			result := tc.Fn(context.Background(), plan, state)
			if cc.Compliant && !result {
				t.Errorf("expected compliant for custom case %q", cc.Name)
			}
			if !cc.Compliant && result {
				t.Errorf("expected noncompliant for custom case %q", cc.Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Meta-tests — verify the test suite helper itself
// ---------------------------------------------------------------------------

func TestRunValidatorTests_GeneratesFourCases(t *testing.T) {
	callCount := 0
	trivialValidator := func(_ context.Context, config ConfigAccessor) bool {
		callCount++
		enabled, ok := config.GetBool("feature")
		if !ok {
			return config.IsUnknown("feature")
		}
		return enabled
	}

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "trivial feature check",
		Fn:              trivialValidator,
		Attribute:       "feature",
		CompliantVal:    true,
		NonCompliantVal: false,
	})

	if callCount != 4 {
		t.Errorf("expected 4 validator calls (compliant, noncompliant, null, unknown), got %d", callCount)
	}
}

func TestRunValidatorTests_NullCompliantFlag(t *testing.T) {
	// Validator where null is legitimately OK — returns true for null/unknown,
	// but still validates the value when present.
	nullOkValidator := func(_ context.Context, config ConfigAccessor) bool {
		enabled, ok := config.GetBool("optional")
		if !ok {
			return true // null and unknown both OK for this attribute
		}
		return enabled
	}

	RunValidatorTests(t, ValidatorTestCase{
		Name:            "null-compliant optional",
		Fn:              nullOkValidator,
		Attribute:       "optional",
		CompliantVal:    true,
		NonCompliantVal: false,
		NullCompliant:   true,
	})
}

func TestRunValidatorTests_CustomOnlyMode(t *testing.T) {
	callCount := 0
	customValidator := func(_ context.Context, config ConfigAccessor) bool {
		callCount++
		return true
	}

	RunValidatorTests(t, ValidatorTestCase{
		Name: "custom only",
		Fn:   customValidator,
		// Attribute intentionally empty — no generated cases
		CustomCases: []CustomTestCase{
			{Name: "case1", Attrs: map[string]interface{}{"a": "x"}, Compliant: true},
			{Name: "case2", Attrs: map[string]interface{}{"a": "y"}, Compliant: true},
		},
	})

	if callCount != 2 {
		t.Errorf("expected 2 custom-only calls, got %d", callCount)
	}
}
