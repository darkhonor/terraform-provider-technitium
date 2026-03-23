// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import "testing"

// ---------------------------------------------------------------------------
// MockAccessor — test double, no TF dependencies
// ---------------------------------------------------------------------------

// MockAccessor is a test double for ConfigAccessor/PlanAccessor/StateAccessor.
type MockAccessor struct {
	attrs map[string]interface{}
}

// NewMockAccessor constructs a MockAccessor pre-loaded with the given attrs.
func NewMockAccessor(attrs map[string]interface{}) *MockAccessor {
	return &MockAccessor{attrs: attrs}
}

func (m *MockAccessor) GetString(key string) (string, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (m *MockAccessor) GetBool(key string) (bool, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (m *MockAccessor) GetStringList(key string) ([]string, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return nil, false
	}
	sl, ok := v.([]string)
	return sl, ok
}

// nullSentinel is a marker type to distinguish null from missing (unknown).
type nullSentinel struct{}

// NullValue is the sentinel stored in MockAccessor to represent a null attribute.
var NullValue = nullSentinel{}

func (m *MockAccessor) IsNull(key string) bool {
	v, ok := m.attrs[key]
	if !ok {
		return false // missing key = unknown, not null
	}
	_, isNull := v.(nullSentinel)
	return isNull
}

func (m *MockAccessor) IsUnknown(key string) bool {
	_, ok := m.attrs[key]
	return !ok // missing key = unknown
}

// Interface compliance assertions.
var _ ConfigAccessor = &MockAccessor{}
var _ PlanAccessor = &MockAccessor{}
var _ StateAccessor = &MockAccessor{}

func TestMockAccessor_IsNull_ReturnsTrueForNullSentinel(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"dnssec.enabled": NullValue,
	})
	if !m.IsNull("dnssec.enabled") {
		t.Error("expected IsNull=true for NullValue sentinel")
	}
	if m.IsUnknown("dnssec.enabled") {
		t.Error("expected IsUnknown=false for NullValue sentinel")
	}
}

func TestMockAccessor_IsUnknown_ReturnsTrueForMissingKey(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	if m.IsNull("dnssec.enabled") {
		t.Error("expected IsNull=false for missing key")
	}
	if !m.IsUnknown("dnssec.enabled") {
		t.Error("expected IsUnknown=true for missing key")
	}
}

func TestMockAccessor_IsNull_FalseForPresentValue(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"dnssec.enabled": true,
	})
	if m.IsNull("dnssec.enabled") {
		t.Error("expected IsNull=false for present value")
	}
	if m.IsUnknown("dnssec.enabled") {
		t.Error("expected IsUnknown=false for present value")
	}
}
