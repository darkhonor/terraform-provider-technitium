// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

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

// Interface compliance assertions.
var _ ConfigAccessor = &MockAccessor{}
var _ PlanAccessor = &MockAccessor{}
var _ StateAccessor = &MockAccessor{}
