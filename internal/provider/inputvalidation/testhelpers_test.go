// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

// MockAccessor is a test double for ConfigAccessor.
type MockAccessor struct {
	attrs map[string]interface{}
}

// NewMockAccessor creates a MockAccessor pre-loaded with the given attrs.
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

func (m *MockAccessor) GetInt64(key string) (int64, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return 0, false
	}
	i, ok := v.(int64)
	return i, ok
}

func (m *MockAccessor) GetStringList(key string) ([]string, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return nil, false
	}
	sl, ok := v.([]string)
	return sl, ok
}

// Interface compliance assertion.
var _ ConfigAccessor = &MockAccessor{}
