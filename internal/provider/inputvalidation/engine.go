// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import "context"

// TargetResource identifies which resource a set of validation rules applies to.
type TargetResource string

const (
	ResourceRecord TargetResource = "technitium_record"
	ResourceZone   TargetResource = "technitium_zone"
)

// ValidationRule defines a single input validation check.
type ValidationRule struct {
	// Name is a unique identifier for this rule (e.g., "a_record_ipv4").
	Name string
	// Description is a human-readable summary for diagnostics.
	Description string
	// Resource is the target resource this rule applies to.
	Resource TargetResource
	// Validate runs the rule against the given config and returns any findings.
	// An empty slice means the input is valid.
	Validate func(ctx context.Context, config ConfigAccessor) []Finding
}

// Finding represents a single validation failure.
type Finding struct {
	// Attribute is the schema attribute that failed validation (e.g., "value").
	Attribute string
	// Summary is a short error message for the Terraform diagnostic summary.
	Summary string
	// Detail is an actionable message explaining the expected format.
	Detail string
}

// ConfigAccessor abstracts read access to Terraform configuration values.
// This is intentionally decoupled from the STIG engine's ConfigAccessor
// to maintain package independence.
type ConfigAccessor interface {
	GetString(path string) (string, bool)
	GetBool(path string) (bool, bool)
	GetInt64(path string) (int64, bool)
	GetStringList(path string) ([]string, bool)
}

// Registry holds validation rules indexed by target resource.
type Registry struct {
	rules map[TargetResource][]ValidationRule
}

// NewRegistry creates an empty validation rule registry.
func NewRegistry() *Registry {
	return &Registry{
		rules: make(map[TargetResource][]ValidationRule),
	}
}

// Register adds a validation rule to the registry.
func (r *Registry) Register(rule ValidationRule) {
	r.rules[rule.Resource] = append(r.rules[rule.Resource], rule)
}

// RulesFor returns all validation rules registered for the given resource.
// Returns an empty slice if no rules are registered.
func (r *Registry) RulesFor(resource TargetResource) []ValidationRule {
	return r.rules[resource]
}

// ---------------------------------------------------------------------------
// MockAccessor — test double
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// RunRules — executes all rules for a given resource
// ---------------------------------------------------------------------------

// RunRules executes all registered rules for the given resource and returns
// all findings. An empty slice means all validations passed.
func (r *Registry) RunRules(ctx context.Context, resource TargetResource, config ConfigAccessor) []Finding {
	var findings []Finding
	for _, rule := range r.rules[resource] {
		if results := rule.Validate(ctx, config); len(results) > 0 {
			findings = append(findings, results...)
		}
	}
	return findings
}
