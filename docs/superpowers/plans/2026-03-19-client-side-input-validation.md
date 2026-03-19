# Client-Side DNS Record Input Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add client-side input validation for all 9 DNS record types so users get clear errors at `terraform validate` time instead of opaque API failures.

**Architecture:** New `internal/provider/inputvalidation/` package with a registry pattern, fully decoupled from the STIG engine. Each resource registers its validation rules. A `ConfigValidator` adapter wires into the record resource alongside the existing STIG validator.

**Tech Stack:** Go standard library (`net`, `strings`, `regexp`), Terraform Plugin Framework (`resource.ConfigValidator`)

**Spec:** `docs/superpowers/specs/2026-03-19-client-side-input-validation-design.md`

---

### Task 1: Core Types and Registry

**Files:**
- Create: `internal/provider/inputvalidation/engine.go`
- Create: `internal/provider/inputvalidation/engine_test.go`

- [ ] **Step 1: Write the failing test for Registry**

Create `internal/provider/inputvalidation/engine_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run TestRegistry`
Expected: Compilation error — package does not exist yet.

- [ ] **Step 3: Write the core types and registry implementation**

Create `internal/provider/inputvalidation/engine.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run TestRegistry`
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/inputvalidation/engine.go internal/provider/inputvalidation/engine_test.go
git commit -m "feat(inputvalidation): add core types and registry (Vikunja #25)"
```

---

### Task 2: MockAccessor and ConfigValidator Adapter

**Files:**
- Modify: `internal/provider/inputvalidation/engine.go`
- Modify: `internal/provider/inputvalidation/engine_test.go`

- [ ] **Step 1: Write the failing test for MockAccessor and ConfigValidator adapter**

Append to `internal/provider/inputvalidation/engine_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestMockAccessor|TestRunRules"`
Expected: Compilation error — `NewMockAccessor` and `RunRules` do not exist.

- [ ] **Step 3: Implement MockAccessor and RunRules**

Add to `internal/provider/inputvalidation/engine.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestMockAccessor|TestRunRules"`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/inputvalidation/engine.go internal/provider/inputvalidation/engine_test.go
git commit -m "feat(inputvalidation): add MockAccessor and RunRules (Vikunja #25)"
```

---

### Task 3: Shared Validation Helpers

**Files:**
- Create: `internal/provider/inputvalidation/helpers.go`
- Create: `internal/provider/inputvalidation/helpers_test.go`

- [ ] **Step 1: Write failing tests for all helpers**

Create `internal/provider/inputvalidation/helpers_test.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import "testing"

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.0.2.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"10.110.11.154", true},
		// Invalid
		{"", false},
		{"2001:db8::1", false},                   // IPv6
		{"::ffff:192.0.2.1", false},               // v4-mapped IPv6
		{"192.168.1.0/24", false},                 // CIDR
		{"example.com", false},                    // hostname
		{"999.999.999.999", false},                // out of range
		{"192.168.1", false},                      // incomplete
		{"fe80::1%eth0", false},                   // zone-scoped IPv6
		{" 192.0.2.1", false},                     // leading space
		{"192.0.2.1 ", false},                     // trailing space
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidIPv4(tt.input); got != tt.want {
				t.Errorf("isValidIPv4(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"2001:db8::1", true},
		{"::1", true},
		{"fe80::1", true},
		{"fdd5:e282:43b8:5303:1234:5678:cafe:9012", true},
		// Invalid
		{"", false},
		{"192.0.2.1", false},                      // IPv4
		{"::ffff:192.0.2.1", false},               // v4-mapped — reject
		{"example.com", false},                    // hostname
		{"fe80::1%eth0", false},                   // zone-scoped
		{"2001:db8::g", false},                    // invalid hex
		{" 2001:db8::1", false},                   // leading space
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidIPv6(tt.input); got != tt.want {
				t.Errorf("isValidIPv6(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidFQDN(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"example.com.", true},                    // trailing dot OK
		{"mail.example.com", true},
		{"mail.example.com.", true},
		{"sub.domain.example.com", true},
		{"a.b", true},                             // minimal FQDN
		{"selector._domainkey.example.com", true}, // DKIM CNAME target
		{"_sip._tcp.example.com", true},           // SRV-style name
		// Invalid
		{"", false},
		{"localhost", false},                      // single label — not FQDN
		{"192.0.2.1", false},                      // IP address
		{"2001:db8::1", false},                    // IPv6
		{"-example.com", false},                   // leading hyphen
		{"example-.com", false},                   // trailing hyphen in label
		{".example.com", false},                   // leading dot
		{"exam ple.com", false},                   // space in label
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidFQDN(tt.input); got != tt.want {
				t.Errorf("isValidFQDN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"rancher", true},                         // single label OK
		{"example.com", true},
		{"example.com.", true},
		{"mail.example.com", true},
		{"host-name", true},                       // hyphen OK
		{"a", true},                               // single char
		{"_dmarc", true},                          // underscore label
		// Invalid
		{"", false},
		{"192.0.2.1", false},                      // IP address
		{"2001:db8::1", false},                    // IPv6
		{"-host", false},                          // leading hyphen
		{"host-", false},                          // trailing hyphen
		{"host name", false},                      // space
		{".host", false},                          // leading dot
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidHostname(tt.input); got != tt.want {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"::1", true},
		// Not IPs
		{"example.com", false},
		{"rancher", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isIPAddress(tt.input); got != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsInRange(t *testing.T) {
	tests := []struct {
		val, min, max int64
		want          bool
	}{
		{0, 0, 65535, true},
		{65535, 0, 65535, true},
		{100, 0, 65535, true},
		{-1, 0, 65535, false},
		{65536, 0, 65535, false},
	}
	for _, tt := range tests {
		if got := isInRange(tt.val, tt.min, tt.max); got != tt.want {
			t.Errorf("isInRange(%d, %d, %d) = %v, want %v", tt.val, tt.min, tt.max, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestIsValid|TestIsIP|TestIsInRange"`
Expected: Compilation error — helper functions do not exist.

- [ ] **Step 3: Implement all helpers**

Create `internal/provider/inputvalidation/helpers.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"net"
	"regexp"
	"strings"
)

// labelPattern matches a valid DNS label per RFC 1123 (extended):
// starts with alphanumeric or underscore, ends with alphanumeric,
// hyphens and underscores allowed in the middle.
// Underscores support SRV names and DKIM CNAME targets.
// labelPattern matches a valid DNS label: starts with alphanumeric or underscore,
// ends with alphanumeric, hyphens and underscores allowed in the middle.
// Underscores are needed for SRV names (_sip._tcp) and DKIM CNAME targets
// (selector._domainkey.example.com).
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

// isValidIPv4 returns true if s is a valid IPv4 address (not IPv6, not CIDR).
func isValidIPv4(s string) bool {
	// Reject if it contains whitespace or CIDR notation.
	if strings.ContainsAny(s, " /") {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	// Must be a pure v4 address — To4() returns non-nil for v4 AND v4-mapped v6.
	// Reject v4-mapped v6 by ensuring the string does not contain ':'.
	return ip.To4() != nil && !strings.Contains(s, ":")
}

// isValidIPv6 returns true if s is a valid IPv6 address (not v4, not v4-mapped).
func isValidIPv6(s string) bool {
	if strings.ContainsAny(s, " %") {
		return false // reject zone-scoped
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	// Must contain a colon (IPv6) and must not be v4-mapped.
	if !strings.Contains(s, ":") {
		return false
	}
	// Reject v4-mapped addresses like ::ffff:192.0.2.1
	if ip.To4() != nil {
		return false
	}
	return true
}

// isValidFQDN returns true if s is a valid fully qualified domain name.
// Requires at least one dot (distinguishes from single-label hostnames).
// Trailing dot is optional. Rejects IP addresses.
func isValidFQDN(s string) bool {
	if s == "" {
		return false
	}
	if isIPAddress(s) {
		return false
	}

	// Strip trailing dot for validation.
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return false
	}

	labels := strings.Split(name, ".")
	// FQDN requires at least 2 labels.
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// isValidHostname returns true if s is a valid hostname (single-label or FQDN).
// Trailing dot is optional. Rejects IP addresses.
func isValidHostname(s string) bool {
	if s == "" {
		return false
	}
	if isIPAddress(s) {
		return false
	}

	// Strip trailing dot for validation.
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return false
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// isIPAddress returns true if s can be parsed as an IPv4 or IPv6 address.
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// isInRange returns true if val is between min and max (inclusive).
func isInRange(val, min, max int64) bool {
	return val >= min && val <= max
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestIsValid|TestIsIP|TestIsInRange"`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/inputvalidation/helpers.go internal/provider/inputvalidation/helpers_test.go
git commit -m "feat(inputvalidation): add shared validation helpers (Vikunja #25)"
```

---

### Task 4: Record Type Validator and A/AAAA/TXT Rules

**Files:**
- Create: `internal/provider/inputvalidation/dns_record.go`
- Create: `internal/provider/inputvalidation/dns_record_test.go`

- [ ] **Step 1: Write failing tests for record type validation and simple record types**

Create `internal/provider/inputvalidation/dns_record_test.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"testing"
)

// --- Record type validator ---

func TestValidateRecordType_Valid(t *testing.T) {
	validTypes := []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "CAA"}
	for _, rt := range validTypes {
		t.Run(rt, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": rt})
			rule := validateRecordType()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings for type %q, got %d: %v", rt, len(findings), findings)
			}
		})
	}
}

func TestValidateRecordType_Invalid(t *testing.T) {
	invalidTypes := []string{"a", "aaaa", "AAAAAA", "mx", "INVALID", ""}
	for _, rt := range invalidTypes {
		t.Run(rt, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": rt})
			rule := validateRecordType()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding for type %q, got %d", rt, len(findings))
			}
		})
	}
}

func TestValidateRecordType_Missing(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{})
	rule := validateRecordType()
	findings := rule.Validate(context.Background(), m)
	// type is Required in schema, so missing at this level means skip (schema catches it)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing type, got %d", len(findings))
	}
}

// --- A record ---

func TestValidateARecord_Valid(t *testing.T) {
	tests := []string{"192.0.2.1", "10.110.11.154", "0.0.0.0", "255.255.255.255"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "A", "value": v})
			rule := validateARecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateARecord_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ipv6", "2001:db8::1"},
		{"fqdn", "example.com"},
		{"cidr", "192.168.1.0/24"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "A", "value": tt.value})
			rule := validateARecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
		})
	}
}

func TestValidateARecord_SkipsOtherTypes(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"type": "AAAA", "value": "not-ipv4"})
	rule := validateARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 0 {
		t.Errorf("A record validator should skip non-A types")
	}
}

// --- AAAA record ---

func TestValidateAAAARecord_Valid(t *testing.T) {
	tests := []string{"2001:db8::1", "::1", "fe80::1"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "AAAA", "value": v})
			rule := validateAAAARecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateAAAARecord_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ipv4", "192.0.2.1"},
		{"v4mapped", "::ffff:192.0.2.1"},
		{"fqdn", "example.com"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "AAAA", "value": tt.value})
			rule := validateAAAARecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
		})
	}
}

// --- TXT record ---

func TestValidateTXTRecord_Valid(t *testing.T) {
	tests := []string{"v=spf1 -all", "some text", "a"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "TXT", "value": v})
			rule := validateTXTRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestValidateTXTRecord_Empty(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{"type": "TXT", "value": ""})
	rule := validateTXTRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for empty TXT, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateRecordType|TestValidateARecord|TestValidateAAAARecord|TestValidateTXTRecord"`
Expected: Compilation error — functions do not exist.

- [ ] **Step 3: Implement dns_record.go with type validator and A/AAAA/TXT rules**

Create `internal/provider/inputvalidation/dns_record.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"fmt"
)

// validRecordTypes is the set of record types supported by the provider.
var validRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"NS": true, "PTR": true, "SRV": true, "TXT": true, "CAA": true,
}

// registerRecordRules adds all DNS record validation rules to the registry.
func registerRecordRules(r *Registry) {
	r.Register(validateRecordType())
	r.Register(validateARecord())
	r.Register(validateAAAARecord())
	r.Register(validateTXTRecord())
	r.Register(validateCNAMERecord())
	r.Register(validateMXRecord())
	r.Register(validateNSRecord())
	r.Register(validatePTRRecord())
	r.Register(validateSRVRecord())
	r.Register(validateCAARecord())
}

// DefaultRegistry returns a registry pre-loaded with all built-in validation rules.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	registerRecordRules(r)
	return r
}

// ---------------------------------------------------------------------------
// Record type validator
// ---------------------------------------------------------------------------

func validateRecordType() ValidationRule {
	return ValidationRule{
		Name:        "record_type",
		Description: "Validates the record type is one of the 9 supported types",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok {
				return nil // type is Required — schema handles missing
			}
			if !validRecordTypes[rt] {
				return []Finding{{
					Attribute: "type",
					Summary:   fmt.Sprintf("Invalid record type: %q", rt),
					Detail:    "Supported record types are: A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA (case-sensitive).",
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// A record
// ---------------------------------------------------------------------------

func validateARecord() ValidationRule {
	return ValidationRule{
		Name:        "a_record_ipv4",
		Description: "A record value must be a valid IPv4 address",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "A" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil // value is Required — schema handles missing
			}
			if !isValidIPv4(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid A record value: %q is not a valid IPv4 address", value),
					Detail:    `A records require a valid IPv4 address (e.g., "192.0.2.1").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// AAAA record
// ---------------------------------------------------------------------------

func validateAAAARecord() ValidationRule {
	return ValidationRule{
		Name:        "aaaa_record_ipv6",
		Description: "AAAA record value must be a valid IPv6 address",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "AAAA" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidIPv6(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid AAAA record value: %q is not a valid IPv6 address", value),
					Detail:    `AAAA records require a valid IPv6 address (e.g., "2001:db8::1").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// TXT record
// ---------------------------------------------------------------------------

func validateTXTRecord() ValidationRule {
	return ValidationRule{
		Name:        "txt_record_nonempty",
		Description: "TXT record value must not be empty",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "TXT" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if value == "" {
				return []Finding{{
					Attribute: "value",
					Summary:   "Invalid TXT record value: value must not be empty",
					Detail:    `TXT records require a non-empty text value (e.g., "v=spf1 -all").`,
				}}
			}
			return nil
		},
	}
}
```

Note: `validateCNAMERecord`, `validateMXRecord`, `validateNSRecord`, `validatePTRRecord`, `validateSRVRecord`, and `validateCAARecord` are declared in the `registerRecordRules` call but implemented in the next tasks. Add temporary stubs so the file compiles:

```go
// Stubs — implemented in subsequent tasks.
func validateCNAMERecord() ValidationRule {
	return ValidationRule{Name: "cname_record_fqdn", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
func validateMXRecord() ValidationRule {
	return ValidationRule{Name: "mx_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
func validateNSRecord() ValidationRule {
	return ValidationRule{Name: "ns_record_fqdn", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
func validatePTRRecord() ValidationRule {
	return ValidationRule{Name: "ptr_record_hostname", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
func validateSRVRecord() ValidationRule {
	return ValidationRule{Name: "srv_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
func validateCAARecord() ValidationRule {
	return ValidationRule{Name: "caa_record", Resource: ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding { return nil }}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateRecordType|TestValidateARecord|TestValidateAAAARecord|TestValidateTXTRecord"`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/inputvalidation/dns_record.go internal/provider/inputvalidation/dns_record_test.go
git commit -m "feat(inputvalidation): add type validator and A/AAAA/TXT rules (Vikunja #25)"
```

---

### Task 5: CNAME, NS, PTR Rules

**Files:**
- Modify: `internal/provider/inputvalidation/dns_record.go` (replace stubs)
- Modify: `internal/provider/inputvalidation/dns_record_test.go`

- [ ] **Step 1: Write failing tests for CNAME, NS, PTR**

Append to `internal/provider/inputvalidation/dns_record_test.go`:

```go
// --- CNAME record ---

func TestValidateCNAMERecord_Valid(t *testing.T) {
	tests := []string{"example.com", "example.com.", "sub.example.com"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "CNAME", "value": v})
			rule := validateCNAMERecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateCNAMERecord_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ipv4", "192.0.2.1"},
		{"ipv6", "2001:db8::1"},
		{"empty", ""},
		{"single_label", "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "CNAME", "value": tt.value})
			rule := validateCNAMERecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
		})
	}
}

// --- NS record ---

func TestValidateNSRecord_Valid(t *testing.T) {
	tests := []string{"ns1.example.com", "ns1.example.com."}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "NS", "value": v})
			rule := validateNSRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateNSRecord_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ipv4", "192.0.2.1"},
		{"ipv6", "2001:db8::1"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "NS", "value": tt.value})
			rule := validateNSRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
		})
	}
}

// --- PTR record ---

func TestValidatePTRRecord_Valid(t *testing.T) {
	tests := []string{"rancher", "rancher.asan.darkhonor.net", "rancher.asan.darkhonor.net.", "154"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "PTR", "value": v})
			rule := validatePTRRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidatePTRRecord_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ipv4", "192.0.2.1"},
		{"ipv6", "2001:db8::1"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(map[string]interface{}{"type": "PTR", "value": tt.value})
			rule := validatePTRRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateCNAMERecord|TestValidateNSRecord|TestValidatePTRRecord"`
Expected: Tests fail — stubs return no findings for invalid input.

- [ ] **Step 3: Replace stubs with real implementations**

In `internal/provider/inputvalidation/dns_record.go`, replace the CNAME, NS, PTR stubs:

```go
// ---------------------------------------------------------------------------
// CNAME record
// ---------------------------------------------------------------------------

func validateCNAMERecord() ValidationRule {
	return ValidationRule{
		Name:        "cname_record_fqdn",
		Description: "CNAME record value must be a valid FQDN",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "CNAME" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidFQDN(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid CNAME record value: %q is not a valid FQDN", value),
					Detail:    `CNAME records require a valid fully qualified domain name (e.g., "target.example.com.").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// NS record
// ---------------------------------------------------------------------------

func validateNSRecord() ValidationRule {
	return ValidationRule{
		Name:        "ns_record_fqdn",
		Description: "NS record value must be a valid FQDN",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "NS" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidFQDN(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid NS record value: %q is not a valid FQDN", value),
					Detail:    `NS records require a valid fully qualified domain name (e.g., "ns1.example.com.").`,
				}}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// PTR record
// ---------------------------------------------------------------------------

func validatePTRRecord() ValidationRule {
	return ValidationRule{
		Name:        "ptr_record_hostname",
		Description: "PTR record value must be a valid hostname (single-label or FQDN)",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "PTR" {
				return nil
			}
			value, ok := config.GetString("value")
			if !ok {
				return nil
			}
			if !isValidHostname(value) {
				return []Finding{{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid PTR record value: %q is not a valid hostname", value),
					Detail:    `PTR records require a valid hostname — either a single label (e.g., "rancher") or FQDN (e.g., "rancher.example.com.").`,
				}}
			}
			return nil
		},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateCNAMERecord|TestValidateNSRecord|TestValidatePTRRecord"`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/inputvalidation/dns_record.go internal/provider/inputvalidation/dns_record_test.go
git commit -m "feat(inputvalidation): add CNAME, NS, PTR rules (Vikunja #25)"
```

---

### Task 6: MX, SRV, CAA Rules (with Cross-Field Presence)

**Files:**
- Modify: `internal/provider/inputvalidation/dns_record.go` (replace stubs)
- Modify: `internal/provider/inputvalidation/dns_record_test.go`

- [ ] **Step 1: Write failing tests for MX, SRV, CAA**

Append to `internal/provider/inputvalidation/dns_record_test.go`:

```go
// --- MX record ---

func TestValidateMXRecord_Valid(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "MX", "value": "mail.example.com.", "priority": int64(10),
	})
	rule := validateMXRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestValidateMXRecord_InvalidValue(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "MX", "value": "192.0.2.1", "priority": int64(10),
	})
	rule := validateMXRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestValidateMXRecord_MissingPriority(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "MX", "value": "mail.example.com.",
	})
	rule := validateMXRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for missing priority, got %d", len(findings))
	}
}

func TestValidateMXRecord_PriorityOutOfRange(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "MX", "value": "mail.example.com.", "priority": int64(70000),
	})
	rule := validateMXRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for out-of-range priority, got %d", len(findings))
	}
}

// --- SRV record ---

func TestValidateSRVRecord_Valid(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "SRV", "value": "target.example.com.",
		"priority": int64(10), "weight": int64(60), "port": int64(5060),
	})
	rule := validateSRVRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestValidateSRVRecord_InvalidTarget(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "SRV", "value": "192.0.2.1",
		"priority": int64(10), "weight": int64(60), "port": int64(5060),
	})
	rule := validateSRVRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestValidateSRVRecord_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]interface{}
	}{
		{"missing_priority", map[string]interface{}{"type": "SRV", "value": "t.example.com.", "weight": int64(60), "port": int64(5060)}},
		{"missing_weight", map[string]interface{}{"type": "SRV", "value": "t.example.com.", "priority": int64(10), "port": int64(5060)}},
		{"missing_port", map[string]interface{}{"type": "SRV", "value": "t.example.com.", "priority": int64(10), "weight": int64(60)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(tt.attrs)
			rule := validateSRVRecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateSRVRecord_PortOutOfRange(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "SRV", "value": "target.example.com.",
		"priority": int64(10), "weight": int64(60), "port": int64(70000),
	})
	rule := validateSRVRecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for out-of-range port, got %d", len(findings))
	}
}

// --- CAA record ---

func TestValidateCAARecord_Valid(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "CAA", "value": "letsencrypt.org",
		"caa_flags": int64(0), "caa_tag": "issue",
	})
	rule := validateCAARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestValidateCAARecord_Flags128(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "CAA", "value": "letsencrypt.org",
		"caa_flags": int64(128), "caa_tag": "issuewild",
	})
	rule := validateCAARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestValidateCAARecord_InvalidFlags(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "CAA", "value": "letsencrypt.org",
		"caa_flags": int64(1), "caa_tag": "issue",
	})
	rule := validateCAARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestValidateCAARecord_InvalidTag(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "CAA", "value": "letsencrypt.org",
		"caa_flags": int64(0), "caa_tag": "invalid",
	})
	rule := validateCAARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestValidateCAARecord_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]interface{}
	}{
		{"missing_flags", map[string]interface{}{"type": "CAA", "value": "ca.example.com", "caa_tag": "issue"}},
		{"missing_tag", map[string]interface{}{"type": "CAA", "value": "ca.example.com", "caa_flags": int64(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockAccessor(tt.attrs)
			rule := validateCAARecord()
			findings := rule.Validate(context.Background(), m)
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d: %v", len(findings), findings)
			}
		})
	}
}

func TestValidateCAARecord_EmptyValue(t *testing.T) {
	m := NewMockAccessor(map[string]interface{}{
		"type": "CAA", "value": "",
		"caa_flags": int64(0), "caa_tag": "issue",
	})
	rule := validateCAARecord()
	findings := rule.Validate(context.Background(), m)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for empty value, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateMXRecord|TestValidateSRVRecord|TestValidateCAARecord"`
Expected: Tests fail — stubs return no findings.

- [ ] **Step 3: Replace MX, SRV, CAA stubs with real implementations**

In `internal/provider/inputvalidation/dns_record.go`, replace the three stubs:

```go
// ---------------------------------------------------------------------------
// MX record
// ---------------------------------------------------------------------------

func validateMXRecord() ValidationRule {
	return ValidationRule{
		Name:        "mx_record",
		Description: "MX record: value must be FQDN, priority required and in range",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "MX" {
				return nil
			}
			var findings []Finding

			// Check priority is present.
			priority, hasPriority := config.GetInt64("priority")
			if !hasPriority {
				findings = append(findings, Finding{
					Attribute: "priority",
					Summary:   "MX record missing required field: priority",
					Detail:    "MX records require a priority value (0-65535).",
				})
			} else if !isInRange(priority, 0, 65535) {
				findings = append(findings, Finding{
					Attribute: "priority",
					Summary:   fmt.Sprintf("Invalid MX record priority: %d is out of range", priority),
					Detail:    "MX record priority must be between 0 and 65535.",
				})
			}

			// Check value is FQDN.
			value, ok := config.GetString("value")
			if !ok {
				return findings
			}
			if !isValidFQDN(value) {
				findings = append(findings, Finding{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid MX record value: %q is not a valid FQDN", value),
					Detail:    `MX records require a valid fully qualified domain name (e.g., "mail.example.com.").`,
				})
			}

			return findings
		},
	}
}

// ---------------------------------------------------------------------------
// SRV record
// ---------------------------------------------------------------------------

func validateSRVRecord() ValidationRule {
	return ValidationRule{
		Name:        "srv_record",
		Description: "SRV record: target must be FQDN, priority/weight/port required and in range",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "SRV" {
				return nil
			}
			var findings []Finding

			// Check required numeric fields.
			type numField struct {
				name string
				attr string
			}
			for _, f := range []numField{
				{"priority", "priority"},
				{"weight", "weight"},
				{"port", "port"},
			} {
				val, has := config.GetInt64(f.attr)
				if !has {
					findings = append(findings, Finding{
						Attribute: f.attr,
						Summary:   fmt.Sprintf("SRV record missing required field: %s", f.name),
						Detail:    fmt.Sprintf("SRV records require %s (0-65535).", f.name),
					})
				} else if !isInRange(val, 0, 65535) {
					findings = append(findings, Finding{
						Attribute: f.attr,
						Summary:   fmt.Sprintf("Invalid SRV record %s: %d is out of range", f.name, val),
						Detail:    fmt.Sprintf("SRV record %s must be between 0 and 65535.", f.name),
					})
				}
			}

			// Check target is FQDN.
			value, ok := config.GetString("value")
			if !ok {
				return findings
			}
			if !isValidFQDN(value) {
				findings = append(findings, Finding{
					Attribute: "value",
					Summary:   fmt.Sprintf("Invalid SRV record target: %q is not a valid FQDN", value),
					Detail:    `SRV records require a valid fully qualified domain name as target (e.g., "sip.example.com.").`,
				})
			}

			return findings
		},
	}
}

// ---------------------------------------------------------------------------
// CAA record
// ---------------------------------------------------------------------------

// validCAATags is the set of recognized CAA tags per RFC 8659.
var validCAATags = map[string]bool{
	"issue":     true,
	"issuewild": true,
	"iodef":     true,
}

func validateCAARecord() ValidationRule {
	return ValidationRule{
		Name:        "caa_record",
		Description: "CAA record: flags must be 0/128, tag must be issue/issuewild/iodef, value non-empty",
		Resource:    ResourceRecord,
		Validate: func(ctx context.Context, config ConfigAccessor) []Finding {
			rt, ok := config.GetString("type")
			if !ok || rt != "CAA" {
				return nil
			}
			var findings []Finding

			// Check required fields present.
			flags, hasFlags := config.GetInt64("caa_flags")
			if !hasFlags {
				findings = append(findings, Finding{
					Attribute: "caa_flags",
					Summary:   "CAA record missing required field: caa_flags",
					Detail:    "CAA records require caa_flags (0 = non-critical, 128 = critical).",
				})
			} else if flags != 0 && flags != 128 {
				findings = append(findings, Finding{
					Attribute: "caa_flags",
					Summary:   fmt.Sprintf("Invalid CAA record caa_flags: %d is not valid", flags),
					Detail:    "CAA record caa_flags must be 0 (non-critical) or 128 (critical).",
				})
			}

			tag, hasTag := config.GetString("caa_tag")
			if !hasTag {
				findings = append(findings, Finding{
					Attribute: "caa_tag",
					Summary:   "CAA record missing required field: caa_tag",
					Detail:    `CAA records require caa_tag: one of "issue", "issuewild", "iodef".`,
				})
			} else if !validCAATags[tag] {
				findings = append(findings, Finding{
					Attribute: "caa_tag",
					Summary:   fmt.Sprintf("Invalid CAA record caa_tag: %q is not a recognized CAA tag", tag),
					Detail:    `CAA records require one of: "issue", "issuewild", "iodef".`,
				})
			}

			// Check value non-empty.
			value, ok := config.GetString("value")
			if ok && value == "" {
				findings = append(findings, Finding{
					Attribute: "value",
					Summary:   "Invalid CAA record value: value must not be empty",
					Detail:    `CAA records require a non-empty value (e.g., "letsencrypt.org").`,
				})
			}

			return findings
		},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestValidateMXRecord|TestValidateSRVRecord|TestValidateCAARecord"`
Expected: All tests PASS.

- [ ] **Step 5: Run full test suite for the package**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/inputvalidation/dns_record.go internal/provider/inputvalidation/dns_record_test.go
git commit -m "feat(inputvalidation): add MX, SRV, CAA rules with cross-field presence (Vikunja #25)"
```

---

### Task 7: TFConfigAdapter with GetInt64 and ConfigValidator Adapter

**Files:**
- Create: `internal/provider/inputvalidation/tf_adapter.go`
- Create: `internal/provider/input_config_validator.go`

- [ ] **Step 1: Create the TF adapter**

Create `internal/provider/inputvalidation/tf_adapter.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// parsePath converts a dot-separated string (e.g. "caa_flags") into a
// framework path.Path.
func parsePath(dotPath string) path.Path {
	parts := strings.Split(dotPath, ".")
	p := path.Root(parts[0])
	for _, part := range parts[1:] {
		p = p.AtName(part)
	}
	return p
}

// TFConfigAdapter wraps tfsdk.Config to implement ConfigAccessor.
type TFConfigAdapter struct {
	Config tfsdk.Config
}

func (a *TFConfigAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFConfigAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFConfigAdapter) GetInt64(dotPath string) (int64, bool) {
	var val types.Int64
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return 0, false
	}
	return val.ValueInt64(), true
}

func (a *TFConfigAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return nil, false
	}
	var result []string
	for _, elem := range val.Elements() {
		if s, ok := elem.(types.String); ok {
			result = append(result, s.ValueString())
		}
	}
	return result, true
}

// Interface compliance assertion.
var _ ConfigAccessor = &TFConfigAdapter{}
```

- [ ] **Step 2: Create the ConfigValidator adapter in the provider package**

Create `internal/provider/input_config_validator.go`:

```go
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/inputvalidation"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// inputConfigValidator implements resource.ConfigValidator for input validation.
type inputConfigValidator struct {
	registry *inputvalidation.Registry
	resource inputvalidation.TargetResource
}

func newInputConfigValidator(registry *inputvalidation.Registry, resource inputvalidation.TargetResource) inputConfigValidator {
	return inputConfigValidator{registry: registry, resource: resource}
}

func (v inputConfigValidator) Description(_ context.Context) string {
	return "Validates resource configuration inputs have correct format and required fields"
}

func (v inputConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v inputConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	adapter := &inputvalidation.TFConfigAdapter{Config: req.Config}
	findings := v.registry.RunRules(ctx, v.resource, adapter)
	for _, f := range findings {
		resp.Diagnostics.AddError(f.Summary, f.Detail)
	}
}
```

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go build ./...`
Expected: Build succeeds.

- [ ] **Step 4: Commit**

```bash
git add internal/provider/inputvalidation/tf_adapter.go internal/provider/input_config_validator.go
git commit -m "feat(inputvalidation): add TFConfigAdapter and ConfigValidator adapter (Vikunja #25)"
```

---

### Task 8: Wire Into Record Resource

**Files:**
- Modify: `internal/provider/record_resource.go:30-37` (add inputRegistry field)
- Modify: `internal/provider/record_resource.go:165-172` (update ConfigValidators)

- [ ] **Step 1: Add inputRegistry field and update NewRecordResource**

In `internal/provider/record_resource.go`, update the struct and constructor:

Change `NewRecordResource`:
```go
func NewRecordResource() resource.Resource {
	return &RecordResource{
		inputRegistry: inputvalidation.DefaultRegistry(),
	}
}
```

Change `RecordResource` struct:
```go
type RecordResource struct {
	client        *client.Client
	providerData  *TechnitiumProviderData
	inputRegistry *inputvalidation.Registry
}
```

Add import: `"github.com/darkhonor/terraform-provider-technitium/internal/provider/inputvalidation"`

- [ ] **Step 2: Update ConfigValidators method**

Replace the existing `ConfigValidators` method:

```go
func (r *RecordResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	cvs := []resource.ConfigValidator{
		newInputConfigValidator(r.inputRegistry, inputvalidation.ResourceRecord),
	}
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		cvs = append(cvs, newSTIGConfigValidator(r.providerData.STIGEngine, validators.ResourceRecord))
	}
	return cvs
}
```

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go build ./...`
Expected: Build succeeds.

- [ ] **Step 4: Run existing unit tests to verify no regressions**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/... -v -count=1 -short`
Expected: All existing tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/record_resource.go
git commit -m "feat(inputvalidation): wire input validators into record resource (Vikunja #25)"
```

---

### Task 9: DefaultRegistry Integration Test

**Files:**
- Modify: `internal/provider/inputvalidation/engine_test.go`

- [ ] **Step 1: Write integration test for DefaultRegistry**

Append to `internal/provider/inputvalidation/engine_test.go`:

```go
func TestDefaultRegistry_HasAllRecordRules(t *testing.T) {
	r := DefaultRegistry()
	rules := r.RulesFor(ResourceRecord)

	// Expect 10 rules: record_type + 9 record type validators
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
```

- [ ] **Step 2: Run the tests**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -run "TestDefaultRegistry"`
Expected: All tests PASS.

- [ ] **Step 3: Run the full package test suite**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./internal/provider/inputvalidation/ -v -count=1`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/provider/inputvalidation/engine_test.go
git commit -m "test(inputvalidation): add DefaultRegistry integration tests (Vikunja #25)"
```

---

### Task 10: Full Build Verification and FIPS Check

**Files:** None (verification only)

- [ ] **Step 1: Run full build**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go build ./...`
Expected: Clean build.

- [ ] **Step 2: Run full test suite**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go test ./... -v -count=1 -short`
Expected: All tests PASS across all packages.

- [ ] **Step 3: FIPS build check**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && GOEXPERIMENT=boringcrypto go build ./...`
Expected: Clean build (no FIPS-incompatible imports in the new package).

- [ ] **Step 4: Verify go vet passes**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && go vet ./...`
Expected: No issues.

- [ ] **Step 5: Commit (if any formatting changes from vet/fmt)**

Run: `cd /Users/aackerman/Development/Terraform/terraform-provider-technitium && gofmt -w internal/provider/inputvalidation/`

```bash
git add -A && git diff --cached --quiet || git commit -m "chore: go fmt inputvalidation package (Vikunja #25)"
```
