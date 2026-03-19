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
