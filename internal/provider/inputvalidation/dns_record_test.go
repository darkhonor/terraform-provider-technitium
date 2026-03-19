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
