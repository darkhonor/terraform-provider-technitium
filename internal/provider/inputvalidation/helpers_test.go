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
		{"2001:db8::1", false},
		{"::ffff:192.0.2.1", false},
		{"192.168.1.0/24", false},
		{"example.com", false},
		{"999.999.999.999", false},
		{"192.168.1", false},
		{"fe80::1%eth0", false},
		{" 192.0.2.1", false},
		{"192.0.2.1 ", false},
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
		{"192.0.2.1", false},
		{"::ffff:192.0.2.1", false},
		{"example.com", false},
		{"fe80::1%eth0", false},
		{"2001:db8::g", false},
		{" 2001:db8::1", false},
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
		{"example.com.", true},
		{"mail.example.com", true},
		{"mail.example.com.", true},
		{"sub.domain.example.com", true},
		{"a.b", true},
		{"selector._domainkey.example.com", true},
		{"_sip._tcp.example.com", true},
		// Invalid
		{"", false},
		{"localhost", false},
		{"192.0.2.1", false},
		{"2001:db8::1", false},
		{"-example.com", false},
		{"example-.com", false},
		{".example.com", false},
		{"exam ple.com", false},
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
		{"rancher", true},
		{"example.com", true},
		{"example.com.", true},
		{"mail.example.com", true},
		{"host-name", true},
		{"a", true},
		{"_dmarc", true},
		// Invalid
		{"", false},
		{"192.0.2.1", false},
		{"2001:db8::1", false},
		{"-host", false},
		{"host-", false},
		{"host name", false},
		{".host", false},
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
