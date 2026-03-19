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
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

// isValidIPv4 returns true if s is a valid IPv4 address (not IPv6, not CIDR).
func isValidIPv4(s string) bool {
	if strings.ContainsAny(s, " /") {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() != nil && !strings.Contains(s, ":")
}

// isValidIPv6 returns true if s is a valid IPv6 address (not v4, not v4-mapped).
func isValidIPv6(s string) bool {
	if strings.ContainsAny(s, " %") {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if !strings.Contains(s, ":") {
		return false
	}
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

	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return false
	}

	labels := strings.Split(name, ".")
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
