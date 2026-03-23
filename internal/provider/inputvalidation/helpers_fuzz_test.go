// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import "testing"

// FuzzIsValidIPv4 exercises IPv4 validation with arbitrary input.
func FuzzIsValidIPv4(f *testing.F) {
	f.Add("192.168.1.1")
	f.Add("10.0.0.0")
	f.Add("255.255.255.255")
	f.Add("0.0.0.0")
	f.Add("::1")
	f.Add("not-an-ip")
	f.Add("")
	f.Add("192.168.1.1/24")
	f.Add("999.999.999.999")

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic on any input.
		_ = isValidIPv4(s)
	})
}

// FuzzIsValidIPv6 exercises IPv6 validation with arbitrary input.
func FuzzIsValidIPv6(f *testing.F) {
	f.Add("::1")
	f.Add("2001:db8::1")
	f.Add("fe80::1%eth0")
	f.Add("192.168.1.1")
	f.Add("")
	f.Add("::ffff:192.168.1.1")
	f.Add("not-an-ip")

	f.Fuzz(func(t *testing.T, s string) {
		_ = isValidIPv6(s)
	})
}

// FuzzIsValidFQDN exercises FQDN validation with arbitrary input.
func FuzzIsValidFQDN(f *testing.F) {
	f.Add("example.com")
	f.Add("example.com.")
	f.Add("sub.domain.example.com")
	f.Add("localhost")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("-invalid.com")
	f.Add("192.168.1.1")
	f.Add("_dmarc.example.com")

	f.Fuzz(func(t *testing.T, s string) {
		_ = isValidFQDN(s)
	})
}

// FuzzIsValidHostname exercises hostname validation with arbitrary input.
func FuzzIsValidHostname(f *testing.F) {
	f.Add("myhost")
	f.Add("my-host.example.com")
	f.Add("localhost")
	f.Add("")
	f.Add("192.168.1.1")
	f.Add("_srv.example.com")
	f.Add("-bad")
	f.Add(string(make([]byte, 256)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = isValidHostname(s)
	})
}
