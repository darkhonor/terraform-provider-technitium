// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package tfpath

import "testing"

// FuzzParse exercises the dot-path parser with arbitrary input to detect
// panics, out-of-bounds access, or unexpected behavior on malformed paths.
func FuzzParse(f *testing.F) {
	// Seed corpus: realistic paths and edge cases
	f.Add("dnssec.enabled")
	f.Add("name")
	f.Add("dnssec.algorithm")
	f.Add("recursion_network_acl")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c.d.e.f")
	f.Add("......")

	f.Fuzz(func(t *testing.T, dotPath string) {
		// Parse must not panic on any input.
		_ = Parse(dotPath)
	})
}

// FuzzParent exercises the parent-path extractor with arbitrary input.
func FuzzParent(f *testing.F) {
	f.Add("dnssec.enabled")
	f.Add("name")
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, dotPath string) {
		result := Parent(dotPath)
		// Parent must always return a string shorter than input
		// (or empty for top-level paths).
		if len(result) >= len(dotPath) && dotPath != "" {
			t.Errorf("Parent(%q) = %q, expected shorter string", dotPath, result)
		}
	})
}
