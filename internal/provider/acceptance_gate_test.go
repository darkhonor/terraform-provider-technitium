// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import "testing"

// Acceptance tests talk to a live Technitium server. Anything that opens a
// connection has to be behind the same TF_ACC gate that resource.Test
// applies, or `go test ./...` fails on a clean clone with no server running.

func TestShouldRunAcceptance_FalseWhenTFACCUnset(t *testing.T) {
	t.Setenv("TF_ACC", "")

	if shouldRunAcceptance() {
		t.Fatal("acceptance work must not run when TF_ACC is unset")
	}
}

func TestShouldRunAcceptance_TrueWhenTFACCSet(t *testing.T) {
	t.Setenv("TF_ACC", "1")

	if !shouldRunAcceptance() {
		t.Fatal("acceptance work must run when TF_ACC is set")
	}
}
