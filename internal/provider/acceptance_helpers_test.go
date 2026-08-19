// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"
)

// defaultAcceptanceHost is the plain-HTTP endpoint published by
// docker-compose.test.yml, used by test setup that bypasses the provider.
const defaultAcceptanceHost = "http://127.0.0.1:5380"

// shouldRunAcceptance reports whether acceptance work may talk to a live
// server. This is the same signal resource.Test honours, hoisted so that test
// setup performed before resource.Test is gated identically.
func shouldRunAcceptance() bool {
	return os.Getenv("TF_ACC") != ""
}

// skipUnlessAcceptance skips the calling test unless acceptance testing is
// enabled. Call this before any live API call, including setup that runs
// ahead of resource.Test.
func skipUnlessAcceptance(t *testing.T) {
	t.Helper()
	if !shouldRunAcceptance() {
		t.Skip("acceptance test: set TF_ACC=1 and run against a Technitium test server (see GNUmakefile testacc targets)")
	}
}
