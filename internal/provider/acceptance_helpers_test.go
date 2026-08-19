// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

// defaultAcceptanceHost is the plain-HTTP endpoint published by
// docker-compose.test.yml. It is only the fallback: under the TLS suite the
// endpoint comes from TECHNITIUM_SERVER_URL instead.
const defaultAcceptanceHost = "http://127.0.0.1:5380"

// acceptanceClientConfig builds the client configuration for test setup that
// bypasses the provider and calls the API directly.
//
// It resolves the endpoint and CA the same way the rest of the suite does, so
// a direct client follows whichever transport the run is using. testacc-tls
// exports TECHNITIUM_SERVER_URL and TECHNITIUM_CACERT; without honouring
// them, setup would talk plaintext to 5380 during a TLS acceptance run (#110).
//
// SkipTLSVerify is deliberately left false. The generated test CA is trusted
// explicitly via CACertFile, never by disabling verification.
func acceptanceClientConfig() client.ClientConfig {
	cfg := client.ClientConfig{
		BaseURL: defaultAcceptanceHost,
		Token:   testAccAPIToken(),
	}
	if serverURL := os.Getenv("TECHNITIUM_SERVER_URL"); serverURL != "" {
		cfg.BaseURL = serverURL
	}
	if caCert := os.Getenv("TECHNITIUM_CACERT"); caCert != "" {
		cfg.CACertFile = caCert
	}
	return cfg
}

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
