// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import "testing"

// Setup helpers that bypass the provider still have to follow the transport
// the suite is running under. testacc-tls exports TECHNITIUM_SERVER_URL and
// TECHNITIUM_CACERT for exactly this, and a direct client that ignores them
// talks plaintext to 5380 in the middle of a TLS acceptance run.

func TestAcceptanceClientConfig_DefaultsToLocalPlainHTTP(t *testing.T) {
	t.Setenv("TECHNITIUM_SERVER_URL", "")
	t.Setenv("TECHNITIUM_CACERT", "")

	cfg := acceptanceClientConfig()

	if got, want := cfg.BaseURL, "http://127.0.0.1:5380"; got != want {
		t.Errorf("BaseURL = %q, want the docker-compose.test.yml endpoint %q", got, want)
	}
	if cfg.CACertFile != "" {
		t.Errorf("CACertFile = %q, want empty when no test CA is configured", cfg.CACertFile)
	}
}

func TestAcceptanceClientConfig_FollowsServerURLIntoTLS(t *testing.T) {
	t.Setenv("TECHNITIUM_SERVER_URL", "https://127.0.0.1:5443")
	t.Setenv("TECHNITIUM_CACERT", "")

	cfg := acceptanceClientConfig()

	if got, want := cfg.BaseURL, "https://127.0.0.1:5443"; got != want {
		t.Errorf("BaseURL = %q, want the TLS endpoint the suite exports, %q", got, want)
	}
}

func TestAcceptanceClientConfig_TrustsTestCAWhenExported(t *testing.T) {
	t.Setenv("TECHNITIUM_SERVER_URL", "https://127.0.0.1:5443")
	t.Setenv("TECHNITIUM_CACERT", "/repo/testdata/tls/ca.pem")

	cfg := acceptanceClientConfig()

	if got, want := cfg.CACertFile, "/repo/testdata/tls/ca.pem"; got != want {
		t.Errorf("CACertFile = %q, want the exported test CA %q", got, want)
	}
	if cfg.SkipTLSVerify {
		t.Error("SkipTLSVerify must stay false: the test CA is trusted explicitly, never by skipping verification")
	}
}

func TestAcceptanceClientConfig_CarriesAPIToken(t *testing.T) {
	t.Setenv("TECHNITIUM_API_TOKEN", "token-from-environment")

	cfg := acceptanceClientConfig()

	if got, want := cfg.Token, "token-from-environment"; got != want {
		t.Errorf("Token = %q, want %q", got, want)
	}
}
