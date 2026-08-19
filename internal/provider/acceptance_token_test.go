// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAccAPIToken_UsesEnvironmentValue(t *testing.T) {
	t.Setenv("TECHNITIUM_API_TOKEN", "token-provisioned-by-the-test-harness")

	if got, want := testAccAPIToken(), "token-provisioned-by-the-test-harness"; got != want {
		t.Fatalf("testAccAPIToken() = %q, want %q", got, want)
	}
}

// With no token configured the helper must return nothing, so the provider
// reports its own "Missing api_token" diagnostic naming TECHNITIUM_API_TOKEN.
// Substituting a baked-in value produces a confusing invalid-token failure
// against whatever server happens to be listening instead.
func TestAccAPIToken_EmptyWhenUnset(t *testing.T) {
	t.Setenv("TECHNITIUM_API_TOKEN", "")

	if got := testAccAPIToken(); got != "" {
		t.Fatalf("testAccAPIToken() = %q, want empty: no credential may be substituted when none is configured", got)
	}
}

// credentialLiteral matches a long unbroken hex run in a quoted string, the
// shape of a Technitium API token, session token, or key digest.
var credentialLiteral = regexp.MustCompile(`"[0-9a-fA-F]{32,}"`)

// Committed credential-shaped literals are flagged by GitHub secret scanning
// and by the scanners operators run when evaluating this provider for a
// hardened environment. Test credentials belong in the environment, not in
// the repository. This guard keeps one from being reintroduced.
func TestNoCommittedCredentialLiterals(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Clean(entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		for _, match := range credentialLiteral.FindAll(body, -1) {
			t.Errorf("%s contains a credential-shaped literal %s; read it from the environment instead", entry.Name(), match)
		}
	}
}
