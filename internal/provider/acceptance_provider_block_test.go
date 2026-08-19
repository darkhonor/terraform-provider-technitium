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

// hardcodedServerURL matches a provider block that pins server_url to a
// literal endpoint instead of resolving it from the environment.
var hardcodedServerURL = regexp.MustCompile(`server_url\s*=\s*"https?://`)

// stigTransportFixtures is the one file allowed to hardcode endpoints.
// testAccSTIGProviderConfigHTTP and testAccSTIGProviderConfigSkipTLS exist to
// assert that insecure transport is *rejected*, so a literal HTTP URL is the
// point of them. The exemption was established deliberately in PR #38 and is
// scoped to this file.
const stigTransportFixtures = "stig_acceptance_test.go"

// guardOwnFile is this file. Its assertions quote literal provider blocks, so
// the scan would otherwise flag the guard itself.
const guardOwnFile = "acceptance_provider_block_test.go"

// Acceptance configs must resolve the endpoint through testAccProviderHCL,
// which honours TECHNITIUM_SERVER_URL and TECHNITIUM_CACERT. A hand-rolled
// provider block pinned to http://127.0.0.1:5380 talks plaintext during the
// TLS acceptance run while the rest of the suite uses HTTPS on 5443 (#115).
func TestNoHardcodedProviderEndpoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") ||
			name == stigTransportFixtures || name == guardOwnFile {
			continue
		}
		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if n := len(hardcodedServerURL.FindAll(body, -1)); n > 0 {
			t.Errorf("%s pins server_url to a literal endpoint in %d place(s); "+
				"use testAccProviderHCL() so the config follows TECHNITIUM_SERVER_URL "+
				"and TECHNITIUM_CACERT", name, n)
		}
	}
}

// The helper the configs rely on has to actually honour the environment,
// otherwise the guard above is enforcing a redirect to a dead end.
func TestProviderHCL_FollowsServerURLAndCACert(t *testing.T) {
	t.Setenv("TECHNITIUM_SERVER_URL", "https://127.0.0.1:5443")
	t.Setenv("TECHNITIUM_CACERT", "/repo/testdata/tls/ca.pem")
	t.Setenv("TECHNITIUM_API_TOKEN", "token-from-environment")

	hcl := testAccProviderHCL()

	for _, want := range []string{
		`server_url = "https://127.0.0.1:5443"`,
		`ca_cert_file = "/repo/testdata/tls/ca.pem"`,
		`api_token  = "token-from-environment"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("provider block missing %s\ngot:\n%s", want, hcl)
		}
	}
}

// With nothing configured it falls back to the plain-HTTP compose endpoint and
// omits ca_cert_file entirely, so `make testacc-up` is unaffected.
func TestProviderHCL_FallsBackToPlainHTTP(t *testing.T) {
	t.Setenv("TECHNITIUM_SERVER_URL", "")
	t.Setenv("TECHNITIUM_CACERT", "")

	hcl := testAccProviderHCL()

	if !strings.Contains(hcl, `server_url = "http://127.0.0.1:5380"`) {
		t.Errorf("expected the docker-compose.test.yml endpoint as fallback, got:\n%s", hcl)
	}
	if strings.Contains(hcl, "ca_cert_file") {
		t.Errorf("ca_cert_file must be omitted when no CA is configured, got:\n%s", hcl)
	}
}
