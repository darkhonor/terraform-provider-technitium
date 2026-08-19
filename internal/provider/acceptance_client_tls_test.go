// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

// The point of #110 is not that the configuration struct holds the right
// strings, it is that a direct client can actually complete a TLS handshake
// against a server presenting a certificate from the test CA. This exercises
// that end to end without needing the docker TLS environment: an httptest TLS
// server stands in for Technitium on 5443, and its self-signed certificate
// stands in for testdata/tls/ca.pem.
func TestAcceptanceClientConfig_ConnectsOverTLSUsingExportedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"version":"14.3"}}`)
	}))
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("writing test CA: %v", err)
	}

	t.Setenv("TECHNITIUM_SERVER_URL", srv.URL)
	t.Setenv("TECHNITIUM_CACERT", caPath)
	t.Setenv("TECHNITIUM_API_TOKEN", "test-token")

	cfg := acceptanceClientConfig()
	if !strings.HasPrefix(cfg.BaseURL, "https://") {
		t.Fatalf("BaseURL = %q, want an https endpoint", cfg.BaseURL)
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with the exported test CA: %v", err)
	}
	if _, err := c.SettingsGet(context.Background()); err != nil {
		t.Fatalf("TLS request failed with the test CA trusted: %v", err)
	}
}

// Without the CA the same request must fail verification. This is what proves
// the test above is passing because the CA is trusted, not because
// verification is being skipped somewhere.
func TestAcceptanceClientConfig_TLSFailsWithoutTheCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"version":"14.3"}}`)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("TECHNITIUM_SERVER_URL", srv.URL)
	t.Setenv("TECHNITIUM_CACERT", "")
	t.Setenv("TECHNITIUM_API_TOKEN", "test-token")

	c, err := client.NewClient(acceptanceClientConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.SettingsGet(context.Background()); err == nil {
		t.Fatal("expected certificate verification to fail without the test CA; a request that succeeds here means verification is being skipped")
	}
}
