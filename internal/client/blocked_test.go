// Copyright (c) 2026 dev
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestExportFilteredZones_TokenViaBearerHeader is a regression test for the
// default authentication mode on the plain-text export endpoints
// (/api/blocked/export, /api/allowed/export): the token must reach the
// server as an Authorization header, never as a "token" query parameter,
// since reverse-proxy access logs routinely capture request URLs in
// cleartext.
func TestExportFilteredZones_TokenViaBearerHeader(t *testing.T) {
	var gotAuthHeader string
	var gotRawQuery string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotRawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("example.com\nblocked.example\n"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "super-secret-token"})
	domains, err := exportFilteredZones(context.Background(), c, "/api/blocked/export")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	if gotAuthHeader != "Bearer super-secret-token" {
		t.Errorf("expected Authorization: Bearer super-secret-token, got %q", gotAuthHeader)
	}
	if strings.Contains(gotRawQuery, "token") {
		t.Errorf("expected no token in query string, got %q", gotRawQuery)
	}
}

// TestExportFilteredZones_LegacyTokenAuth verifies that setting
// LegacyTokenAuth preserves the pre-15.0 behavior of sending the token as a
// query parameter.
func TestExportFilteredZones_LegacyTokenAuth(t *testing.T) {
	var gotAuthHeader string
	var gotToken string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotToken = r.URL.Query().Get("token")
		_, _ = w.Write([]byte("example.com\n"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "legacy-token", LegacyTokenAuth: true})
	if _, err := exportFilteredZones(context.Background(), c, "/api/blocked/export"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotToken != "legacy-token" {
		t.Errorf("expected token=legacy-token in query params, got %q", gotToken)
	}
	if gotAuthHeader != "" {
		t.Errorf("expected no Authorization header in legacy mode, got %q", gotAuthHeader)
	}
}
