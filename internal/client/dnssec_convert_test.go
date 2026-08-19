// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestZoneDNSSECConvertNxProof_CallsCorrectEndpoint(t *testing.T) {
	var gotPath, gotZone string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotZone = r.URL.Query().Get("zone")
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ZoneDNSSECConvertNxProof(context.Background(), "z.test", "NSEC3"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/zones/dnssec/properties/convertToNSEC3" {
		t.Fatalf("wrong endpoint: %s", gotPath)
	}
	if gotZone != "z.test" {
		t.Fatalf("wrong zone param: %s", gotZone)
	}
	if err := c.ZoneDNSSECConvertNxProof(context.Background(), "z.test", "NSEC"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/zones/dnssec/properties/convertToNSEC" {
		t.Fatalf("wrong endpoint: %s", gotPath)
	}
	if gotZone != "z.test" {
		t.Fatalf("wrong zone param on NSEC branch: %s", gotZone)
	}
}

func TestZoneDNSSECConvertNxProof_InvalidValueDoesNotCallServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ZoneDNSSECConvertNxProof(context.Background(), "z.test", "NSEC5"); err == nil {
		t.Fatal("expected error for invalid nxProof, got nil")
	}
	if called {
		t.Fatal("server must not be called for an invalid nxProof value")
	}
}
