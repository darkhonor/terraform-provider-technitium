// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// Wire-format coverage for the zone access options added for issue #89 and
// the RFC 2136 dynamic-update options: the values must reach
// /api/zones/options/set unmodified.
func TestZoneOptionsSet_QueryAccessAndDynamicUpdateParams(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/zones/options/set" {
			_ = r.ParseForm()
			got = r.PostForm
		}
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = c.ZoneOptionsSet(context.Background(), "example.internal", map[string]string{
		"queryAccess":           "UseSpecifiedNetworkACL",
		"queryAccessNetworkACL": "10.0.0.0/8,192.0.2.7",
		"update":                "AllowZoneNameServersAndUseSpecifiedNetworkACL",
		"updateNetworkACL":      "10.0.0.0/16",
	})
	if err != nil {
		t.Fatalf("ZoneOptionsSet: %v", err)
	}

	want := map[string]string{
		"zone":                  "example.internal",
		"queryAccess":           "UseSpecifiedNetworkACL",
		"queryAccessNetworkACL": "10.0.0.0/8,192.0.2.7",
		"update":                "AllowZoneNameServersAndUseSpecifiedNetworkACL",
		"updateNetworkACL":      "10.0.0.0/16",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Fatalf("param %q = %q, want %q (all params: %v)", k, got.Get(k), v, got)
		}
	}
}

// ZoneOptionsGet must surface the queryAccess / dynamicUpdate fields the
// server reports.
func TestZoneOptionsGet_ParsesAccessOptions(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"name":"example.internal",
			"type":"Primary",
			"queryAccess":"UseSpecifiedNetworkACL",
			"queryAccessNetworkACL":["10.0.0.0/8","192.0.2.7"],
			"update":"AllowZoneNameServersAndUseSpecifiedNetworkACL",
			"updateNetworkACL":["10.0.0.0/16"]
		}}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	z, err := c.ZoneOptionsGet(context.Background(), "example.internal")
	if err != nil {
		t.Fatalf("ZoneOptionsGet: %v", err)
	}
	if z.QueryAccess != "UseSpecifiedNetworkACL" {
		t.Fatalf("QueryAccess = %q", z.QueryAccess)
	}
	if len(z.QueryAccessNetworkACL) != 2 || z.QueryAccessNetworkACL[1] != "192.0.2.7" {
		t.Fatalf("QueryAccessNetworkACL = %v", z.QueryAccessNetworkACL)
	}
	if z.Update != "AllowZoneNameServersAndUseSpecifiedNetworkACL" {
		t.Fatalf("Update = %q", z.Update)
	}
	if len(z.UpdateNetworkACL) != 1 || z.UpdateNetworkACL[0] != "10.0.0.0/16" {
		t.Fatalf("UpdateNetworkACL = %v", z.UpdateNetworkACL)
	}
}

// Secondary-family and Stub zones need their primaries at creation: the
// server performs the first transfer inside zones/create. Wire names differ
// from the read side (zoneTransferProtocol here, primaryZoneTransferProtocol
// on options/set and options/get) and were checked against a running server.
func TestZoneCreateWithOptions_SecondaryParams(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"domain":"home.example.com"}}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.ZoneCreateWithOptions(context.Background(), "home.example.com", "Secondary", false, ZoneCreateOptions{
		PrimaryNameServerAddresses: []string{"10.0.10.12", "10.0.10.13:5353"},
		ZoneTransferProtocol:       "Tls",
		TsigKeyName:                "dns01-dns02",
	})
	if err != nil {
		t.Fatalf("ZoneCreateWithOptions: %v", err)
	}

	want := map[string]string{
		"zone":                       "home.example.com",
		"type":                       "Secondary",
		"primaryNameServerAddresses": "10.0.10.12,10.0.10.13:5353",
		"zoneTransferProtocol":       "Tls",
		"tsigKeyName":                "dns01-dns02",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Fatalf("param %q = %q, want %q (all params: %v)", k, got.Get(k), v, got)
		}
	}
}

// The zero value of ZoneCreateOptions must not add parameters, so existing
// callers (Primary, Forwarder) keep their exact wire format.
func TestZoneCreateWithOptions_ZeroValueAddsNothing(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"domain":"example.com"}}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.ZoneCreate(context.Background(), "example.com", "Primary", false); err != nil {
		t.Fatalf("ZoneCreate: %v", err)
	}
	for _, k := range []string{"primaryNameServerAddresses", "zoneTransferProtocol", "tsigKeyName"} {
		if got.Has(k) {
			t.Fatalf("param %q must not be sent for a plain create (all params: %v)", k, got)
		}
	}
}

// ZoneOptionsGet must surface the primaries and transfer protocol exactly as
// the server echoes them, including the normalisation it applies.
func TestZoneOptionsGet_ParsesPrimaryNameServers(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"name":"home.example.com","type":"Secondary",
			"primaryNameServerAddresses":["10.0.10.12:853","[2001:db8::1]:853"],
			"primaryZoneTransferProtocol":"Tls",
			"primaryZoneTransferTsigKeyName":"dns01-dns02"}}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	z, err := c.ZoneOptionsGet(context.Background(), "home.example.com")
	if err != nil {
		t.Fatalf("ZoneOptionsGet: %v", err)
	}
	if len(z.PrimaryNameServerAddresses) != 2 ||
		z.PrimaryNameServerAddresses[0] != "10.0.10.12:853" ||
		z.PrimaryNameServerAddresses[1] != "[2001:db8::1]:853" {
		t.Fatalf("PrimaryNameServerAddresses = %v", z.PrimaryNameServerAddresses)
	}
	if z.PrimaryZoneTransferProtocol != "Tls" {
		t.Fatalf("PrimaryZoneTransferProtocol = %q, want Tls", z.PrimaryZoneTransferProtocol)
	}
}
