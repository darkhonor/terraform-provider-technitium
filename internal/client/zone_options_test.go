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
			got = r.URL.Query()
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
