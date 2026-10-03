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

const soaApexRecords = `{"status":"ok","response":{"zone":{"name":"example.internal"},"records":[
	{"name":"example.internal","type":"NS","ttl":3600,"rData":{"nameServer":"ns1.example.internal"}},
	{"name":"example.internal","type":"SOA","ttl":900,"comments":"owned by netops","rData":{
		"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
		"serial":4294967290,"refresh":901,"retry":301,"expire":604801,"minimum":901,
		"useSerialDateScheme":%t}},
	{"name":"example.internal","type":"RRSIG","ttl":900,"rData":{
		"typeCovered":"SOA","originalTtl":1,"serial":1,"useSerialDateScheme":%t}}]}}`

func newSOATestClient(t *testing.T, scheme bool, update *url.Values, method *string) *Client {
	t.Helper()
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/zones/records/get":
			_, _ = fmt.Fprintf(w, soaApexRecords, scheme, !scheme)
		case "/api/zones/records/update":
			_ = r.ParseForm()
			*update = r.PostForm
			*method = r.Method
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestZoneSOAGet_SelectsSOAAmongApexRecords(t *testing.T) {
	var upd url.Values
	var m string
	c := newSOATestClient(t, true, &upd, &m)

	soa, err := c.ZoneSOAGet(context.Background(), "example.internal")
	if err != nil {
		t.Fatalf("ZoneSOAGet: %v", err)
	}
	if soa.TTL != 900 || soa.RData.Serial != 4294967290 || soa.RData.UseSerialDateScheme == nil ||
		!*soa.RData.UseSerialDateScheme || soa.Comments != "owned by netops" ||
		soa.RData.PrimaryNameServer != "ns1.example.internal" || soa.RData.Minimum != 901 {
		t.Fatalf("unexpected SOA: %+v", soa)
	}
}

func TestZoneSOAGet_NoSOAIsError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"records":[]}}`)
	})
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.ZoneSOAGet(context.Background(), "example.internal"); err == nil {
		t.Fatal("expected error when the zone has no SOA record")
	}
}

func TestZoneSOAGet_AbsentSchemeFieldIsNil(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
			"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
			"serial":1,"refresh":900,"retry":300,"expire":604800,"minimum":900}}]}}`)
	})
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	soa, err := c.ZoneSOAGet(context.Background(), "example.internal")
	if err != nil {
		t.Fatalf("ZoneSOAGet: %v", err)
	}
	if soa.RData.UseSerialDateScheme != nil {
		t.Fatalf("UseSerialDateScheme = %v, want nil", *soa.RData.UseSerialDateScheme)
	}
}

func TestZoneSOASetSerialDateScheme_NoWriteWhenFieldAbsent(t *testing.T) {
	var updates int
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/zones/records/update" {
			updates++
		}
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
			"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
			"serial":1,"refresh":900,"retry":300,"expire":604800,"minimum":900}}]}}`)
	})
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.ZoneSOASetSerialDateScheme(context.Background(), "example.internal", true); err != nil {
		t.Fatalf("ZoneSOASetSerialDateScheme: %v", err)
	}
	if updates != 0 {
		t.Fatalf("records/update calls = %d, want 0", updates)
	}
}

func TestZoneSOASetSerialDateScheme_SendsEveryFieldAsRead(t *testing.T) {
	var upd url.Values
	var m string
	c := newSOATestClient(t, false, &upd, &m)

	if err := c.ZoneSOASetSerialDateScheme(context.Background(), "example.internal", true); err != nil {
		t.Fatalf("ZoneSOASetSerialDateScheme: %v", err)
	}
	if m != http.MethodPost {
		t.Fatalf("method = %s, want POST", m)
	}
	want := map[string]string{
		"domain": "example.internal", "zone": "example.internal", "type": "SOA", "ttl": "900",
		"primaryNameServer": "ns1.example.internal", "responsiblePerson": "hostadmin@example.internal",
		"serial": "4294967290", "refresh": "901", "retry": "301", "expire": "604801", "minimum": "901",
		"useSerialDateScheme": "true", "comments": "owned by netops",
	}
	if len(upd) != len(want) {
		t.Errorf("sent %d params, want %d: %v", len(upd), len(want), upd)
	}
	for k, v := range want {
		if upd.Get(k) != v {
			t.Errorf("param %q = %q, want %q", k, upd.Get(k), v)
		}
	}
}

func TestZoneSOASetSerialDateScheme_NoWriteWhenAlreadySet(t *testing.T) {
	var upd url.Values
	var m string
	c := newSOATestClient(t, true, &upd, &m)

	if err := c.ZoneSOASetSerialDateScheme(context.Background(), "example.internal", true); err != nil {
		t.Fatalf("ZoneSOASetSerialDateScheme: %v", err)
	}
	if m != "" {
		t.Fatalf("expected no update request, got %s %v", m, upd)
	}
}
