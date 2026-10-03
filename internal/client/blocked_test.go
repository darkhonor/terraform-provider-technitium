// Copyright (c) 2026 bytestrom
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"fmt"
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

func TestExportFilteredZones_LegacyTokenAuth(t *testing.T) {
	var gotAuthHeader, gotToken, gotMethod, gotRawQuery string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAuthHeader = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotRawQuery = r.URL.RawQuery
		gotToken = r.PostForm.Get("token")
		_, _ = w.Write([]byte("example.com\n"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "legacy-token", LegacyTokenAuth: true})
	if _, err := exportFilteredZones(context.Background(), c, "/api/blocked/export"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost || gotRawQuery != "" {
		t.Errorf("legacy export = %s with query %q, want POST with no query", gotMethod, gotRawQuery)
	}
	if gotToken != "legacy-token" {
		t.Errorf("expected token=legacy-token in the form body, got %q", gotToken)
	}
	if gotAuthHeader != "" {
		t.Errorf("expected no Authorization header in legacy mode, got %q", gotAuthHeader)
	}
}

func TestExportFilteredZones_LegacyTokenAuth_TransportErrorRedactsToken(t *testing.T) {
	const secretToken = "super-secret-export-token"
	var seen []*http.Request
	c := failingTransportClient(t, secretToken, &seen)
	_, err := exportFilteredZones(context.Background(), c, "/api/blocked/export")
	assertLegacyTransportFailure(t, err, secretToken, seen)
}

func TestExportFilteredZones_Non200IsErrorAndRedacted(t *testing.T) {
	const token = "export-secret-token"
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, "<html>upstream failed for /api/blocked/export?token=%s</html>", token)
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: token, LegacyTokenAuth: true})
	domains, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatalf("expected error, got domains %v", domains)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should carry the status: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("token leaked into error: %v", err)
	}
}

func TestExportFilteredZones_JSONErrorEnvelopeIsAPIError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"invalid-token","errorMessage":"Invalid token or session expired."}`)
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	domains, err := c.AllowedZoneList(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got err=%v domains=%v", err, domains)
	}
	if apiErr.Status != "invalid-token" {
		t.Errorf("status = %q", apiErr.Status)
	}
}

func TestExportFilteredZones_HTMLOn200IsError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "\n  <!DOCTYPE html><html><body>Sign in to continue</body></html>")
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	domains, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatalf("expected error, got domains %v", domains)
	}
}

func TestExportFilteredZones_DomainListUnchanged(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "a.example.test\r\n\nb.example.test\n")
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	domains, err := c.BlockedZoneList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(domains, ",") != "a.example.test,b.example.test" {
		t.Errorf("domains = %v", domains)
	}
}

func TestExportFilteredZones_NonErrorJSONIsError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	domains, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatalf("expected error, got domains %v", domains)
	}
}

func TestExportFilteredZones_BOMPrefixedEnvelopeIsAPIError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "\ufeff{\"status\":\"invalid-token\",\"errorMessage\":\"Invalid token or session expired.\"}")
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	domains, err := c.BlockedZoneList(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got err=%v domains=%v", err, domains)
	}
}

func TestExportFilteredZones_HTMLOn200RedactsToken(t *testing.T) {
	const token = "export-secret-token"
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _ = fmt.Fprintf(w, "<html>Sign in to reach %s with %s</html>", r.URL.RequestURI(), r.PostForm.Encode())
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: token, LegacyTokenAuth: true})
	_, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("token leaked into error: %v", err)
	}
}

func TestExportFilteredZones_JSONOn200RedactsToken(t *testing.T) {
	const token = "export-secret-token"
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _ = fmt.Fprintf(w, `{"status":"ok","uri":%q,"form":%q}`, r.URL.RequestURI(), r.PostForm.Encode())
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: token, LegacyTokenAuth: true})
	_, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("token leaked into error: %v", err)
	}
}

func TestExportFilteredZones_JSONArrayOrStringIsError(t *testing.T) {
	for _, body := range []string{`["a.example.test"]`, `"error"`} {
		t.Run(body, func(t *testing.T) {
			srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, body)
			})
			defer srv.Close()
			c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
			domains, err := c.BlockedZoneList(context.Background())
			if err == nil {
				t.Fatalf("expected error, got domains %v", domains)
			}
		})
	}
}
