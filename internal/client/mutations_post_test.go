// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type capturedRequest struct {
	method      string
	path        string
	rawURL      string
	rawQuery    string
	contentType string
	auth        string
	form        url.Values
}

func captureServer(t *testing.T) (*httptest.Server, *[]capturedRequest) {
	t.Helper()
	var mu sync.Mutex
	var got []capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("unparseable body %q: %v", body, err)
		}
		mu.Lock()
		got = append(got, capturedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			rawURL:      r.URL.String(),
			rawQuery:    r.URL.RawQuery,
			contentType: r.Header.Get("Content-Type"),
			auth:        r.Header.Get("Authorization"),
			form:        form,
		})
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{"domain":"example.test"}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

type mutationCase struct {
	name string
	path string
	want map[string]string
	call func(*Client) error
}

func mutationCases(ctx context.Context) []mutationCase {
	return []mutationCase{
		{"RecordAdd", "/api/zones/records/add",
			map[string]string{"domain": "h.example.test", "zone": "example.test", "type": "A", "ipAddress": "192.0.2.1"},
			func(c *Client) error {
				_, err := c.RecordAdd(ctx, "h.example.test", "example.test", "A", 300, false, map[string]string{"ipAddress": "192.0.2.1"})
				return err
			}},
		{"RecordGet", "/api/zones/records/get",
			map[string]string{"domain": "h.example.test", "zone": "example.test"},
			func(c *Client) error {
				_, err := c.RecordGet(ctx, "h.example.test", "example.test")
				return err
			}},
		{"RecordUpdate", "/api/zones/records/update",
			map[string]string{"domain": "h.example.test", "zone": "example.test", "type": "A", "ipAddress": "192.0.2.1", "newIpAddress": "192.0.2.2"},
			func(c *Client) error {
				return c.RecordUpdate(ctx, "h.example.test", "example.test", "A", 300, map[string]string{"ipAddress": "192.0.2.1", "newIpAddress": "192.0.2.2"})
			}},
		{"RecordDelete", "/api/zones/records/delete",
			map[string]string{"domain": "h.example.test", "zone": "example.test", "type": "A", "ipAddress": "192.0.2.1"},
			func(c *Client) error {
				return c.RecordDelete(ctx, "h.example.test", "example.test", "A", map[string]string{"ipAddress": "192.0.2.1"})
			}},
	}
}

func TestMutations_SendFormBodyNotQuery(t *testing.T) {
	const token = "secret-test-token"
	for _, legacy := range []bool{false, true} {
		for _, tc := range mutationCases(context.Background()) {
			t.Run(fmt.Sprintf("%s/legacy=%v", tc.name, legacy), func(t *testing.T) {
				srv, got := captureServer(t)
				c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: token, LegacyTokenAuth: legacy})
				if err != nil {
					t.Fatal(err)
				}
				if err := tc.call(c); err != nil {
					t.Fatalf("call: %v", err)
				}
				if len(*got) != 1 {
					t.Fatalf("requests = %d, want 1", len(*got))
				}
				r := (*got)[0]
				if r.path != tc.path {
					t.Fatalf("path = %q, want %q", r.path, tc.path)
				}
				if r.method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.method)
				}
				if r.rawQuery != "" {
					t.Errorf("query string = %q, want empty", r.rawQuery)
				}
				if r.contentType != "application/x-www-form-urlencoded" {
					t.Errorf("Content-Type = %q", r.contentType)
				}
				for k, v := range tc.want {
					if r.form.Get(k) != v {
						t.Errorf("form %q = %q, want %q", k, r.form.Get(k), v)
					}
				}
				if legacy {
					if r.form.Get("token") != token {
						t.Errorf("legacy: token not in body")
					}
					if r.auth != "" {
						t.Errorf("legacy: unexpected Authorization header")
					}
				} else {
					if r.auth != "Bearer "+token {
						t.Errorf("Authorization = %q", r.auth)
					}
					if r.form.Has("token") {
						t.Errorf("bearer: token leaked into body")
					}
				}
				if strings.Contains(r.rawURL, token) {
					t.Errorf("token in URL %q", r.rawURL)
				}
			})
		}
	}
}

func TestRecordMutations_SecretsAndSpecialCharsStayInBody(t *testing.T) {
	const secret = "proxy-SENTINEL-p@ss"
	const comment = "comment-SENTINEL a+b&c=d%20#;é\nline2"
	ctx := context.Background()
	fwd := map[string]string{
		"protocol":      "Udp",
		"forwarder":     "192.0.2.53",
		"proxyType":     "Http",
		"proxyAddress":  "192.0.2.80",
		"proxyPort":     "8080",
		"proxyUsername": "user",
		"proxyPassword": secret,
		"comments":      comment,
	}
	calls := map[string]func(*Client) error{
		"add": func(c *Client) error {
			_, err := c.RecordAdd(ctx, "fwd.example.test", "fwd.example.test", "FWD", 300, false, fwd)
			return err
		},
		"update": func(c *Client) error {
			return c.RecordUpdate(ctx, "fwd.example.test", "fwd.example.test", "FWD", 300, fwd)
		},
		"delete": func(c *Client) error {
			return c.RecordDelete(ctx, "fwd.example.test", "fwd.example.test", "FWD", fwd)
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			srv, got := captureServer(t)
			c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
			if err != nil {
				t.Fatal(err)
			}
			if err := call(c); err != nil {
				t.Fatal(err)
			}
			if len(*got) != 1 {
				t.Fatalf("requests = %d, want 1", len(*got))
			}
			r := (*got)[0]
			for _, s := range []string{"SENTINEL", url.QueryEscape(secret), url.QueryEscape(comment)} {
				if strings.Contains(r.rawURL, s) {
					t.Errorf("%q found in request URL %q", s, r.rawURL)
				}
			}
			if r.form.Get("proxyPassword") != secret {
				t.Errorf("proxyPassword body = %q", r.form.Get("proxyPassword"))
			}
			if r.form.Get("comments") != comment {
				t.Errorf("comments body = %q, want exact round-trip", r.form.Get("comments"))
			}
		})
	}
}
