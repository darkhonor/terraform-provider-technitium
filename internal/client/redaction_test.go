// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRequestCreationError_RedactsToken(t *testing.T) {
	const secretToken = "super-secret-create-token"

	c, err := NewClient(ClientConfig{BaseURL: "http://bad host", Token: secretToken, LegacyTokenAuth: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	calls := map[string]func() error{
		"doGet": func() error {
			_, err := c.doGet(context.Background(), "/api/zones/list", nil)
			return err
		},
		"doPost": func() error {
			_, err := c.doPost(context.Background(), "/api/settings/set", nil)
			return err
		},
		"exportFilteredZones": func() error {
			_, err := exportFilteredZones(context.Background(), c, "/api/blocked/export")
			return err
		},
	}
	for name, call := range calls {
		err := call()
		if err == nil {
			t.Errorf("%s: expected a request-creation error for an unparseable server URL", name)
			continue
		}
		if strings.Contains(err.Error(), secretToken) {
			t.Errorf("%s: error message leaks the API token: %v", name, err)
		}
	}
}

func TestLogin_RequestCreationError_RedactsURL(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://bad host", Username: "admin", Password: "super-secret-pass"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = c.Login(context.Background())
	if err == nil {
		t.Fatal("expected a request-creation error for an unparseable server URL")
	}
	if strings.Contains(err.Error(), "bad host") {
		t.Errorf("error message carries the unredacted URL: %v", err)
	}
}

// Reverse proxies and WAFs routinely echo the request URI or form body in
// their error pages. In LegacyTokenAuth mode the form body carries the token.
func TestParseResponse_NonOKBodyRedactsToken(t *testing.T) {
	const secretToken = "super-secret/echo+token"

	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, "<html>502 Bad Gateway for %s %s (raw token %s)</html>", r.URL.RequestURI(), r.PostForm.Encode(), secretToken)
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: secretToken, LegacyTokenAuth: true})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected an HTTP status error")
	}
	for _, form := range []string{secretToken, url.QueryEscape(secretToken)} {
		if strings.Contains(err.Error(), form) {
			t.Errorf("error message leaks the API token as %q: %v", form, err)
		}
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error message lost the HTTP status: %v", err)
	}
}

func TestParseResponse_NonOKBodyIsTruncated(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", 64*1024)))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected an HTTP status error")
	}
	if n := len(err.Error()); n > 1024 {
		t.Errorf("error message is %d bytes; a non-200 body must be truncated", n)
	}
}

func TestLogin_NonOKBodyRedactsPassword(t *testing.T) {
	const secretPass = "super-secret-login-pass"

	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, "blocked request with body %s", r.PostForm.Encode())
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Username: "admin", Password: secretPass})
	err := c.Login(context.Background())
	if err == nil {
		t.Fatal("expected an HTTP status error")
	}
	if strings.Contains(err.Error(), secretPass) {
		t.Errorf("error message leaks the password: %v", err)
	}
}

func TestAPIErrorMessage_RedactsCredentials(t *testing.T) {
	const token = "envelope-secret-token"
	const pass = "envelope-secret-pass"
	echo := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _ = fmt.Fprintf(w, `{"status":"error","errorMessage":"rejected %s / %s / %s"}`,
			r.Form.Get("token"), r.Form.Get("pass"), url.QueryEscape(token))
	}
	cases := map[string]func(*Client) error{
		"parseResponse": func(c *Client) error {
			return c.RecordDelete(context.Background(), "h.example.test", "example.test", "A", map[string]string{"ipAddress": "192.0.2.1"})
		},
		"export": func(c *Client) error {
			_, err := c.BlockedZoneList(context.Background())
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, `{"status":"error","errorMessage":"rejected %s / %s"}`, token, url.QueryEscape(token))
			})
			defer srv.Close()
			c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: token})
			err := call(c)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *APIError, got %v", err)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token)) {
				t.Errorf("credential leaked: %v", err)
			}
		})
	}
	t.Run("login", func(t *testing.T) {
		srv := newTestServer(t, echo)
		defer srv.Close()
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Username: "admin", Password: pass})
		err := c.Login(context.Background())
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *APIError, got %v", err)
		}
		if strings.Contains(err.Error(), pass) {
			t.Errorf("password leaked: %v", err)
		}
	})
}

func TestRedactTransportErr_StripsTokenFromURL(t *testing.T) {
	err := redactTransportErr("/api/x", &url.Error{Op: "Get", URL: "http://h/api/x?token=SECRET-TOKEN", Err: errors.New("connection refused")})
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("token not stripped: %v", err)
	}
}

func TestRedactRequestErr_StripsTokenFromURL(t *testing.T) {
	err := redactRequestErr("/api/x", &url.Error{Op: "parse", URL: "http://h/api/x?token=SECRET-TOKEN", Err: errors.New("invalid character")})
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("token not stripped: %v", err)
	}
}
