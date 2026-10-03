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

func TestRequestCreationError_RedactsURL(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c, err := NewClient(ClientConfig{BaseURL: "http://bad host", Token: "t", LegacyTokenAuth: legacy})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		assertRequestCreationRedacted(t, c, legacy)
	}
}

func assertRequestCreationRedacted(t *testing.T, c *Client, legacy bool) {
	t.Helper()

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
		if strings.Contains(err.Error(), "bad host") {
			t.Errorf("%s (legacy=%v): error message carries the unredacted URL: %v", name, legacy, err)
		}
	}
}

func TestDoGet_TransportErrorStripsQuery(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:1", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	_, err = c.doGet(context.Background(), "/api/zones/options/get", url.Values{"zone": {"QUERY-MARKER"}})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "QUERY-MARKER") {
		t.Errorf("query string not stripped from transport error: %v", err)
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

func TestRequestSecrets_RedactedFromErrorBodiesAndEnvelopes(t *testing.T) {
	const secret = "req-SECRET-v@lue+1"
	cases := map[string]url.Values{
		"pass":                             {"user": {"alice"}, "pass": {secret}},
		"newPass":                          {"user": {"alice"}, "newPass": {secret}},
		"proxyPassword":                    {"proxyPassword": {secret}},
		"primaryNodePassword":              {"primaryNodePassword": {secret}},
		"primaryNodeTotp":                  {"primaryNodeTotp": {secret}},
		"ssoClientSecret":                  {"ssoClientSecret": {secret}},
		"webServiceTlsCertificatePassword": {"webServiceTlsCertificatePassword": {secret}},
		"tsigKeys":                         {"tsigKeys": {"key1|" + secret + "|hmac-sha256|key2|other-" + secret + "|hmac-sha256"}},
	}
	for name, params := range cases {
		for _, mode := range []string{"502-echo", "envelope-echo"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
					_ = r.ParseForm()
					if mode == "502-echo" {
						w.WriteHeader(http.StatusBadGateway)
						_, _ = fmt.Fprintf(w, "<html>blocked: %s</html>", r.PostForm.Encode())
						return
					}
					_, _ = fmt.Fprintf(w, `{"status":"error","errorMessage":"rejected %s"}`, secret)
				})
				defer srv.Close()
				c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
				_, err := c.doPost(context.Background(), "/api/x", params)
				if err == nil {
					t.Fatal("expected an error")
				}
				for _, form := range []string{secret, url.QueryEscape(secret)} {
					if strings.Contains(err.Error(), form) {
						t.Errorf("error leaks %s as %q: %v", name, form, err)
					}
				}
			})
		}
	}
}

func TestRedactTransportErr_MalformedLocationIsNotQuoted(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://user:password@dns.example/lo%ZZgin?token=SECRET-LOC")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	_, err := c.doPost(context.Background(), "/api/x", nil)
	if err == nil {
		t.Fatal("expected an error for an unparseable Location header")
	}
	for _, bad := range []string{"SECRET-LOC", "password@", "user:"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error quotes the Location header (%q): %v", bad, err)
		}
	}
}
