// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type recordingServer struct {
	*httptest.Server
	conns    atomic.Int64
	mu       sync.Mutex
	requests []capturedRequest
	bodies   []string
}

func newRecordingServer(t *testing.T, listener net.Listener, useTLS bool, respond func(w http.ResponseWriter, form url.Values)) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		rs.mu.Lock()
		rs.requests = append(rs.requests, capturedRequest{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, auth: r.Header.Get("Authorization"), form: form})
		rs.bodies = append(rs.bodies, string(body))
		rs.mu.Unlock()
		respond(w, form)
	}))
	rs.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			rs.conns.Add(1)
		}
	}
	if listener != nil {
		_ = rs.Listener.Close()
		rs.Listener = listener
	}
	if useTLS {
		rs.StartTLS()
	} else {
		rs.Start()
	}
	t.Cleanup(rs.Close)
	return rs
}

func okResponder(w http.ResponseWriter, _ url.Values) {
	_, _ = io.WriteString(w, `{"status":"ok","response":{}}`)
}

func redirector(t *testing.T, useTLS bool, code int, target func() string) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target()+r.URL.Path)
		w.WriteHeader(code)
	})
	var s *httptest.Server
	if useTLS {
		s = httptest.NewTLSServer(h)
	} else {
		s = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	return s
}

func TestRedirect_SameSchemeAndHostOtherPortIsFollowed(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		b := newRecordingServer(t, nil, false, okResponder)
		a := redirector(t, false, http.StatusTemporaryRedirect, func() string { return b.URL })
		c, err := NewClient(ClientConfig{BaseURL: a.URL, Token: "tok", LegacyTokenAuth: legacy})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.doPost(context.Background(), "/api/zones/delete", url.Values{"zone": {"example.test"}}); err != nil {
			t.Fatalf("legacy=%v: %v", legacy, err)
		}
		if len(b.requests) != 1 {
			t.Fatalf("legacy=%v: target requests = %d, want 1", legacy, len(b.requests))
		}
		r := b.requests[0]
		if r.method != http.MethodPost || r.form.Get("zone") != "example.test" {
			t.Errorf("legacy=%v: target saw %s with form %v", legacy, r.method, r.form)
		}
		if legacy && r.form.Get("token") != "tok" {
			t.Errorf("legacy token did not arrive on the followed hop")
		}
		if !legacy && r.auth != "Bearer tok" {
			t.Errorf("Authorization did not arrive on the followed hop: %q", r.auth)
		}
	}
}

func TestRedirect_CrossHostIsRefused(t *testing.T) {
	const token, pass = "cross-host-token", "cross-host-pass"
	calls := map[string]func(base string) error{
		"legacy doGet": func(base string) error {
			c, _ := NewClient(ClientConfig{BaseURL: base, Token: token, LegacyTokenAuth: true})
			_, err := c.doGet(context.Background(), "/api/zones/list", nil)
			return err
		},
		"bearer doPost": func(base string) error {
			c, _ := NewClient(ClientConfig{BaseURL: base, Token: token})
			_, err := c.doPost(context.Background(), "/api/zones/delete", url.Values{"zone": {"example.test"}})
			return err
		},
		"login": func(base string) error {
			c, _ := NewClient(ClientConfig{BaseURL: base, Username: "admin", Password: pass})
			return c.Login(context.Background())
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.2:0")
			if err != nil {
				t.Skipf("127.0.0.2 not available (macOS: ifconfig lo0 alias 127.0.0.2): %v", err)
			}
			b := newRecordingServer(t, l, false, okResponder)
			a := redirector(t, false, http.StatusTemporaryRedirect, func() string { return b.URL })
			err = call(a.URL)
			if err == nil {
				t.Fatal("expected the cross-host redirect to be refused")
			}
			if n := b.conns.Load(); n != 0 {
				t.Errorf("cross-host target received %d connections", n)
			}
			msg := err.Error()
			for _, bad := range []string{token, pass, "?"} {
				if strings.Contains(msg, bad) {
					t.Errorf("error contains %q: %v", bad, msg)
				}
			}
			if !strings.Contains(msg, "127.0.0.1") || !strings.Contains(msg, "127.0.0.2") {
				t.Errorf("error should name both hosts: %v", msg)
			}
		})
	}
}

func TestRedirect_SchemeUpgradeIsRefused(t *testing.T) {
	tlsTarget := newRecordingServer(t, nil, true, okResponder)
	a := redirector(t, false, http.StatusTemporaryRedirect, func() string { return tlsTarget.URL })
	c, _ := NewClient(ClientConfig{BaseURL: a.URL, Token: "tok", SkipTLSVerify: true})
	if _, err := c.doPost(context.Background(), "/api/zones/delete", url.Values{"zone": {"example.test"}}); err == nil {
		t.Fatal("expected the http->https redirect to be refused")
	}
	if n := tlsTarget.conns.Load(); n != 0 {
		t.Errorf("https target received %d connections", n)
	}
}

func TestRedirect_SchemeDowngradeIsRefused(t *testing.T) {
	plain := newRecordingServer(t, nil, false, okResponder)
	a := redirector(t, true, http.StatusTemporaryRedirect, func() string { return plain.URL })
	c, err := NewClient(ClientConfig{BaseURL: a.URL, Token: "tok", SkipTLSVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.doPost(context.Background(), "/api/zones/delete", url.Values{"zone": {"example.test"}}); err == nil {
		t.Fatal("expected the https->http redirect to be refused")
	}
	if n := plain.conns.Load(); n != 0 {
		t.Errorf("http target received %d connections", n)
	}
}

func TestRedirect_302OnWriteBecomesBodylessGET(t *testing.T) {
	b := newRecordingServer(t, nil, false, func(w http.ResponseWriter, form url.Values) {
		if len(form) == 0 {
			_, _ = io.WriteString(w, `{"status":"error","errorMessage":"Parameter 'zone' missing."}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok","response":{}}`)
	})
	a := redirector(t, false, http.StatusFound, func() string { return b.URL })
	c, _ := NewClient(ClientConfig{BaseURL: a.URL, Token: "tok"})
	if _, err := c.doPost(context.Background(), "/api/zones/delete", url.Values{"zone": {"x"}}); err == nil {
		t.Fatal("expected the redirected write to fail")
	}
	if len(b.requests) != 1 {
		t.Fatalf("target requests = %d, want 1", len(b.requests))
	}
	if r := b.requests[0]; r.method != http.MethodGet || b.bodies[0] != "" || r.auth != "Bearer tok" {
		t.Errorf("target saw method=%s body=%q auth=%q, want GET, empty body, Bearer kept", r.method, b.bodies[0], r.auth)
	}
}

func TestRedactURL_StripsUserinfoQueryAndFragment(t *testing.T) {
	if got := redactURL("http://u:pw@h/x?token=t#frag"); got != "http://h/x" {
		t.Errorf("redactURL = %q, want http://h/x", got)
	}
}

func TestNewClient_UppercaseHTTPSSchemeGetsTLSConfig(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "HTTPS://localhost:5380", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.httpClient.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("HTTPS:// scheme did not get the configured TLS 1.3 minimum: %+v", tr.TLSClientConfig)
	}
}

func TestCheckRedirect_Table(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	orig := mk("http://Dns.Example.test:5380/api/x")
	cases := []struct {
		target string
		allow  bool
	}{
		{"http://dns.example.test:5380/api/y", true},
		{"http://dns.example.test:8080/api/x", true},
		{"http://DNS.EXAMPLE.TEST:5380/api/x", true},
		{"https://dns.example.test:53443/api/x", false},
		{"http://evil.test/x", false},
		{"http://dns.example.test@evil.test/x", false},
		{"http:///x", false},
		{"HTTPS://dns.example.test:5380/api/x", false},
		{"//evil.test/x", false},
		{"http://dns.example.test.:5380/api/x", false},
	}
	for _, tc := range cases {
		err := checkRedirect(mk(tc.target), []*http.Request{orig})
		if (err == nil) != tc.allow {
			t.Errorf("%s: allowed=%v, want %v (err=%v)", tc.target, err == nil, tc.allow, err)
		}
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = orig
	}
	if err := checkRedirect(mk("http://dns.example.test:5380/api/z"), via); err == nil {
		t.Error("11th hop should be refused")
	}
}

func TestClusterInitJoin_ErrorRedactsPrimaryNodeURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"error","errorMessage":"join failed"}`)
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t"})
	_, err := c.ClusterInitJoin(context.Background(), ClusterInitJoinParams{
		PrimaryNodeURL:      "https://user:hunter2@primary.example.test:53443",
		PrimaryNodeUsername: "admin",
		PrimaryNodePassword: "pass",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user:") {
		t.Errorf("error leaks primary node URL userinfo: %v", err)
	}
}
