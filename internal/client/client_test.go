// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newTestServer creates a mock Technitium API server.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestNewClient_ValidInputs(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380", Token: "test-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "http://localhost:5380" {
		t.Errorf("expected baseURL http://localhost:5380, got %s", c.baseURL)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380/", Token: "test-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "http://localhost:5380" {
		t.Errorf("expected trailing slash stripped, got %s", c.baseURL)
	}
}

func TestNewClient_EmptyURL(t *testing.T) {
	_, err := NewClient(ClientConfig{BaseURL: "", Token: "test-token"})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewClient_EmptyToken(t *testing.T) {
	_, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380", Token: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNewClient_SkipTLSVerify(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "https://localhost:5380", Token: "test-token", SkipTLSVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestDoGet_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "test-token" {
			t.Error("token not passed in query params")
		}
		json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"zones":[]}`),
		})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	resp, err := c.doGet("/api/zones/list", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

func TestDoGet_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "zone not found",
		})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet("/api/zones/options/get", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.ErrorMessage != "zone not found" {
		t.Errorf("expected 'zone not found', got %s", apiErr.ErrorMessage)
	}
}

func TestDoGet_InvalidToken(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{
			Status:       "invalid-token",
			ErrorMessage: "The session has expired. Please login again.",
		})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "bad-token"})
	_, err := c.doGet("/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if !apiErr.IsInvalidToken() {
		t.Error("expected IsInvalidToken() to be true")
	}
}

func TestDoGet_HTTPError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet("/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestDoGet_InvalidJSON(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet("/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDoPost_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.FormValue("token") != "test-token" {
			t.Error("token not passed in form body")
		}
		if r.FormValue("setting") != "value1" {
			t.Error("expected setting=value1 in form body")
		}
		json.NewEncoder(w).Encode(APIResponse{Status: "ok"})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	params := url.Values{"setting": {"value1"}}
	resp, err := c.doPost("/api/settings/set", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

func TestDoPost_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "access denied",
		})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doPost("/api/settings/set", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPing_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{Status: "ok"})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.Ping(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPing_InvalidToken(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{
			Status:       "invalid-token",
			ErrorMessage: "Invalid token.",
		})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "bad-token"})
	if err := c.Ping(); err == nil {
		t.Fatal("expected error for invalid token")
	}
}
