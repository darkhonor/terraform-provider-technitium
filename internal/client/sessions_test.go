// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// SessionsList must surface the fields the api_token resource relies on to
// resolve the server-side partial token (Type, Username, TokenName,
// PartialToken). The partialToken in the fixture is a 16-char prefix, which
// is how the server derives it (Token.AsSpan(0, 16) in WebServiceAuthApi).
func TestSessionsList_ParsesAPITokenSessions(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/sessions/list" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"status":"ok","response":{"sessions":[
			{"username":"admin","isCurrentSession":true,"partialToken":"aaaabbbbccccdddd","type":"Standard","tokenName":null,"lastSeen":"2026-08-16T00:00:00Z"},
			{"username":"tf-dns","isCurrentSession":false,"partialToken":"1234567890abcdef","type":"ApiToken","tokenName":"terraform-automation","lastSeen":"2026-08-16T00:00:00Z"}
		]}}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sessions, err := c.SessionsList(context.Background())
	if err != nil {
		t.Fatalf("SessionsList: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions) = %d, want 2", len(sessions))
	}
	tok := sessions[1]
	if tok.Type != "ApiToken" || tok.Username != "tf-dns" || tok.TokenName != "terraform-automation" {
		t.Fatalf("unexpected token session: %+v", tok)
	}
	if tok.PartialToken != "1234567890abcdef" {
		t.Fatalf("PartialToken = %q", tok.PartialToken)
	}
}

// SessionDelete must pass the revocation handle through unmodified as the
// partialToken query parameter.
func TestSessionDelete_PassesPartialToken(t *testing.T) {
	var gotPartial string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/sessions/delete" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		gotPartial = r.URL.Query().Get("partialToken")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.SessionDelete(context.Background(), "1234567890abcdef"); err != nil {
		t.Fatalf("SessionDelete: %v", err)
	}
	if gotPartial != "1234567890abcdef" {
		t.Fatalf("partialToken param = %q", gotPartial)
	}
}
