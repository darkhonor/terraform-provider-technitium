// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// User represents a Technitium user account.
type User struct {
	Username              string   `json:"username"`
	DisplayName           string   `json:"displayName"`
	Disabled              bool     `json:"disabled"`
	IsSSOUser             bool     `json:"isSsoUser"`
	SessionTimeoutSeconds int      `json:"sessionTimeoutSeconds"`
	MemberOfGroups        []string `json:"memberOfGroups"`
}

// UserGet returns details for a user account including group memberships.
func (c *Client) UserGet(ctx context.Context, username string) (*User, error) {
	params := url.Values{
		"user":          {username},
		"includeGroups": {"true"},
	}
	resp, err := c.doGet(ctx, "/api/admin/users/get", params)
	if err != nil {
		return nil, fmt.Errorf("getting user %q: %w", username, err)
	}

	var user User
	if err := json.Unmarshal(resp.Response, &user); err != nil {
		return nil, fmt.Errorf("parsing user response: %w", err)
	}
	return &user, nil
}

// UserCreate creates a new user account. Uses POST so the password is
// carried in the request body rather than the URL.
func (c *Client) UserCreate(ctx context.Context, username, password, displayName string) error {
	params := url.Values{
		"user": {username},
		"pass": {password},
	}
	if displayName != "" {
		params.Set("displayName", displayName)
	}
	_, err := c.doPost(ctx, "/api/admin/users/create", params)
	if err != nil {
		return fmt.Errorf("creating user %q: %w", username, err)
	}
	return nil
}

// UserSet updates a user account. Supported params include displayName,
// newPass, disabled, sessionTimeoutSeconds, and memberOfGroups (comma
// separated). Uses POST so credentials are carried in the request body.
func (c *Client) UserSet(ctx context.Context, username string, params map[string]string) error {
	qp := url.Values{
		"user": {username},
	}
	for k, v := range params {
		qp.Set(k, v)
	}
	_, err := c.doPost(ctx, "/api/admin/users/set", qp)
	if err != nil {
		return fmt.Errorf("updating user %q: %w", username, err)
	}
	return nil
}

// UserDelete deletes a user account.
func (c *Client) UserDelete(ctx context.Context, username string) error {
	params := url.Values{
		"user": {username},
	}
	_, err := c.doGet(ctx, "/api/admin/users/delete", params)
	if err != nil {
		return fmt.Errorf("deleting user %q: %w", username, err)
	}
	return nil
}

// Session represents an active session or API token from
// /api/admin/sessions/list.
type Session struct {
	Username         string `json:"username"`
	IsCurrentSession bool   `json:"isCurrentSession"`
	PartialToken     string `json:"partialToken"`
	Type             string `json:"type"`
	TokenName        string `json:"tokenName"`
	LastSeen         string `json:"lastSeen"`
}

// SessionsList returns all active sessions and API tokens.
func (c *Client) SessionsList(ctx context.Context) ([]Session, error) {
	resp, err := c.doGet(ctx, "/api/admin/sessions/list", nil)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	var result struct {
		Sessions []Session `json:"sessions"`
	}
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return nil, fmt.Errorf("parsing sessions list response: %w", err)
	}
	return result.Sessions, nil
}

// APIToken is the result of creating a non-expiring API token.
type APIToken struct {
	Username  string `json:"username"`
	TokenName string `json:"tokenName"`
	Token     string `json:"token"`
}

// CreateAPIToken creates a non-expiring API token for the given user. The
// full token value is only returned by this call and cannot be read back
// later.
func (c *Client) CreateAPIToken(ctx context.Context, username, tokenName string) (*APIToken, error) {
	params := url.Values{
		"user":      {username},
		"tokenName": {tokenName},
	}
	resp, err := c.doGet(ctx, "/api/admin/sessions/createToken", params)
	if err != nil {
		return nil, fmt.Errorf("creating API token %q for user %q: %w", tokenName, username, err)
	}

	var token APIToken
	if err := json.Unmarshal(resp.Response, &token); err != nil {
		return nil, fmt.Errorf("parsing createToken response: %w", err)
	}
	return &token, nil
}

// SessionDelete deletes a session or API token identified by its partial
// token.
func (c *Client) SessionDelete(ctx context.Context, partialToken string) error {
	params := url.Values{
		"partialToken": {partialToken},
	}
	_, err := c.doGet(ctx, "/api/admin/sessions/delete", params)
	if err != nil {
		return fmt.Errorf("deleting session %q: %w", partialToken, err)
	}
	return nil
}

// GroupList returns all local group names.
func (c *Client) GroupList(ctx context.Context) ([]string, error) {
	resp, err := c.doGet(ctx, "/api/admin/groups/list", nil)
	if err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}

	var result struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return nil, fmt.Errorf("parsing groups list response: %w", err)
	}
	names := make([]string, 0, len(result.Groups))
	for _, g := range result.Groups {
		names = append(names, g.Name)
	}
	return names, nil
}
