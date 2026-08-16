// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// SSOGroupMapEntry maps a remote (OIDC provider) group to a local group.
type SSOGroupMapEntry struct {
	RemoteGroup string `json:"remoteGroup"`
	LocalGroup  string `json:"localGroup"`
}

// SSOConfig represents the Single Sign-On (OIDC) configuration.
//
// The server always masks ssoClientSecret in responses, so the value read
// back is never the real secret.
type SSOConfig struct {
	SSOEnabled                       bool               `json:"ssoEnabled"`
	SSOAuthority                     *string            `json:"ssoAuthority"`
	SSOClientID                      *string            `json:"ssoClientId"`
	SSOClientSecret                  *string            `json:"ssoClientSecret"`
	SSOMetadataAddress               *string            `json:"ssoMetadataAddress"`
	SSOScopes                        []string           `json:"ssoScopes"`
	SSOAllowSignup                   bool               `json:"ssoAllowSignup"`
	SSOAllowSignupOnlyForMappedUsers bool               `json:"ssoAllowSignupOnlyForMappedUsers"`
	SSOGroupMap                      []SSOGroupMapEntry `json:"ssoGroupMap"`
	LocalGroups                      []string           `json:"localGroups"`
}

// SSOGet returns the current SSO configuration.
func (c *Client) SSOGet(ctx context.Context) (*SSOConfig, error) {
	resp, err := c.doGet(ctx, "/api/admin/sso/get", nil)
	if err != nil {
		return nil, fmt.Errorf("getting SSO config: %w", err)
	}

	var cfg SSOConfig
	if err := json.Unmarshal(resp.Response, &cfg); err != nil {
		return nil, fmt.Errorf("parsing SSO config response: %w", err)
	}
	return &cfg, nil
}

// SSOSet updates the SSO configuration. Uses POST so the client secret is
// carried in the request body rather than the URL.
func (c *Client) SSOSet(ctx context.Context, params map[string]string) (*SSOConfig, error) {
	qp := url.Values{}
	for k, v := range params {
		qp.Set(k, v)
	}

	resp, err := c.doPost(ctx, "/api/admin/sso/set", qp)
	if err != nil {
		return nil, fmt.Errorf("updating SSO config: %w", err)
	}

	var cfg SSOConfig
	if err := json.Unmarshal(resp.Response, &cfg); err != nil {
		return nil, fmt.Errorf("parsing SSO config response: %w", err)
	}
	return &cfg, nil
}
