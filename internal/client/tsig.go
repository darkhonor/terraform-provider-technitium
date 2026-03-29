// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// TSIGKey represents a TSIG key from the Technitium API.
type TSIGKey struct {
	KeyName       string `json:"keyName"`
	SharedSecret  string `json:"sharedSecret"`
	AlgorithmName string `json:"algorithmName"`
}

// ErrTSIGKeyNotFound is returned when a TSIG key does not exist.
var ErrTSIGKeyNotFound = errors.New("TSIG key not found")

// TSIGKeyList returns all TSIG keys from server settings.
func (c *Client) TSIGKeyList(ctx context.Context) ([]TSIGKey, error) {
	settings, err := c.SettingsGet(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing TSIG keys: %w", err)
	}
	if settings.TsigKeys == nil {
		return []TSIGKey{}, nil
	}
	return settings.TsigKeys, nil
}

// TSIGKeyGet returns a single TSIG key by name.
func (c *Client) TSIGKeyGet(ctx context.Context, keyName string) (*TSIGKey, error) {
	keys, err := c.TSIGKeyList(ctx)
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		if strings.EqualFold(k.KeyName, keyName) {
			key := keys[i]
			return &key, nil
		}
	}
	return nil, ErrTSIGKeyNotFound
}

// writeTSIGKeys encodes the key list as pipe-delimited and writes to settings.
// Format: name1|secret1|algo1|name2|secret2|algo2
// Empty list sends tsigKeys=false to clear all keys.
func (c *Client) writeTSIGKeys(ctx context.Context, keys []TSIGKey) error {
	value := "false"
	if len(keys) > 0 {
		parts := make([]string, 0, len(keys)*3)
		for _, k := range keys {
			parts = append(parts, k.KeyName, k.SharedSecret, k.AlgorithmName)
		}
		value = strings.Join(parts, "|")
	}
	return c.SettingsSet(ctx, map[string]string{"tsigKeys": value})
}

// validateTSIGKeyFields checks that no field contains the pipe delimiter
// which would corrupt the wire format.
func validateTSIGKeyFields(key TSIGKey) error {
	for _, field := range []string{key.KeyName, key.SharedSecret, key.AlgorithmName} {
		if strings.Contains(field, "|") {
			return fmt.Errorf("TSIG key fields must not contain '|': %q", field)
		}
	}
	return nil
}

// TSIGKeyCreate adds a new TSIG key. Returns error if key name already exists.
func (c *Client) TSIGKeyCreate(ctx context.Context, key TSIGKey) error {
	if err := validateTSIGKeyFields(key); err != nil {
		return fmt.Errorf("creating TSIG key: %w", err)
	}

	keys, err := c.TSIGKeyList(ctx)
	if err != nil {
		return fmt.Errorf("creating TSIG key: %w", err)
	}

	// Check for duplicate
	for _, k := range keys {
		if strings.EqualFold(k.KeyName, key.KeyName) {
			return fmt.Errorf("TSIG key %q already exists", key.KeyName)
		}
	}

	keys = append(keys, key)
	if err := c.writeTSIGKeys(ctx, keys); err != nil {
		return fmt.Errorf("creating TSIG key %q: %w", key.KeyName, err)
	}
	return nil
}

// TSIGKeyUpdate replaces an existing TSIG key by name.
func (c *Client) TSIGKeyUpdate(ctx context.Context, key TSIGKey) error {
	if err := validateTSIGKeyFields(key); err != nil {
		return fmt.Errorf("updating TSIG key: %w", err)
	}

	keys, err := c.TSIGKeyList(ctx)
	if err != nil {
		return fmt.Errorf("updating TSIG key: %w", err)
	}

	found := false
	for i, k := range keys {
		if strings.EqualFold(k.KeyName, key.KeyName) {
			keys[i] = key
			found = true
			break
		}
	}
	if !found {
		return ErrTSIGKeyNotFound
	}

	if err := c.writeTSIGKeys(ctx, keys); err != nil {
		return fmt.Errorf("updating TSIG key %q: %w", key.KeyName, err)
	}
	return nil
}

// TSIGKeyDelete removes a TSIG key by name. Idempotent — succeeds silently if key not found.
func (c *Client) TSIGKeyDelete(ctx context.Context, keyName string) error {
	keys, err := c.TSIGKeyList(ctx)
	if err != nil {
		return fmt.Errorf("deleting TSIG key: %w", err)
	}

	filtered := make([]TSIGKey, 0, len(keys))
	for _, k := range keys {
		if !strings.EqualFold(k.KeyName, keyName) {
			filtered = append(filtered, k)
		}
	}

	// Key was not present — nothing to do (idempotent)
	if len(filtered) == len(keys) {
		return nil
	}

	if err := c.writeTSIGKeys(ctx, filtered); err != nil {
		return fmt.Errorf("deleting TSIG key %q: %w", keyName, err)
	}
	return nil
}
