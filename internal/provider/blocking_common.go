// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

// FilterZoneType identifies which filter list (blocked or allowed) an operation
// targets. It is used by the shared routing helpers below.
type FilterZoneType string

const (
	FilterZoneBlocked FilterZoneType = "blocked"
	FilterZoneAllowed FilterZoneType = "allowed"
)

// ---------------------------------------------------------------------------
// Routing helpers (unexported)
// ---------------------------------------------------------------------------

// zoneExists returns true if domain is present in the named filter list.
func zoneExists(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) (bool, error) {
	switch zoneType {
	case FilterZoneBlocked:
		return c.BlockedZoneExists(ctx, domain)
	case FilterZoneAllowed:
		return c.AllowedZoneExists(ctx, domain)
	default:
		return false, fmt.Errorf("unknown filter zone type: %q", zoneType)
	}
}

// zoneAdd adds domain to the named filter list.
func zoneAdd(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) error {
	switch zoneType {
	case FilterZoneBlocked:
		return c.BlockedZoneAdd(ctx, domain)
	case FilterZoneAllowed:
		return c.AllowedZoneAdd(ctx, domain)
	default:
		return fmt.Errorf("unknown filter zone type: %q", zoneType)
	}
}

// zoneDelete removes domain from the named filter list.
func zoneDelete(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) error {
	switch zoneType {
	case FilterZoneBlocked:
		return c.BlockedZoneDelete(ctx, domain)
	case FilterZoneAllowed:
		return c.AllowedZoneDelete(ctx, domain)
	default:
		return fmt.Errorf("unknown filter zone type: %q", zoneType)
	}
}

// zoneList returns all domains in the named filter list.
func zoneList(ctx context.Context, c *client.Client, zoneType FilterZoneType) ([]string, error) {
	switch zoneType {
	case FilterZoneBlocked:
		return c.BlockedZoneList(ctx)
	case FilterZoneAllowed:
		return c.AllowedZoneList(ctx)
	default:
		return nil, fmt.Errorf("unknown filter zone type: %q", zoneType)
	}
}

// ---------------------------------------------------------------------------
// Higher-level helpers (exported within package)
// ---------------------------------------------------------------------------

// checkAndSetCreate ensures domain is present in the named filter list.
// If the domain already exists it is adopted (adopted=true) without error.
// If the domain does not exist it is added (adopted=false).
func checkAndSetCreate(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) (adopted bool, err error) {
	exists, err := zoneExists(ctx, c, domain, zoneType)
	if err != nil {
		return false, fmt.Errorf("checking %s zone %q before create: %w", zoneType, domain, err)
	}
	if exists {
		return true, nil
	}
	if err := zoneAdd(ctx, c, domain, zoneType); err != nil {
		return false, fmt.Errorf("adding %s zone %q: %w", zoneType, domain, err)
	}
	return false, nil
}

// checkAndSetDelete removes domain from the named filter list if it exists.
// A missing domain is treated as a no-op (idempotent).
func checkAndSetDelete(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) error {
	exists, err := zoneExists(ctx, c, domain, zoneType)
	if err != nil {
		return fmt.Errorf("checking %s zone %q before delete: %w", zoneType, domain, err)
	}
	if !exists {
		return nil
	}
	if err := zoneDelete(ctx, c, domain, zoneType); err != nil {
		return fmt.Errorf("deleting %s zone %q: %w", zoneType, domain, err)
	}
	return nil
}

// reconcileSet brings the named filter list in line with planDomains, starting
// from the set of domains recorded in state (stateDomains). Domains present in
// the plan but absent from state are added; domains present in state but absent
// from the plan are removed.
func reconcileSet(ctx context.Context, c *client.Client, stateDomains, planDomains []string, zoneType FilterZoneType) error {
	stateMap := make(map[string]struct{}, len(stateDomains))
	for _, d := range stateDomains {
		stateMap[d] = struct{}{}
	}

	planMap := make(map[string]struct{}, len(planDomains))
	for _, d := range planDomains {
		planMap[d] = struct{}{}
	}

	// Add domains that are in the plan but not in state.
	for d := range planMap {
		if _, inState := stateMap[d]; !inState {
			if _, err := checkAndSetCreate(ctx, c, d, zoneType); err != nil {
				return err
			}
		}
	}

	// Remove domains that are in state but not in the plan.
	for d := range stateMap {
		if _, inPlan := planMap[d]; !inPlan {
			if err := checkAndSetDelete(ctx, c, d, zoneType); err != nil {
				return err
			}
		}
	}

	return nil
}

// readDomainExists is a pure existence check for use during Read operations.
func readDomainExists(ctx context.Context, c *client.Client, domain string, zoneType FilterZoneType) (bool, error) {
	return zoneExists(ctx, c, domain, zoneType)
}
