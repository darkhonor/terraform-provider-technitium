// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

// Package tfpath provides shared utilities for converting dot-separated
// attribute paths to Terraform framework path.Path values.
package tfpath

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
)

// Parse converts a dot-separated string (e.g. "dnssec.enabled") into a
// Terraform framework path.Path.
func Parse(dotPath string) path.Path {
	parts := strings.Split(dotPath, ".")
	p := path.Root(parts[0])
	for _, part := range parts[1:] {
		p = p.AtName(part)
	}
	return p
}
