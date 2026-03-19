// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// parsePath converts a dot-separated string (e.g. "caa_flags") into a
// framework path.Path.
func parsePath(dotPath string) path.Path {
	parts := strings.Split(dotPath, ".")
	p := path.Root(parts[0])
	for _, part := range parts[1:] {
		p = p.AtName(part)
	}
	return p
}

// TFConfigAdapter wraps tfsdk.Config to implement ConfigAccessor.
type TFConfigAdapter struct {
	Config tfsdk.Config
}

func (a *TFConfigAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFConfigAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFConfigAdapter) GetInt64(dotPath string) (int64, bool) {
	var val types.Int64
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return 0, false
	}
	return val.ValueInt64(), true
}

func (a *TFConfigAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.Config.GetAttribute(context.Background(), parsePath(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return nil, false
	}
	var result []string
	for _, elem := range val.Elements() {
		if s, ok := elem.(types.String); ok {
			result = append(result, s.ValueString())
		}
	}
	return result, true
}

// Interface compliance assertion.
var _ ConfigAccessor = &TFConfigAdapter{}
