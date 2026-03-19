// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package inputvalidation

import (
	"context"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/tfpath"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TFConfigAdapter wraps tfsdk.Config to implement ConfigAccessor.
// It carries the caller's context.Context to forward cancellation and
// deadline signals through to Terraform framework calls.
type TFConfigAdapter struct {
	Config tfsdk.Config
	ctx    context.Context
}

// NewTFConfigAdapter creates a TFConfigAdapter with the given context.
func NewTFConfigAdapter(ctx context.Context, cfg tfsdk.Config) *TFConfigAdapter {
	return &TFConfigAdapter{Config: cfg, ctx: ctx}
}

func (a *TFConfigAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.Config.GetAttribute(a.ctx, tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFConfigAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.Config.GetAttribute(a.ctx, tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFConfigAdapter) GetInt64(dotPath string) (int64, bool) {
	var val types.Int64
	diags := a.Config.GetAttribute(a.ctx, tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return 0, false
	}
	return val.ValueInt64(), true
}

func (a *TFConfigAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.Config.GetAttribute(a.ctx, tfpath.Parse(dotPath), &val)
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
