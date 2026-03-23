// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/tfpath"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ConfigAccessor provides read access to Terraform configuration values.
type ConfigAccessor interface {
	GetString(path string) (string, bool)
	GetBool(path string) (bool, bool)
	GetStringList(path string) ([]string, bool)
	// IsNull returns true when the attribute exists in the schema but the
	// user omitted it (or explicitly set it to null). For security-critical
	// attributes, null means "not configured" and should be treated as a
	// finding by validators.
	IsNull(path string) bool
	// IsUnknown returns true when the attribute value will only be resolved
	// at apply time (e.g. computed values). Validators should skip checks
	// for unknown values since they cannot be evaluated yet.
	IsUnknown(path string) bool
}

// PlanAccessor provides read access to Terraform plan values.
type PlanAccessor interface {
	ConfigAccessor
}

// StateAccessor provides read access to Terraform state values.
type StateAccessor interface {
	ConfigAccessor
}

// ---------------------------------------------------------------------------
// toTftypesPath converts a dot-separated path to a tftypes.AttributePath.
// ---------------------------------------------------------------------------

func toTftypesPath(dotPath string) *tftypes.AttributePath {
	parts := strings.Split(dotPath, ".")
	steps := make([]tftypes.AttributePathStep, len(parts))
	for i, p := range parts {
		steps[i] = tftypes.AttributeName(p)
	}
	return tftypes.NewAttributePathWithSteps(steps)
}

// ---------------------------------------------------------------------------
// TF Adapters — wrap tfsdk.Config / tfsdk.Plan / tfsdk.State
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TFConfigAdapter
// ---------------------------------------------------------------------------

// TFConfigAdapter wraps tfsdk.Config to implement ConfigAccessor.
type TFConfigAdapter struct {
	Config tfsdk.Config
}

func (a *TFConfigAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.Config.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFConfigAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.Config.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFConfigAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.Config.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
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

func (a *TFConfigAdapter) IsNull(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.Config.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		// Path traversal failed — possibly because a parent block is null.
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" {
			return a.IsNull(parentDotPath)
		}
		return false
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return false
	}
	return v.IsNull()
}

func (a *TFConfigAdapter) IsUnknown(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.Config.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		// Path traversal failed — if the parent is null, this is NOT unknown.
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" && a.IsNull(parentDotPath) {
			return false
		}
		return true
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return true
	}
	return !v.IsKnown()
}

// ---------------------------------------------------------------------------
// TFPlanAdapter
// ---------------------------------------------------------------------------

// TFPlanAdapter wraps tfsdk.Plan to implement PlanAccessor.
type TFPlanAdapter struct {
	Plan tfsdk.Plan
}

func (a *TFPlanAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.Plan.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFPlanAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.Plan.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFPlanAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.Plan.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
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

func (a *TFPlanAdapter) IsNull(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.Plan.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" {
			return a.IsNull(parentDotPath)
		}
		return false
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return false
	}
	return v.IsNull()
}

func (a *TFPlanAdapter) IsUnknown(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.Plan.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" && a.IsNull(parentDotPath) {
			return false
		}
		return true
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return true
	}
	return !v.IsKnown()
}

// ---------------------------------------------------------------------------
// TFStateAdapter
// ---------------------------------------------------------------------------

// TFStateAdapter wraps tfsdk.State to implement StateAccessor.
type TFStateAdapter struct {
	State tfsdk.State
}

func (a *TFStateAdapter) GetString(dotPath string) (string, bool) {
	var val types.String
	diags := a.State.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return "", false
	}
	return val.ValueString(), true
}

func (a *TFStateAdapter) GetBool(dotPath string) (bool, bool) {
	var val types.Bool
	diags := a.State.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
	if diags.HasError() || val.IsNull() || val.IsUnknown() {
		return false, false
	}
	return val.ValueBool(), true
}

func (a *TFStateAdapter) GetStringList(dotPath string) ([]string, bool) {
	var val types.List
	diags := a.State.GetAttribute(context.Background(), tfpath.Parse(dotPath), &val)
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

func (a *TFStateAdapter) IsNull(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.State.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" {
			return a.IsNull(parentDotPath)
		}
		return false
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return false
	}
	return v.IsNull()
}

func (a *TFStateAdapter) IsUnknown(dotPath string) bool {
	rawVal, remaining, err := tftypes.WalkAttributePath(a.State.Raw, toTftypesPath(dotPath))
	if err != nil || len(remaining.Steps()) > 0 {
		parentDotPath := tfpath.Parent(dotPath)
		if parentDotPath != "" && a.IsNull(parentDotPath) {
			return false
		}
		return true
	}
	v, ok := rawVal.(tftypes.Value)
	if !ok {
		return true
	}
	return !v.IsKnown()
}

// Interface compliance assertions.
var _ ConfigAccessor = &TFConfigAdapter{}
var _ PlanAccessor = &TFPlanAdapter{}
var _ StateAccessor = &TFStateAdapter{}
