// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/tfpath"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ConfigAccessor provides read access to Terraform configuration values.
type ConfigAccessor interface {
	GetString(path string) (string, bool)
	GetBool(path string) (bool, bool)
	GetStringList(path string) ([]string, bool)
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
// MockAccessor — test double, no TF dependencies
// ---------------------------------------------------------------------------

// MockAccessor is a test double for ConfigAccessor/PlanAccessor/StateAccessor.
type MockAccessor struct {
	attrs map[string]interface{}
}

// NewMockAccessor constructs a MockAccessor pre-loaded with the given attrs.
func NewMockAccessor(attrs map[string]interface{}) *MockAccessor {
	return &MockAccessor{attrs: attrs}
}

func (m *MockAccessor) GetString(key string) (string, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (m *MockAccessor) GetBool(key string) (bool, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (m *MockAccessor) GetStringList(key string) ([]string, bool) {
	v, ok := m.attrs[key]
	if !ok {
		return nil, false
	}
	sl, ok := v.([]string)
	return sl, ok
}

// Interface compliance assertions.
var _ ConfigAccessor = &MockAccessor{}
var _ PlanAccessor = &MockAccessor{}
var _ StateAccessor = &MockAccessor{}

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

// Interface compliance assertions.
var _ ConfigAccessor = &TFConfigAdapter{}
var _ PlanAccessor = &TFPlanAdapter{}
var _ StateAccessor = &TFStateAdapter{}
