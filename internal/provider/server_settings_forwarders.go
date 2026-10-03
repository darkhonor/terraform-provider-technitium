// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type canonicalForwardersModifier struct{}

func (canonicalForwardersModifier) Description(context.Context) string {
	return "Plans each forwarder in the form Technitium stores for forwarder_protocol."
}

func (m canonicalForwardersModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (canonicalForwardersModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.ConfigValue.IsNull() {
		if req.StateValue.IsNull() {
			resp.PlanValue = types.ListUnknown(types.StringType)
		} else {
			resp.PlanValue = req.StateValue
		}
		return
	}
	var protocol types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("forwarder_protocol"), &protocol)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if req.ConfigValue.IsUnknown() || protocol.IsUnknown() || protocol.IsNull() {
		resp.PlanValue = types.ListUnknown(types.StringType)
		return
	}
	elements := req.ConfigValue.Elements()
	out := make([]attr.Value, 0, len(elements))
	for i, e := range elements {
		s, ok := e.(types.String)
		if !ok || s.IsUnknown() {
			resp.PlanValue = types.ListUnknown(types.StringType)
			return
		}
		if s.IsNull() {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i), "Invalid forwarder", "A forwarder must not be null.")
			continue
		}
		canonical, err := canonicalForwarder(s.ValueString(), protocol.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i), "Invalid forwarder", err.Error())
			continue
		}
		out = append(out, types.StringValue(canonical))
	}
	if resp.Diagnostics.HasError() {
		return
	}
	planned, d := types.ListValue(types.StringType, out)
	resp.Diagnostics.Append(d...)
	resp.PlanValue = planned
}

type forwarderProtocolModifier struct{}

func (forwarderProtocolModifier) Description(context.Context) string {
	return "Keeps forwarder_protocol consistent with the server when forwarders is not configured."
}

func (m forwarderProtocolModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (forwarderProtocolModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsUnknown() {
		return
	}
	var forwardersConfig types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("forwarders"), &forwardersConfig)...)
	if resp.Diagnostics.HasError() || !forwardersConfig.IsNull() {
		return
	}
	if req.ConfigValue.IsNull() {
		if req.StateValue.IsNull() {
			resp.PlanValue = types.StringUnknown()
		} else {
			resp.PlanValue = req.StateValue
		}
		return
	}
	priorForwarders := priorStateForwarders(ctx, req.State)
	if len(priorForwarders) > 0 && !req.StateValue.IsNull() && req.StateValue.ValueString() != req.ConfigValue.ValueString() {
		resp.Diagnostics.AddAttributeError(req.Path, "forwarder_protocol does not match the server",
			fmt.Sprintf("The server's forwarders use forwarder_protocol %q, and forwarder_protocol has no effect unless forwarders is set "+
				"in the same configuration. Set forwarders alongside forwarder_protocol, or remove forwarder_protocol.",
				req.StateValue.ValueString()))
		return
	}
	resp.Diagnostics.AddAttributeWarning(req.Path, "forwarder_protocol has no effect without forwarders",
		"forwarder_protocol has no effect unless forwarders is set in the same configuration.")
}

func priorStateForwarders(ctx context.Context, state tfsdk.State) []string {
	if state.Raw.IsNull() {
		return nil
	}
	var list types.List
	if d := state.GetAttribute(ctx, path.Root("forwarders"), &list); d.HasError() || list.IsNull() || list.IsUnknown() {
		return nil
	}
	var out []string
	list.ElementsAs(ctx, &out, false)
	return out
}

func omitUnmanagedForwarders(params map[string]string, configForwarders types.List) {
	if configForwarders.IsNull() {
		delete(params, "forwarders")
		delete(params, "forwarderProtocol")
	}
}

func checkUnmanagedForwarders(planned, applied *ServerSettingsResourceModel, diags *diag.Diagnostics) {
	protocolMismatch := len(applied.Forwarders.Elements()) > 0 && !planned.ForwarderProtocol.IsUnknown() &&
		!planned.ForwarderProtocol.Equal(applied.ForwarderProtocol)
	listMismatch := !planned.Forwarders.IsUnknown() && !planned.Forwarders.Equal(applied.Forwarders)
	if protocolMismatch || listMismatch {
		diags.AddError("Server forwarders changed outside this plan",
			fmt.Sprintf("forwarders is not set in this configuration, and the server now holds forwarders %v with forwarder_protocol %q, "+
				"which differ from the plan. Refresh and plan again, or set forwarders and forwarder_protocol explicitly.",
				applied.Forwarders.Elements(), applied.ForwarderProtocol.ValueString()))
	}
}
