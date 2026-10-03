// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type forwardersValidator struct{}

func (forwardersValidator) Description(context.Context) string {
	return "Rejects forwarders that Technitium would store in a different form for forwarder_protocol."
}

func (v forwardersValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (forwardersValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var protocol types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("forwarder_protocol"), &protocol)...)
	if resp.Diagnostics.HasError() || protocol.IsUnknown() {
		return
	}
	p := "Tls"
	if !protocol.IsNull() {
		p = protocol.ValueString()
	}
	for i, e := range req.ConfigValue.Elements() {
		s, ok := e.(types.String)
		if !ok || s.IsUnknown() {
			continue
		}
		if s.IsNull() {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i), "Invalid forwarder", "A forwarder must not be null.")
			continue
		}
		if _, err := canonicalForwarder(s.ValueString(), p); err != nil {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i), "Invalid forwarder", err.Error())
		}
	}
}

func reconcileForwarders(ctx context.Context, configured types.List, server []string, protocol string) types.List {
	if configured.IsNull() {
		return configured
	}
	if server == nil {
		server = []string{}
	}
	fromServer, _ := types.ListValueFrom(ctx, types.StringType, server)
	if configured.IsUnknown() || len(configured.Elements()) != len(server) {
		return fromServer
	}
	for i, e := range configured.Elements() {
		s, ok := e.(types.String)
		if !ok || s.IsNull() || s.IsUnknown() || !sameForwarder(s.ValueString(), server[i], protocol) {
			return fromServer
		}
	}
	return configured
}

type forwarderProtocolModifier struct{}

func (forwarderProtocolModifier) Description(context.Context) string {
	return "Warns when forwarder_protocol is set without forwarders."
}

func (m forwarderProtocolModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (forwarderProtocolModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var forwardersConfig types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("forwarders"), &forwardersConfig)...)
	if resp.Diagnostics.HasError() || !forwardersConfig.IsNull() {
		return
	}
	resp.Diagnostics.AddAttributeWarning(req.Path, "forwarder_protocol has no effect without forwarders",
		"forwarder_protocol has no effect unless forwarders is set in the same configuration.")
}

func sameForwarder(configured, server, protocol string) bool {
	want, err := canonicalForwarder(configured, protocol)
	if err != nil {
		return false
	}
	got, err := canonicalForwarder(server, protocol)
	if err != nil {
		got = server
	}
	return strings.EqualFold(want, got)
}

func invalidForwarders(ctx context.Context, plan *ServerSettingsResourceModel, diags *diag.Diagnostics) bool {
	if plan.Forwarders.IsNull() || plan.Forwarders.IsUnknown() {
		return false
	}
	protocol := plan.ForwarderProtocol.ValueString()
	var items []string
	diags.Append(plan.Forwarders.ElementsAs(ctx, &items, false)...)
	for i, f := range items {
		if _, err := canonicalForwarder(f, protocol); err != nil {
			diags.AddAttributeError(path.Root("forwarders").AtListIndex(i), "Invalid forwarder", err.Error())
		}
	}
	return diags.HasError()
}

func omitUnmanagedForwarders(params map[string]string, forwarders types.List) {
	if forwarders.IsNull() {
		delete(params, "forwarderProtocol")
	}
}
