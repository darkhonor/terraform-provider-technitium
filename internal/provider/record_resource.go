// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/inputvalidation"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                     = &RecordResource{}
	_ resource.ResourceWithImportState      = &RecordResource{}
	_ resource.ResourceWithModifyPlan       = &RecordResource{}
	_ resource.ResourceWithConfigValidators = &RecordResource{}
)

func NewRecordResource() resource.Resource {
	return &RecordResource{
		inputRegistry: inputvalidation.DefaultRegistry(),
	}
}

type RecordResource struct {
	client        *client.Client
	providerData  *TechnitiumProviderData
	inputRegistry *inputvalidation.Registry
}

type RecordResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Zone              types.String `tfsdk:"zone"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	TTL               types.Int64  `tfsdk:"ttl"`
	Value             types.String `tfsdk:"value"`
	Priority          types.Int64  `tfsdk:"priority"`
	Weight            types.Int64  `tfsdk:"weight"`
	Port              types.Int64  `tfsdk:"port"`
	CAAFlags          types.Int64  `tfsdk:"caa_flags"`
	CAATag            types.String `tfsdk:"caa_tag"`
	Protocol          types.String `tfsdk:"protocol"`
	ForwarderPriority types.Int64  `tfsdk:"forwarder_priority"`
	DNSSECValidation  types.Bool   `tfsdk:"dnssec_validation"`
	ProxyType         types.String `tfsdk:"proxy_type"`
	ProxyAddress      types.String `tfsdk:"proxy_address"`
	ProxyPort         types.Int64  `tfsdk:"proxy_port"`
	ProxyUsername     types.String `tfsdk:"proxy_username"`
	ProxyPassword     types.String `tfsdk:"proxy_password"`
	Overwrite         types.Bool   `tfsdk:"overwrite"`
	// Computed
	LastModified types.String `tfsdk:"last_modified"`
}

func (r *RecordResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record"
}

func (r *RecordResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a DNS record in a Technitium DNS zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Record identifier (zone::name::type::value composite key). Uniquely identifies an individual DNS record.",
				Computed:    true,
			},
			"zone": schema.StringAttribute{
				Description: "Parent zone name.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Fully qualified domain name for the record.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description: "DNS record type: A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA, FWD.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ttl": schema.Int64Attribute{
				Description: "Time to live in seconds.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(3600),
			},
			"value": schema.StringAttribute{
				Description: "Record data. For A/AAAA: IP address. For CNAME: target domain. For MX: exchange domain. For TXT: text data. For SRV: target. For PTR: domain name. For NS: nameserver. For CAA: value. For FWD: forwarder address.",
				Required:    true,
			},
			"priority": schema.Int64Attribute{
				Description: "Priority for MX and SRV records.",
				Optional:    true,
			},
			"weight": schema.Int64Attribute{
				Description: "Weight for SRV records.",
				Optional:    true,
			},
			"port": schema.Int64Attribute{
				Description: "Port for SRV records.",
				Optional:    true,
			},
			"caa_flags": schema.Int64Attribute{
				Description: "CAA record flags (0 = non-critical, 128 = critical). Required for CAA records.",
				Optional:    true,
			},
			"caa_tag": schema.StringAttribute{
				Description: "CAA record tag: issue, issuewild, iodef. Required for CAA records.",
				Optional:    true,
			},
			"protocol": schema.StringAttribute{
				Description: "FWD record DNS transport protocol: Udp, Tcp, Tls, Https, or Quic. Optional for FWD records; Technitium defaults to Udp.",
				Optional:    true,
			},
			"forwarder_priority": schema.Int64Attribute{
				Description: "FWD record priority. Lower values are queried first; same-priority forwarders are queried concurrently.",
				Optional:    true,
			},
			"dnssec_validation": schema.BoolAttribute{
				Description: "Whether DNSSEC validation must be done for this FWD record. " +
					"Changing this forces a new record, because the Technitium API cannot " +
					"update it unambiguously when two FWD records differ only by this field.",
				Optional: true,
				PlanModifiers: []planmodifier.Bool{
					// RequiresReplace, not in-place update. dnssecValidation is part of
					// the FWD record's identity (see buildRecordID), but the update API
					// treats it as a SETTABLE value, not an identifier: there is no
					// newDnssecValidation parameter, so a record can only be located by
					// forwarder/protocol/forwarderPriority. Measured against Technitium
					// 15.2 and 15.4 with two records differing only by this field — an update
					// rewrote one onto the other and the two COLLAPSED INTO ONE, with
					// the API returning status "ok". Replacing routes the change through
					// delete+create, which is well-defined for the ordinary single-record
					// case. It does NOT rescue an existing colliding pair: delete ignores
					// dnssecValidation when matching (see buildDeleteParams), so two FWD
					// records differing only by this field cannot be addressed
					// individually through the 15.2 and 15.4 APIs at all. The provider can keep
					// them distinct in state — that is what buildRecordID fixes — but
					// acting on one without disturbing the other is a server-side gap.
					boolplanmodifier.RequiresReplace(),
				},
			},
			"proxy_type": schema.StringAttribute{
				Description: "Proxy type for FWD records: NoProxy, DefaultProxy, Http, or Socks5.",
				Optional:    true,
			},
			"proxy_address": schema.StringAttribute{
				Description: "Proxy server address for FWD records.",
				Optional:    true,
			},
			"proxy_port": schema.Int64Attribute{
				Description: "Proxy server port for FWD records.",
				Optional:    true,
			},
			"proxy_username": schema.StringAttribute{
				Description: "Proxy username for FWD records.",
				Optional:    true,
			},
			"proxy_password": schema.StringAttribute{
				Description: "Proxy password for FWD records.",
				Optional:    true,
				Sensitive:   true,
			},
			"overwrite": schema.BoolAttribute{
				Description: "Replace existing record set for this type. Default: true.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"last_modified": schema.StringAttribute{
				Description: "Timestamp of last modification.",
				Computed:    true,
			},
		},
	}
}

func (r *RecordResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	r.providerData = providerData
	r.client = providerData.Client
}

func (r *RecordResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy plan
	}
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		r.providerData.STIGEngine.ValidatePlan(
			ctx,
			validators.ResourceRecord,
			&validators.TFPlanAdapter{Plan: req.Plan},
			&validators.TFStateAdapter{State: req.State},
			&resp.Diagnostics,
		)
	}
}

func (r *RecordResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	cvs := []resource.ConfigValidator{
		newInputConfigValidator(r.inputRegistry, inputvalidation.ResourceRecord),
	}
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		cvs = append(cvs, newSTIGConfigValidator(r.providerData.STIGEngine, validators.ResourceRecord))
	}
	return cvs
}

func (r *RecordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RecordResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := r.buildAddParams(&plan)
	record, err := r.client.RecordAdd(ctx,
		plan.Name.ValueString(),
		plan.Zone.ValueString(),
		plan.Type.ValueString(),
		int(plan.TTL.ValueInt64()),
		plan.Overwrite.ValueBool(),
		params,
	)
	if err != nil {
		resp.Diagnostics.AddError("Error creating record", err.Error())
		return
	}

	plan.ID = types.StringValue(buildRecordID(&plan))
	plan.LastModified = types.StringValue(record.LastModified)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RecordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RecordResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	records, err := r.client.RecordGet(ctx, state.Name.ValueString(), state.Zone.ValueString())
	if err != nil {
		// A missing parent zone means the record is gone (e.g. the server was
		// re-provisioned): drop it from state so the plan recreates it instead
		// of hard-failing the refresh.
		if isRecordAlreadyGone(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading record", err.Error())
		return
	}

	// Find matching record by type AND value (fixes #6: ID collision)
	found := false
	recordType := state.Type.ValueString()
	for _, rec := range records {
		if recordMatchesState(rec, &state) {
			if recordType == "FWD" && !state.TTL.IsNull() && !state.TTL.IsUnknown() {
				// Technitium stores FWD records with TTL 0; preserve configured TTL
				// to avoid perpetual diffs for an API-ignored field.
			} else {
				state.TTL = types.Int64Value(int64(rec.TTL))
			}
			state.Value = types.StringValue(client.RecordValueFromRData(recordType, rec.RData))
			state.LastModified = types.StringValue(rec.LastModified)

			// Extract MX/SRV-specific fields
			if pref, ok := rec.RData["preference"]; ok {
				state.Priority = types.Int64Value(int64(toFloat64(pref)))
			}
			if weight, ok := rec.RData["weight"]; ok {
				state.Weight = types.Int64Value(int64(toFloat64(weight)))
			}
			if port, ok := rec.RData["port"]; ok {
				state.Port = types.Int64Value(int64(toFloat64(port)))
			}
			if priority, ok := rec.RData["priority"]; ok && recordType != "FWD" {
				state.Priority = types.Int64Value(int64(toFloat64(priority)))
			}
			// CAA fields
			if flags, ok := rec.RData["flags"]; ok {
				state.CAAFlags = types.Int64Value(int64(toFloat64(flags)))
			}
			if tag, ok := rec.RData["tag"]; ok {
				state.CAATag = types.StringValue(fmt.Sprintf("%v", tag))
			}

			// FWD fields
			if protocol, ok := rec.RData["protocol"]; ok {
				state.Protocol = types.StringValue(fmt.Sprintf("%v", protocol))
			}
			if priority, ok := rec.RData["priority"]; ok && recordType == "FWD" {
				state.ForwarderPriority = types.Int64Value(int64(toFloat64(priority)))
			}
			if priority, ok := rec.RData["forwarderPriority"]; ok {
				state.ForwarderPriority = types.Int64Value(int64(toFloat64(priority)))
			}
			// Only refresh dnssec_validation when it is already tracked. The
			// attribute is Optional and NOT Computed, so a config that omits it
			// plans as null; adopting the server's value here surfaces a permanent
			// `false -> null` diff, and because the attribute is RequiresReplace
			// that diff reads as "must be replaced" on every plan — a forced
			// destroy/create of a record nobody touched.
			//
			// Caught by TestAccZoneResource_ForwarderConditional, whose upstreams
			// deliberately omit the attribute (the common case for internal
			// resolvers): the post-apply refresh plan was non-empty and both
			// records were marked for replacement.
			//
			// Users who DO set the attribute still get real drift detection.
			if !state.DNSSECValidation.IsNull() {
				if dnssecValidation, ok := rec.RData["dnssecValidation"]; ok {
					if v, ok := dnssecValidation.(bool); ok {
						state.DNSSECValidation = types.BoolValue(v)
					}
				}
			}

			found = true
			break
		}
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RecordResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RecordResourceModel
	var state RecordResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := r.buildUpdateParams(&state, &plan)
	err := r.client.RecordUpdate(ctx,
		plan.Name.ValueString(),
		plan.Zone.ValueString(),
		plan.Type.ValueString(),
		int(plan.TTL.ValueInt64()),
		params,
	)
	if err != nil {
		resp.Diagnostics.AddError("Error updating record", err.Error())
		return
	}

	// Read back
	records, err := r.client.RecordGet(ctx, plan.Name.ValueString(), plan.Zone.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading record after update", err.Error())
		return
	}
	for _, rec := range records {
		if recordMatchesState(rec, &plan) {
			plan.LastModified = types.StringValue(rec.LastModified)
			break
		}
	}

	// Rebuild ID — value may have changed
	plan.ID = types.StringValue(buildRecordID(&plan))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes a managed DNS record. If the underlying record is already
// gone (deleted out-of-band, or the parent zone destroyed independently),
// the operation is treated as success — destroy is idempotent.
func (r *RecordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RecordResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := r.buildDeleteParams(&state)
	err := r.client.RecordDelete(ctx,
		state.Name.ValueString(),
		state.Zone.ValueString(),
		state.Type.ValueString(),
		params,
	)
	if err != nil && !isRecordAlreadyGone(err) {
		resp.Diagnostics.AddError("Error deleting record", err.Error())
	}
}

// isRecordAlreadyGone returns true when an error from RecordDelete indicates
// that the record (or its parent zone) is no longer present on the server,
// so the destroy should be treated as already-complete. Technitium's API
// returns these as generic-status APIErrors with English error text rather
// than a typed "not_found" status, so the match is on substring.
func isRecordAlreadyGone(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such record exists") ||
		strings.Contains(msg, "no such zone") ||
		strings.Contains(msg, "zone does not exist") ||
		strings.Contains(msg, "zone was not found") ||
		strings.Contains(msg, "zone not found")
}

func (r *RecordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID format: "zone::name::type::value"
	zone, name, recordType, valueSegment, err := parseRecordID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import ID must be in format: zone::name::type::value "+
				"(e.g., example.com::www.example.com::A::192.0.2.1). "+
				"For MX: zone::name::MX::exchange:priority. "+
				"For SRV: zone::name::SRV::target:priority:weight:port. "+
				"For CAA: zone::name::CAA::value:flags:tag. "+
				"For FWD: zone::name::FWD::forwarder:protocol:priority[:dnssecValidation].")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), zone)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), recordType)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("overwrite"), false)...)

	// Parse value segment for type-specific fields
	fields, parseErr := parseImportValueSegment(recordType, valueSegment)
	if parseErr != nil {
		resp.Diagnostics.AddError("Invalid import value segment", parseErr.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("value"), fields.Value)...)

	if recordType == "MX" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("priority"), fields.Priority)...)
	}
	if recordType == "SRV" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("priority"), fields.Priority)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("weight"), fields.Weight)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), fields.Port)...)
	}
	if recordType == "CAA" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("caa_flags"), fields.CAAFlags)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("caa_tag"), fields.CAATag)...)
	}
	if recordType == "FWD" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("protocol"), fields.Protocol)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("forwarder_priority"), fields.Priority)...)
		// Only set dnssec_validation when the import ID actually stated it. A
		// legacy 3-field ID leaves this nil, and writing an explicit false there
		// would fabricate state the user never supplied — which would then show
		// up as spurious drift on the next plan.
		if fields.DNSSECValidation != nil {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("dnssec_validation"), *fields.DNSSECValidation)...)
		}
	}
}

// buildAddParams creates type-specific API parameters for record creation.
func (r *RecordResource) buildAddParams(model *RecordResourceModel) map[string]string {
	params := map[string]string{}
	recordType := model.Type.ValueString()
	value := model.Value.ValueString()

	params[client.RecordValueParam(recordType)] = value

	// MX preference
	if recordType == "MX" && !model.Priority.IsNull() {
		params["preference"] = fmt.Sprintf("%d", model.Priority.ValueInt64())
	}

	// SRV fields
	if recordType == "SRV" {
		if !model.Priority.IsNull() {
			params["priority"] = fmt.Sprintf("%d", model.Priority.ValueInt64())
		}
		if !model.Weight.IsNull() {
			params["weight"] = fmt.Sprintf("%d", model.Weight.ValueInt64())
		}
		if !model.Port.IsNull() {
			params["port"] = fmt.Sprintf("%d", model.Port.ValueInt64())
		}
	}

	// CAA flags and tag
	if recordType == "CAA" {
		if !model.CAAFlags.IsNull() {
			params["flags"] = fmt.Sprintf("%d", model.CAAFlags.ValueInt64())
		} else {
			params["flags"] = "0"
		}
		if !model.CAATag.IsNull() && model.CAATag.ValueString() != "" {
			params["tag"] = model.CAATag.ValueString()
		} else {
			params["tag"] = "issue"
		}
	}

	if recordType == "FWD" {
		if !model.Protocol.IsNull() && model.Protocol.ValueString() != "" {
			params["protocol"] = model.Protocol.ValueString()
		}
		if !model.ForwarderPriority.IsNull() {
			params["forwarderPriority"] = fmt.Sprintf("%d", model.ForwarderPriority.ValueInt64())
		}
		if !model.DNSSECValidation.IsNull() {
			params["dnssecValidation"] = fmt.Sprintf("%t", model.DNSSECValidation.ValueBool())
		}
		addOptionalFWDProxyParams(params, model)
	}

	return params
}

// buildUpdateParams creates type-specific API parameters for record update.
func (r *RecordResource) buildUpdateParams(state, plan *RecordResourceModel) map[string]string {
	params := map[string]string{}
	recordType := plan.Type.ValueString()
	valueParam := client.RecordValueParam(recordType)

	// Current value (required for API to identify the record)
	oldValue := state.Value.ValueString()
	newValue := plan.Value.ValueString()

	switch recordType {
	case "A", "AAAA":
		params["ipAddress"] = oldValue
		if oldValue != newValue {
			params["newIpAddress"] = newValue
		}
	case "CNAME":
		params["cname"] = newValue
	case "MX":
		params["exchange"] = oldValue
		if oldValue != newValue {
			params["newExchange"] = newValue
		}
		if !state.Priority.IsNull() {
			params["preference"] = fmt.Sprintf("%d", state.Priority.ValueInt64())
		}
		if !plan.Priority.IsNull() {
			params["newPreference"] = fmt.Sprintf("%d", plan.Priority.ValueInt64())
		}
	case "TXT":
		params["text"] = oldValue
		if oldValue != newValue {
			params["newText"] = newValue
		}
	case "SRV":
		params["target"] = oldValue
		if oldValue != newValue {
			params["newTarget"] = newValue
		}
		if !state.Priority.IsNull() {
			params["priority"] = fmt.Sprintf("%d", state.Priority.ValueInt64())
		}
		if !plan.Priority.IsNull() {
			params["newPriority"] = fmt.Sprintf("%d", plan.Priority.ValueInt64())
		}
		if !state.Weight.IsNull() {
			params["weight"] = fmt.Sprintf("%d", state.Weight.ValueInt64())
		}
		if !plan.Weight.IsNull() {
			params["newWeight"] = fmt.Sprintf("%d", plan.Weight.ValueInt64())
		}
		if !state.Port.IsNull() {
			params["port"] = fmt.Sprintf("%d", state.Port.ValueInt64())
		}
		if !plan.Port.IsNull() {
			params["newPort"] = fmt.Sprintf("%d", plan.Port.ValueInt64())
		}
	case "PTR":
		params["ptrName"] = oldValue
		if oldValue != newValue {
			params["newPtrName"] = newValue
		}
	case "NS":
		params["nameServer"] = oldValue
		if oldValue != newValue {
			params["newNameServer"] = newValue
		}
	case "CAA":
		params["value"] = oldValue
		if oldValue != newValue {
			params["newValue"] = newValue
		}
		if !state.CAAFlags.IsNull() {
			params["flags"] = fmt.Sprintf("%d", state.CAAFlags.ValueInt64())
		}
		if !plan.CAAFlags.IsNull() {
			params["newFlags"] = fmt.Sprintf("%d", plan.CAAFlags.ValueInt64())
		}
		if !state.CAATag.IsNull() {
			params["tag"] = state.CAATag.ValueString()
		}
		if !plan.CAATag.IsNull() {
			params["newTag"] = plan.CAATag.ValueString()
		}
	case "FWD":
		params["forwarder"] = oldValue
		if oldValue != newValue {
			params["newForwarder"] = newValue
		}
		if !state.Protocol.IsNull() {
			params["protocol"] = state.Protocol.ValueString()
		}
		if !plan.Protocol.IsNull() {
			params["newProtocol"] = plan.Protocol.ValueString()
		}
		if !state.ForwarderPriority.IsNull() {
			params["forwarderPriority"] = fmt.Sprintf("%d", state.ForwarderPriority.ValueInt64())
		}
		if !plan.ForwarderPriority.IsNull() {
			params["newForwarderPriority"] = fmt.Sprintf("%d", plan.ForwarderPriority.ValueInt64())
		}
		// Always send the current value, falling back to state when the config
		// omits the attribute. Technitium treats a MISSING dnssecValidation on
		// update as false rather than "leave alone": verified against 15.2 and 15.4, a
		// TTL-only update silently flipped a dnssec=true record to false. Since
		// the attribute is Optional and not Computed, a user who never writes it
		// in HCL plans null on every apply, so without this fallback any
		// unrelated update would quietly disable DNSSEC validation.
		//
		// dnssec_validation is RequiresReplace, so plan and state agree here for
		// any update that actually reaches this code; the fallback exists for the
		// null-plan case, not to reconcile a change.
		switch {
		case !plan.DNSSECValidation.IsNull():
			params["dnssecValidation"] = fmt.Sprintf("%t", plan.DNSSECValidation.ValueBool())
		case !state.DNSSECValidation.IsNull():
			params["dnssecValidation"] = fmt.Sprintf("%t", state.DNSSECValidation.ValueBool())
		}
		addOptionalFWDProxyParams(params, plan)
	default:
		params[valueParam] = newValue
	}

	return params
}

// buildDeleteParams creates type-specific API parameters for record deletion.
func (r *RecordResource) buildDeleteParams(model *RecordResourceModel) map[string]string {
	params := map[string]string{}
	recordType := model.Type.ValueString()
	value := model.Value.ValueString()

	params[client.RecordValueParam(recordType)] = value

	if recordType == "MX" && !model.Priority.IsNull() {
		params["preference"] = fmt.Sprintf("%d", model.Priority.ValueInt64())
	}

	if recordType == "SRV" {
		if !model.Priority.IsNull() {
			params["priority"] = fmt.Sprintf("%d", model.Priority.ValueInt64())
		}
		if !model.Weight.IsNull() {
			params["weight"] = fmt.Sprintf("%d", model.Weight.ValueInt64())
		}
		if !model.Port.IsNull() {
			params["port"] = fmt.Sprintf("%d", model.Port.ValueInt64())
		}
	}

	if recordType == "CAA" {
		if !model.CAAFlags.IsNull() {
			params["flags"] = fmt.Sprintf("%d", model.CAAFlags.ValueInt64())
		}
		if !model.CAATag.IsNull() && model.CAATag.ValueString() != "" {
			params["tag"] = model.CAATag.ValueString()
		}
	}

	if recordType == "FWD" {
		if !model.Protocol.IsNull() && model.Protocol.ValueString() != "" {
			params["protocol"] = model.Protocol.ValueString()
		}
		if !model.ForwarderPriority.IsNull() {
			params["forwarderPriority"] = fmt.Sprintf("%d", model.ForwarderPriority.ValueInt64())
		}
		// Sent for completeness and forward compatibility. Be clear about what
		// this does NOT do: Technitium 15.2 and 15.4 IGNORE dnssecValidation when
		// matching a record to delete. Measured with two FWD records differing
		// only by this field, all four combinations of creation order and
		// parameter value deleted the FIRST-CREATED record:
		//
		//   created true,false + delete dnssecValidation=true  -> True deleted
		//   created true,false + delete dnssecValidation=false -> True deleted
		//   created false,true + delete dnssecValidation=true  -> False deleted
		//   created false,true + delete dnssecValidation=false -> False deleted
		//
		// So a colliding pair CANNOT be individually destroyed through this API,
		// with or without this parameter. Sending it costs nothing, makes the
		// request state the caller's intent, and starts working the day the
		// server honours it. It is not a fix — see the schema note on
		// dnssec_validation for the limitation and how the provider contains it.
		if !model.DNSSECValidation.IsNull() {
			params["dnssecValidation"] = fmt.Sprintf("%t", model.DNSSECValidation.ValueBool())
		}
	}

	return params
}

// toFloat64 safely converts an interface{} to float64 (JSON numbers are float64).
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func addOptionalFWDProxyParams(params map[string]string, model *RecordResourceModel) {
	if !model.ProxyType.IsNull() && model.ProxyType.ValueString() != "" {
		params["proxyType"] = model.ProxyType.ValueString()
	}
	if !model.ProxyAddress.IsNull() && model.ProxyAddress.ValueString() != "" {
		params["proxyAddress"] = model.ProxyAddress.ValueString()
	}
	if !model.ProxyPort.IsNull() {
		params["proxyPort"] = fmt.Sprintf("%d", model.ProxyPort.ValueInt64())
	}
	if !model.ProxyUsername.IsNull() && model.ProxyUsername.ValueString() != "" {
		params["proxyUsername"] = model.ProxyUsername.ValueString()
	}
	if !model.ProxyPassword.IsNull() && model.ProxyPassword.ValueString() != "" {
		params["proxyPassword"] = model.ProxyPassword.ValueString()
	}
}
