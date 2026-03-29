// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/inputvalidation"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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
	ID       types.String `tfsdk:"id"`
	Zone     types.String `tfsdk:"zone"`
	Name     types.String `tfsdk:"name"`
	Type     types.String `tfsdk:"type"`
	TTL      types.Int64  `tfsdk:"ttl"`
	Value    types.String `tfsdk:"value"`
	Priority types.Int64  `tfsdk:"priority"`
	Weight   types.Int64  `tfsdk:"weight"`
	Port     types.Int64  `tfsdk:"port"`
	CAAFlags types.Int64  `tfsdk:"caa_flags"`
	CAATag   types.String `tfsdk:"caa_tag"`
	Overwrite types.Bool  `tfsdk:"overwrite"`
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
				Description: "DNS record type: A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA.",
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
				Description: "Record data. For A/AAAA: IP address. For CNAME: target domain. For MX: exchange domain. For TXT: text data. For SRV: target. For PTR: domain name. For NS: nameserver. For CAA: value.",
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
		resp.Diagnostics.AddError("Error reading record", err.Error())
		return
	}

	// Find matching record by type AND value (fixes #6: ID collision)
	found := false
	recordType := state.Type.ValueString()
	for _, rec := range records {
		if recordMatchesState(rec, &state) {
			state.TTL = types.Int64Value(int64(rec.TTL))
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
			if priority, ok := rec.RData["priority"]; ok {
				state.Priority = types.Int64Value(int64(toFloat64(priority)))
			}
			// CAA fields
			if flags, ok := rec.RData["flags"]; ok {
				state.CAAFlags = types.Int64Value(int64(toFloat64(flags)))
			}
			if tag, ok := rec.RData["tag"]; ok {
				state.CAATag = types.StringValue(fmt.Sprintf("%v", tag))
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
	if err != nil {
		resp.Diagnostics.AddError("Error deleting record", err.Error())
	}
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
				"For CAA: zone::name::CAA::value:flags:tag.")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), zone)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), recordType)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("overwrite"), false)...)

	// Parse value segment for type-specific fields
	value, priority, weight, port, caaFlags, caaTag, parseErr := parseImportValueSegment(recordType, valueSegment)
	if parseErr != nil {
		resp.Diagnostics.AddError("Invalid import value segment", parseErr.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("value"), value)...)

	if recordType == "MX" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("priority"), priority)...)
	}
	if recordType == "SRV" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("priority"), priority)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("weight"), weight)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
	}
	if recordType == "CAA" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("caa_flags"), caaFlags)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("caa_tag"), caaTag)...)
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
