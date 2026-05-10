// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                     = &ZoneResource{}
	_ resource.ResourceWithImportState      = &ZoneResource{}
	_ resource.ResourceWithModifyPlan       = &ZoneResource{}
	_ resource.ResourceWithConfigValidators = &ZoneResource{}
)

func NewZoneResource() resource.Resource {
	return &ZoneResource{}
}

// ZoneResource defines the resource implementation.
type ZoneResource struct {
	client       *client.Client
	providerData *TechnitiumProviderData
}

// ZoneResourceModel describes the resource data model.
type ZoneResourceModel struct {
	ID                             types.String `tfsdk:"id"`
	Name                           types.String `tfsdk:"name"`
	Type                           types.String `tfsdk:"type"`
	SOASerialDateScheme            types.Bool   `tfsdk:"soa_serial_date_scheme"`
	Notify                         types.List   `tfsdk:"notify"`
	AllowTransfer                  types.List   `tfsdk:"allow_transfer"`
	DNSSEC                         *DNSSECModel `tfsdk:"dnssec"`
	ZoneTransferTsigKeyNames       types.List   `tfsdk:"zone_transfer_tsig_key_names"`
	PrimaryZoneTransferTsigKeyName types.String `tfsdk:"primary_zone_transfer_tsig_key_name"`
	// Computed
	SOASerial    types.Int64  `tfsdk:"soa_serial"`
	Status       types.String `tfsdk:"status"`
	DNSSECStatus types.String `tfsdk:"dnssec_status"`
}

// DNSSECModel maps the dnssec block.
type DNSSECModel struct {
	Enabled   types.Bool   `tfsdk:"enabled"`
	Algorithm types.String `tfsdk:"algorithm"`
	Curve     types.String `tfsdk:"curve"`
	NxProof   types.String `tfsdk:"nx_proof"`
}

func (r *ZoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zone"
}

func (r *ZoneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Technitium DNS zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Zone identifier (same as zone name).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The domain name for the zone.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description: "The type of zone. Valid values: Primary, Secondary, Stub, Forwarder.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"soa_serial_date_scheme": schema.BoolAttribute{
				Description: "Use date-based SOA serial numbering scheme.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"notify": schema.ListAttribute{
				Description: "List of IP addresses to notify on zone changes. Maps to STIG BIND-9X-001390 (SC-20).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"allow_transfer": schema.ListAttribute{
				Description: "List of IP addresses allowed to perform zone transfers. Maps to STIG BIND-9X-001010 (AC-10).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"zone_transfer_tsig_key_names": schema.ListAttribute{
				Description: "List of TSIG key names authorized to perform zone transfers. " +
					"Valid for Primary, Secondary, Forwarder, and Catalog zones. " +
					"Maps to STIG BIND-9X-001010 (AC-10).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"primary_zone_transfer_tsig_key_name": schema.StringAttribute{
				Description: "TSIG key name for authenticating zone transfers from the primary server. " +
					"Valid only for Secondary, SecondaryForwarder, and SecondaryCatalog zones. " +
					"Maps to STIG BIND-9X-001010 (AC-10).",
				Optional: true,
			},
			// Computed attributes
			"soa_serial": schema.Int64Attribute{
				Description: "Current SOA serial number.",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Zone status (enabled/disabled).",
				Computed:    true,
			},
			"dnssec_status": schema.StringAttribute{
				Description: "DNSSEC signing status.",
				Computed:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"dnssec": schema.SingleNestedBlock{
				Description: "DNSSEC configuration. Maps to STIG BIND-9X-001650 (SC-20/21/22/23/8/24).",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enable DNSSEC signing for the zone.",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
					},
					"algorithm": schema.StringAttribute{
						Description: "DNSSEC signing algorithm. Valid values: ECDSA, EDDSA, RSA. Maps to STIG BIND-9X-002050 (SC-13).",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("ECDSA"),
					},
					"curve": schema.StringAttribute{
						Description: "Curve for ECDSA (P256, P384) or EDDSA (ED25519, ED448). Default: P256.",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("P256"),
					},
					"nx_proof": schema.StringAttribute{
						Description: "NSEC/NSEC3 proof of non-existence. Maps to STIG BIND-9X-001270 (SC-20).",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("NSEC3"),
					},
				},
			},
		},
	}
}

func (r *ZoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}

	r.client = providerData.Client
	r.providerData = providerData
}

func (r *ZoneResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Don't modify plan on destroy
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan ZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// NSS validation: when running in NSS mode with ECDSA, P256 is not allowed.
	// CNSSI 1253 requires P384 for higher security margin in classified environments.
	if r.providerData != nil && r.providerData.NSS &&
		plan.DNSSEC != nil && plan.DNSSEC.Enabled.ValueBool() &&
		plan.DNSSEC.Algorithm.ValueString() == "ECDSA" &&
		plan.DNSSEC.Curve.ValueString() == "P256" {

		resp.Diagnostics.AddError("DNSSEC curve P256 not allowed in NSS mode",
			"National Security Systems require ECDSA P384 (not P256) for DNSSEC signing. "+
				"CNSSI 1253 mandates higher security margins for classified environments. "+
				"Set dnssec { curve = \"P384\" } to comply.")
	}

	// Zone type validation for zone_transfer_tsig_key_names
	if !plan.ZoneTransferTsigKeyNames.IsNull() && !plan.ZoneTransferTsigKeyNames.IsUnknown() {
		zoneType := plan.Type.ValueString()
		validTransferTypes := map[string]bool{
			"Primary": true, "Secondary": true, "Forwarder": true, "Catalog": true,
		}
		if !validTransferTypes[zoneType] {
			resp.Diagnostics.AddError(
				"Invalid zone type for zone_transfer_tsig_key_names",
				fmt.Sprintf("\"zone_transfer_tsig_key_names\" is only valid for Primary, Secondary, Forwarder, and Catalog zones. Got: %q.", zoneType))
		}
	}

	// Zone type validation for primary_zone_transfer_tsig_key_name
	if !plan.PrimaryZoneTransferTsigKeyName.IsNull() && !plan.PrimaryZoneTransferTsigKeyName.IsUnknown() &&
		plan.PrimaryZoneTransferTsigKeyName.ValueString() != "" {
		zoneType := plan.Type.ValueString()
		validPrimaryTypes := map[string]bool{
			"Secondary": true, "SecondaryForwarder": true, "SecondaryCatalog": true,
		}
		if !validPrimaryTypes[zoneType] {
			resp.Diagnostics.AddError(
				"Invalid zone type for primary_zone_transfer_tsig_key_name",
				fmt.Sprintf("\"primary_zone_transfer_tsig_key_name\" is only valid for Secondary, SecondaryForwarder, and SecondaryCatalog zones. Got: %q.", zoneType))
		}
	}

	// STIG compliance validation
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		r.providerData.STIGEngine.ValidatePlan(
			ctx,
			validators.ResourceZone,
			&validators.TFPlanAdapter{Plan: req.Plan},
			&validators.TFStateAdapter{State: req.State},
			&resp.Diagnostics,
		)
	}
}

func (r *ZoneResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	if r.providerData == nil || r.providerData.STIGEngine == nil {
		return nil
	}
	return []resource.ConfigValidator{
		newSTIGConfigValidator(r.providerData.STIGEngine, validators.ResourceZone),
	}
}

func (r *ZoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate TSIG key references exist on the server
	r.validateTsigKeyReferences(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create zone
	domain, err := r.client.ZoneCreate(ctx,
		plan.Name.ValueString(),
		plan.Type.ValueString(),
		plan.SOASerialDateScheme.ValueBool(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Error creating zone", err.Error())
		return
	}

	plan.ID = types.StringValue(domain)

	// Set zone options (notify, allow_transfer)
	if err := r.setZoneOptions(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error setting zone options", err.Error())
		return
	}

	// Handle DNSSEC signing (NSS P256→P384 upgrade already handled in ModifyPlan)
	if plan.DNSSEC != nil && plan.DNSSEC.Enabled.ValueBool() && plan.Type.ValueString() == "Primary" {
		err := r.client.ZoneDNSSECSign(ctx,
			plan.Name.ValueString(),
			plan.DNSSEC.Algorithm.ValueString(),
			plan.DNSSEC.Curve.ValueString(),
			plan.DNSSEC.NxProof.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError("Error signing zone with DNSSEC", err.Error())
			return
		}
	}

	// Read back state
	if err := r.readZoneState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading zone state", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ZoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if zone still exists
	exists, err := r.client.ZoneExists(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error checking zone existence", err.Error())
		return
	}
	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}

	if err := r.readZoneState(ctx, &state); err != nil {
		resp.Diagnostics.AddError("Error reading zone", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ZoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ZoneResourceModel
	var state ZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate TSIG key references exist on the server
	r.validateTsigKeyReferences(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update zone options
	if err := r.setZoneOptions(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error updating zone options", err.Error())
		return
	}

	// Handle DNSSEC changes
	if plan.Type.ValueString() == "Primary" {
		planDNSSECEnabled := plan.DNSSEC != nil && plan.DNSSEC.Enabled.ValueBool()
		stateDNSSECEnabled := state.DNSSECStatus.ValueString() != "Unsigned" && state.DNSSECStatus.ValueString() != ""

		if planDNSSECEnabled && !stateDNSSECEnabled {
			// Sign zone
			err := r.client.ZoneDNSSECSign(ctx,
				plan.Name.ValueString(),
				plan.DNSSEC.Algorithm.ValueString(),
				plan.DNSSEC.Curve.ValueString(),
				plan.DNSSEC.NxProof.ValueString(),
			)
			if err != nil {
				resp.Diagnostics.AddError("Error signing zone with DNSSEC", err.Error())
				return
			}
		} else if !planDNSSECEnabled && stateDNSSECEnabled {
			// Unsign zone
			if err := r.client.ZoneDNSSECUnsign(ctx, plan.Name.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error unsigning zone", err.Error())
				return
			}
		}
	}

	// Read back state
	if err := r.readZoneState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading zone state", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes a managed zone. If the underlying zone is already gone
// (deleted out-of-band, or removed by another tool), the operation is
// treated as success — destroy is idempotent. Same posture as
// RecordResource.Delete and CatalogMembershipResource.Delete.
func (r *ZoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.ZoneDelete(ctx, state.Name.ValueString()); err != nil && !isRecordAlreadyGone(err) {
		resp.Diagnostics.AddError("Error deleting zone", err.Error())
	}
}

func (r *ZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
	// Also set ID to the zone name
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// setZoneOptions applies notify and allow_transfer settings.
func (r *ZoneResource) setZoneOptions(ctx context.Context, plan *ZoneResourceModel) error {
	opts := map[string]string{}

	// Handle notify
	if !plan.Notify.IsNull() && !plan.Notify.IsUnknown() {
		var notifyIPs []string
		plan.Notify.ElementsAs(ctx, &notifyIPs, false)
		if len(notifyIPs) > 0 {
			opts["notify"] = "SpecifiedNameServers"
			opts["notifyNameServers"] = strings.Join(notifyIPs, ",")
		} else {
			opts["notify"] = "ZoneNameServers"
		}
	}

	// Handle allow_transfer
	if !plan.AllowTransfer.IsNull() && !plan.AllowTransfer.IsUnknown() {
		var transferIPs []string
		plan.AllowTransfer.ElementsAs(ctx, &transferIPs, false)
		if len(transferIPs) > 0 {
			opts["zoneTransfer"] = "UseSpecifiedNetworkACL"
			opts["zoneTransferNetworkACL"] = strings.Join(transferIPs, ",")
		} else {
			opts["zoneTransfer"] = "AllowOnlyZoneNameServers"
		}
	}

	// Handle zone_transfer_tsig_key_names
	if !plan.ZoneTransferTsigKeyNames.IsNull() && !plan.ZoneTransferTsigKeyNames.IsUnknown() {
		var keyNames []string
		plan.ZoneTransferTsigKeyNames.ElementsAs(ctx, &keyNames, false)
		if len(keyNames) > 0 {
			opts["zoneTransferTsigKeyNames"] = strings.Join(keyNames, ",")
		} else {
			opts["zoneTransferTsigKeyNames"] = "false"
		}
	}

	// Handle primary_zone_transfer_tsig_key_name
	if !plan.PrimaryZoneTransferTsigKeyName.IsNull() && !plan.PrimaryZoneTransferTsigKeyName.IsUnknown() {
		val := plan.PrimaryZoneTransferTsigKeyName.ValueString()
		if val != "" {
			opts["primaryZoneTransferTsigKeyName"] = val
		}
	}

	if len(opts) > 0 {
		return r.client.ZoneOptionsSet(ctx, plan.Name.ValueString(), opts)
	}
	return nil
}

// readZoneState reads the current zone state from the API.
func (r *ZoneResource) readZoneState(ctx context.Context, model *ZoneResourceModel) error {
	zone, err := r.client.ZoneOptionsGet(ctx, model.Name.ValueString())
	if err != nil {
		return fmt.Errorf("reading zone options: %w", err)
	}

	model.ID = types.StringValue(zone.Name)
	model.Name = types.StringValue(zone.Name)
	model.Type = types.StringValue(zone.Type)
	model.DNSSECStatus = types.StringValue(zone.DNSSECStatus)

	if zone.Disabled {
		model.Status = types.StringValue("disabled")
	} else {
		model.Status = types.StringValue("enabled")
	}

	// Read notify IPs
	if zone.Notify == "SpecifiedNameServers" || zone.Notify == "BothZoneAndSpecifiedNameServers" {
		notifyList, diags := types.ListValueFrom(ctx, types.StringType, zone.NotifyNameServers)
		if diags.HasError() {
			return fmt.Errorf("converting notify list")
		}
		model.Notify = notifyList
	}
	// When server reports no notify IPs but user configured the attribute,
	// model.Notify retains its plan value — no action needed.

	// Read allow_transfer IPs
	if zone.ZoneTransfer == "UseSpecifiedNetworkACL" || zone.ZoneTransfer == "AllowZoneNameServersAndUseSpecifiedNetworkACL" {
		transferList, diags := types.ListValueFrom(ctx, types.StringType, zone.ZoneTransferNetworkACL)
		if diags.HasError() {
			return fmt.Errorf("converting allow_transfer list")
		}
		model.AllowTransfer = transferList
	}
	// When server reports no transfer ACL but user configured the attribute,
	// model.AllowTransfer retains its plan value — no action needed.

	// Read zone_transfer_tsig_key_names
	readStringList(ctx, &model.ZoneTransferTsigKeyNames, zone.ZoneTransferTsigKeys)

	// Read primary_zone_transfer_tsig_key_name
	// Set to null for non-secondary zone types to prevent perpetual diffs
	isSecondaryType := zone.Type == "Secondary" || zone.Type == "SecondaryForwarder" || zone.Type == "SecondaryCatalog"
	if isSecondaryType && zone.PrimaryZoneTransferTsigKeyName != "" {
		model.PrimaryZoneTransferTsigKeyName = types.StringValue(zone.PrimaryZoneTransferTsigKeyName)
	} else {
		model.PrimaryZoneTransferTsigKeyName = types.StringNull()
	}

	// Read SOA serial from zone list
	zones, err := r.client.ZoneList(ctx)
	if err != nil {
		return fmt.Errorf("listing zones for SOA serial: %w", err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, zone.Name) {
			model.SOASerial = types.Int64Value(int64(z.SOASerial))
			break
		}
	}

	// Read DNSSEC state
	if zone.DNSSECStatus != "Unsigned" && zone.DNSSECStatus != "" {
		props, err := r.client.ZoneDNSSECPropertiesGet(ctx, model.Name.ValueString())
		if err != nil {
			return fmt.Errorf("reading DNSSEC properties: %w", err)
		}

		if model.DNSSEC == nil {
			model.DNSSEC = &DNSSECModel{}
		}
		model.DNSSEC.Enabled = types.BoolValue(true)

		// Extract algorithm/curve from the private key info
		if len(props.DNSSECPrivateKeys) > 0 {
			algoName := props.DNSSECPrivateKeys[0].Algorithm
			algo, curve := mapIANAAlgorithmToAPI(algoName)
			model.DNSSEC.Algorithm = types.StringValue(algo)
			model.DNSSEC.Curve = types.StringValue(curve)
		}

		// Determine NSEC vs NSEC3
		if strings.Contains(zone.DNSSECStatus, "NSEC3") {
			model.DNSSEC.NxProof = types.StringValue("NSEC3")
		} else {
			model.DNSSEC.NxProof = types.StringValue("NSEC")
		}
	} else if model.DNSSEC != nil {
		model.DNSSEC.Enabled = types.BoolValue(false)
	}

	return nil
}

// validateTsigKeyReference checks that a TSIG key exists and, in NSS mode,
// that its algorithm meets FIPS 140-3 / CNSSI 1253 requirements.
func (r *ZoneResource) validateTsigKeyReference(ctx context.Context, keyName string, diagnostics *diag.Diagnostics) {
	key, err := r.client.TSIGKeyGet(ctx, keyName)
	if err != nil {
		if errors.Is(err, client.ErrTSIGKeyNotFound) {
			diagnostics.AddError(
				"TSIG key not found",
				fmt.Sprintf("TSIG key %q not found on the server. Ensure the key exists before referencing it in a zone.", keyName))
		} else {
			diagnostics.AddError(
				"Error validating TSIG key",
				fmt.Sprintf("Failed to look up TSIG key %q: %s", keyName, err.Error()))
		}
		return
	}

	if r.providerData != nil && r.providerData.NSS {
		if !isNSSCompliantTSIGAlgorithm(key.AlgorithmName) {
			diagnostics.AddError(
				"TSIG key does not meet NSS requirements",
				fmt.Sprintf("TSIG key %q uses algorithm %q which does not meet FIPS 140-3/CNSSI 1253 requirements. "+
					"Use hmac-sha256, hmac-sha384, or hmac-sha512.", keyName, key.AlgorithmName))
		}
	}
}

// validateTsigKeyReferences validates all TSIG key references in a zone plan.
func (r *ZoneResource) validateTsigKeyReferences(ctx context.Context, plan *ZoneResourceModel, diagnostics *diag.Diagnostics) {
	// Validate zone_transfer_tsig_key_names
	if !plan.ZoneTransferTsigKeyNames.IsNull() && !plan.ZoneTransferTsigKeyNames.IsUnknown() {
		var keyNames []string
		plan.ZoneTransferTsigKeyNames.ElementsAs(ctx, &keyNames, false)
		for _, keyName := range keyNames {
			r.validateTsigKeyReference(ctx, keyName, diagnostics)
		}
	}

	// Validate primary_zone_transfer_tsig_key_name
	if !plan.PrimaryZoneTransferTsigKeyName.IsNull() && !plan.PrimaryZoneTransferTsigKeyName.IsUnknown() {
		keyName := plan.PrimaryZoneTransferTsigKeyName.ValueString()
		if keyName != "" {
			r.validateTsigKeyReference(ctx, keyName, diagnostics)
		}
	}
}

// mapIANAAlgorithmToAPI converts IANA algorithm names (e.g., ECDSAP256SHA256)
// back to the API's algorithm + curve parameters.
func mapIANAAlgorithmToAPI(iana string) (algorithm, curve string) {
	switch iana {
	case "ECDSAP256SHA256":
		return "ECDSA", "P256"
	case "ECDSAP384SHA384":
		return "ECDSA", "P384"
	case "ED25519":
		return "EDDSA", "ED25519"
	case "ED448":
		return "EDDSA", "ED448"
	default:
		// RSA variants
		if strings.HasPrefix(iana, "RSA") {
			return "RSA", ""
		}
		return iana, ""
	}
}
