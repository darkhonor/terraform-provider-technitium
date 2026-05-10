// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                     = &CatalogMembershipResource{}
	_ resource.ResourceWithImportState      = &CatalogMembershipResource{}
	_ resource.ResourceWithModifyPlan       = &CatalogMembershipResource{}
	_ resource.ResourceWithConfigValidators = &CatalogMembershipResource{}
)

func NewCatalogMembershipResource() resource.Resource {
	return &CatalogMembershipResource{}
}

// CatalogMembershipResource manages the membership relationship between a DNS
// zone (the member) and a catalog zone (the container).
//
// In Technitium, catalog zones (RFC 9432) are special zones whose contents
// instruct secondary name servers which zones to slave automatically. Catalog
// membership is a per-member-zone setting; this resource exposes that setting
// as a separate Terraform resource so its lifecycle can be managed
// independently of the member zone itself.
type CatalogMembershipResource struct {
	client       *client.Client
	providerData *TechnitiumProviderData
}

// CatalogMembershipResourceModel describes the resource data model.
type CatalogMembershipResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Zone        types.String `tfsdk:"zone"`
	CatalogZone types.String `tfsdk:"catalog_zone"`
}

func (r *CatalogMembershipResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_catalog_membership"
}

func (r *CatalogMembershipResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages catalog zone membership for a Technitium DNS zone. " +
			"Assigns the member zone to a catalog zone so that secondary name " +
			"servers slaving the catalog zone will automatically provision the " +
			"member zone. Valid for Primary, Secondary, Stub, and Forwarder " +
			"member zones; the referenced catalog zone must be of type Catalog " +
			"or SecondaryCatalog.\n\n" +
			"**Inheritance:** When a zone is added to a catalog, settings on " +
			"the catalog zone for `queryAccess`, `zoneTransfer`, and `notify` " +
			"take precedence over the same settings declared on the member " +
			"zone via `technitium_zone`, unless override flags are configured. " +
			"This provider does not yet expose those override flags; see the " +
			"project issue tracker for follow-on work.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Catalog membership identifier (same as zone).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"zone": schema.StringAttribute{
				Description: "The name of the member zone whose catalog membership is being managed. " +
					"The zone must already exist by the time `terraform apply` reaches this resource; " +
					"if the zone is created by another resource in the same configuration, declare an " +
					"explicit dependency or rely on attribute reference ordering. " +
					"Changing this attribute forces replacement.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"catalog_zone": schema.StringAttribute{
				Description: "The name of the catalog zone to which this zone is being assigned as a member. " +
					"The catalog zone must exist by the time `terraform apply` reaches this resource and " +
					"must be of type Catalog or SecondaryCatalog. The Technitium server returns an error " +
					"at apply time if the catalog zone is missing or of a non-catalog type.",
				Required: true,
			},
		},
	}
}

func (r *CatalogMembershipResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// ConfigValidators returns config-level validators that run at terraform
// validate / plan time without requiring API access. These catch common typos
// and self-references early, leaving live-API correctness to apply time.
func (r *CatalogMembershipResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{catalogMembershipSelfReferenceValidator{}}
}

// ModifyPlan emits a one-time inheritance warning whenever this resource is
// being created OR when its catalog_zone attribute is changing. The warning
// surfaces the queryAccess / zoneTransfer / notify shadowing behavior because
// override flags are not yet exposed by this provider.
//
// Plan-time API existence checks are intentionally NOT performed here: the
// member zone and the catalog zone are commonly created in the same plan as
// this membership, in which case neither zone exists yet on the server when
// ModifyPlan runs. The Technitium API returns a clear error at apply time if
// either zone is missing.
func (r *CatalogMembershipResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		// Destroy plan; nothing to warn about.
		return
	}

	var plan CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Detect whether this is a create (no prior state) or whether catalog_zone
	// is changing on an existing membership. Skip the warning on no-op refresh
	// plans to avoid training operators to ignore it.
	isCreate := req.State.Raw.IsNull()
	catalogChanging := false
	if !isCreate {
		var state CatalogMembershipResourceModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		catalogChanging = !plan.CatalogZone.Equal(state.CatalogZone)
	}

	if isCreate || catalogChanging {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("catalog_zone"),
			"Catalog inheritance: query/transfer/notify settings take precedence",
			"When a zone is a member of a catalog zone, the catalog zone's "+
				"queryAccess, zoneTransfer, and notify settings take effect on "+
				"the member zone unless override flags are set. This provider "+
				"does not yet expose those override flags; any such settings "+
				"declared on the underlying technitium_zone resource may be "+
				"silently shadowed by the catalog zone. See "+
				"https://github.com/darkhonor/terraform-provider-technitium/issues/29 "+
				"for follow-on work.",
		)
	}
}

func (r *CatalogMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zoneName := plan.Zone.ValueString()
	catalogName := plan.CatalogZone.ValueString()

	if err := r.client.ZoneSetCatalog(ctx, zoneName, catalogName); err != nil {
		resp.Diagnostics.AddError(
			"Error assigning catalog membership",
			fmt.Sprintf(
				"Failed to assign zone %q to catalog %q on the Technitium server: %s\n\n"+
					"Common causes:\n"+
					"  - The member zone does not exist. Ensure a technitium_zone resource "+
					"creates it, and that Terraform applies that resource before this one "+
					"(an explicit attribute reference such as `zone = technitium_zone.x.name` "+
					"establishes the dependency).\n"+
					"  - The catalog zone does not exist or is not of type Catalog/SecondaryCatalog.\n"+
					"  - The member zone is of an ineligible type (only Primary, Secondary, "+
					"Stub, and Forwarder zones may be catalog members).",
				zoneName, catalogName, err.Error()))
		return
	}

	// Read back to confirm the API accepted the assignment. DNS names are
	// case-insensitive (RFC 1035 section 2.3.3), so compare with EqualFold to
	// tolerate any case normalization the API performs on the way out.
	zoneOpts, err := r.client.ZoneOptionsGet(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading zone options after assigning catalog membership",
			fmt.Sprintf("Catalog membership was set on the API but the read-back failed: %s", err.Error()))
		return
	}

	observed := stringFromPtr(zoneOpts.Catalog)
	if !strings.EqualFold(observed, catalogName) {
		resp.Diagnostics.AddError(
			"Catalog membership not reflected by the API after assignment",
			fmt.Sprintf("Expected catalog %q on zone %q after set; observed %q. The Technitium API may have rejected the assignment silently.", catalogName, zoneName, observed))
		return
	}

	plan.ID = types.StringValue(zoneName)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CatalogMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zoneName := state.Zone.ValueString()

	// Determine whether the underlying zone still exists. A typed lookup via
	// ZoneExists avoids depending on error-string text from ZoneOptionsGet.
	exists, err := r.client.ZoneExists(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error checking zone existence during Read",
			fmt.Sprintf("Failed to determine whether zone %q still exists: %s", zoneName, err.Error()))
		return
	}
	if !exists {
		// The zone has been removed out-of-band; remove the membership from
		// state so the next plan can react cleanly.
		resp.State.RemoveResource(ctx)
		return
	}

	zoneOpts, err := r.client.ZoneOptionsGet(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading zone options",
			fmt.Sprintf("Failed to read options for zone %q: %s", zoneName, err.Error()))
		return
	}

	observed := stringFromPtr(zoneOpts.Catalog)
	if observed == "" {
		// Membership has been removed out-of-band; drop from state. The
		// next terraform plan will offer to recreate it.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(zoneName)
	state.CatalogZone = types.StringValue(observed)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CatalogMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zoneName := plan.Zone.ValueString()
	catalogName := plan.CatalogZone.ValueString()

	if err := r.client.ZoneSetCatalog(ctx, zoneName, catalogName); err != nil {
		resp.Diagnostics.AddError(
			"Error updating catalog membership",
			fmt.Sprintf(
				"Failed to update catalog assignment for zone %q to %q on the Technitium server: %s",
				zoneName, catalogName, err.Error()))
		return
	}

	zoneOpts, err := r.client.ZoneOptionsGet(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading zone options after update", err.Error())
		return
	}

	observed := stringFromPtr(zoneOpts.Catalog)
	if !strings.EqualFold(observed, catalogName) {
		resp.Diagnostics.AddError(
			"Catalog membership not reflected by the API after update",
			fmt.Sprintf("Expected catalog %q on zone %q after set; observed %q.", catalogName, zoneName, observed))
		return
	}

	plan.ID = types.StringValue(zoneName)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes catalog membership from the member zone, leaving the zone
// itself intact. If the zone has been deleted out-of-band (operator removed
// it directly via the Technitium UI, or another Terraform resource), Delete
// treats the operation as already complete and returns success.
//
// Edge case: if the underlying zone has been *renamed* out-of-band rather
// than deleted, ZoneExists for the original name will return false and this
// Delete returns success — Terraform will lose the chance to unset membership
// on whichever name the zone now has. Catalog membership on a renamed zone
// remains a possible source of stale state and is the operator's
// responsibility to clean up.
func (r *CatalogMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zoneName := state.Zone.ValueString()

	exists, err := r.client.ZoneExists(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error checking zone existence during Delete",
			fmt.Sprintf("Failed to determine whether zone %q still exists: %s", zoneName, err.Error()))
		return
	}
	if !exists {
		// Zone is gone (deleted or renamed out-of-band); membership is
		// effectively gone too. Idempotent destroy.
		return
	}

	// Unset catalog membership by passing an empty catalog value. The member
	// zone itself remains intact; ownership of the zone resource lifecycle
	// belongs to the technitium_zone resource that created it.
	if err := r.client.ZoneSetCatalog(ctx, zoneName, ""); err != nil {
		resp.Diagnostics.AddError("Error unsetting catalog membership",
			fmt.Sprintf("Failed to remove catalog assignment from zone %q: %s", zoneName, err.Error()))
	}
}

func (r *CatalogMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// stringFromPtr returns the dereferenced value of a string pointer, or the
// empty string if the pointer is nil.
func stringFromPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// catalogMembershipSelfReferenceValidator is a resource.ConfigValidator that
// ensures the member zone and the catalog zone are not the same DNS name. A
// zone cannot be a member of itself; this catches the typo at plan time.
type catalogMembershipSelfReferenceValidator struct{}

func (catalogMembershipSelfReferenceValidator) Description(_ context.Context) string {
	return "Validates that catalog_zone differs from zone (a zone cannot be a member of itself)."
}

func (v catalogMembershipSelfReferenceValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (catalogMembershipSelfReferenceValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg CatalogMembershipResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip the check when either value is unknown or null; cannot be
	// validated until both are concrete.
	if cfg.Zone.IsUnknown() || cfg.Zone.IsNull() ||
		cfg.CatalogZone.IsUnknown() || cfg.CatalogZone.IsNull() {
		return
	}

	if strings.EqualFold(cfg.Zone.ValueString(), cfg.CatalogZone.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("catalog_zone"),
			"catalog_zone must differ from zone",
			fmt.Sprintf("A zone cannot be a member of itself. Both attributes are set to %q.", cfg.Zone.ValueString()),
		)
	}
}
