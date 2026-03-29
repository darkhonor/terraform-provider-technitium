// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                     = &TSIGKeyResource{}
	_ resource.ResourceWithImportState      = &TSIGKeyResource{}
	_ resource.ResourceWithModifyPlan       = &TSIGKeyResource{}
	_ resource.ResourceWithConfigValidators = &TSIGKeyResource{}
)

// validTSIGAlgorithms lists all TSIG algorithms supported by Technitium.
var validTSIGAlgorithms = map[string]bool{
	"hmac-md5.sig-alg.reg.int": true, "hmac-sha1": true,
	"hmac-sha256": true, "hmac-sha256-128": true,
	"hmac-sha384": true, "hmac-sha384-192": true,
	"hmac-sha512": true, "hmac-sha512-256": true,
}

func NewTSIGKeyResource() resource.Resource {
	return &TSIGKeyResource{}
}

// TSIGKeyResource defines the resource implementation.
type TSIGKeyResource struct {
	client       *client.Client
	providerData *TechnitiumProviderData
}

// TSIGKeyResourceModel describes the resource data model.
type TSIGKeyResourceModel struct {
	ID           types.String `tfsdk:"id"`
	KeyName      types.String `tfsdk:"key_name"`
	Algorithm    types.String `tfsdk:"algorithm"`
	SharedSecret types.String `tfsdk:"shared_secret"`
}

func (r *TSIGKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tsig_key"
}

func (r *TSIGKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Technitium DNS TSIG key.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "TSIG key identifier (same as key_name).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_name": schema.StringAttribute{
				Description: "The TSIG key name (e.g., transfer.example.com).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"algorithm": schema.StringAttribute{
				Description: "The TSIG algorithm. Valid values: hmac-md5.sig-alg.reg.int, hmac-sha1, hmac-sha256, hmac-sha256-128, hmac-sha384, hmac-sha384-192, hmac-sha512, hmac-sha512-256.",
				Required:    true,
			},
			"shared_secret": schema.StringAttribute{
				Description: "The base64-encoded shared secret. If omitted, the server generates one.",
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func (r *TSIGKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TSIGKeyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Don't modify plan on destroy
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan TSIGKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	algo := plan.Algorithm.ValueString()

	// Validate algorithm is in the supported list
	if !validTSIGAlgorithms[algo] {
		resp.Diagnostics.AddError("Invalid TSIG algorithm",
			fmt.Sprintf("Algorithm %q is not supported. Use one of: hmac-md5.sig-alg.reg.int, hmac-sha1, hmac-sha256, hmac-sha256-128, hmac-sha384, hmac-sha384-192, hmac-sha512, hmac-sha512-256.", algo))
		return
	}

	// NSS compliance check
	if r.providerData != nil && r.providerData.NSS {
		if !isNSSCompliantTSIGAlgorithm(algo) {
			resp.Diagnostics.AddError("TSIG algorithm not allowed in NSS mode",
				fmt.Sprintf("Algorithm %q does not meet FIPS 140-3/CNSSI 1253 requirements. Use hmac-sha256, hmac-sha384, or hmac-sha512.", algo))
		}
	}

	// STIG compliance validation
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		r.providerData.STIGEngine.ValidatePlan(
			ctx,
			validators.ResourceTSIGKey,
			&validators.TFPlanAdapter{Plan: req.Plan},
			&validators.TFStateAdapter{State: req.State},
			&resp.Diagnostics,
		)
	}
}

func (r *TSIGKeyResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	if r.providerData == nil || r.providerData.STIGEngine == nil {
		return nil
	}
	return []resource.ConfigValidator{
		newSTIGConfigValidator(r.providerData.STIGEngine, validators.ResourceTSIGKey),
	}
}

func (r *TSIGKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TSIGKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := client.TSIGKey{
		KeyName:       plan.KeyName.ValueString(),
		AlgorithmName: plan.Algorithm.ValueString(),
		SharedSecret:  plan.SharedSecret.ValueString(),
	}

	if err := r.client.TSIGKeyCreate(ctx, key); err != nil {
		resp.Diagnostics.AddError("Error creating TSIG key", err.Error())
		return
	}

	// Read back state from the API
	created, err := r.client.TSIGKeyGet(ctx, plan.KeyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading TSIG key after create", err.Error())
		return
	}

	plan.ID = types.StringValue(created.KeyName)
	plan.KeyName = types.StringValue(created.KeyName)
	plan.Algorithm = types.StringValue(created.AlgorithmName)
	plan.SharedSecret = types.StringValue(created.SharedSecret)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TSIGKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TSIGKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := r.client.TSIGKeyGet(ctx, state.KeyName.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrTSIGKeyNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading TSIG key", err.Error())
		return
	}

	state.ID = types.StringValue(key.KeyName)
	state.KeyName = types.StringValue(key.KeyName)
	state.Algorithm = types.StringValue(key.AlgorithmName)
	state.SharedSecret = types.StringValue(key.SharedSecret)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TSIGKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TSIGKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := client.TSIGKey{
		KeyName:       plan.KeyName.ValueString(),
		AlgorithmName: plan.Algorithm.ValueString(),
		SharedSecret:  plan.SharedSecret.ValueString(),
	}

	if err := r.client.TSIGKeyUpdate(ctx, key); err != nil {
		resp.Diagnostics.AddError("Error updating TSIG key", err.Error())
		return
	}

	// Read back state
	updated, err := r.client.TSIGKeyGet(ctx, plan.KeyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading TSIG key after update", err.Error())
		return
	}

	plan.ID = types.StringValue(updated.KeyName)
	plan.KeyName = types.StringValue(updated.KeyName)
	plan.Algorithm = types.StringValue(updated.AlgorithmName)
	plan.SharedSecret = types.StringValue(updated.SharedSecret)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TSIGKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TSIGKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.TSIGKeyDelete(ctx, state.KeyName.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting TSIG key", err.Error())
	}
}

func (r *TSIGKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by key_name — set both attributes explicitly
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
