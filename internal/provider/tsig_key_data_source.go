// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &TSIGKeyDataSource{}

func NewTSIGKeyDataSource() datasource.DataSource {
	return &TSIGKeyDataSource{}
}

type TSIGKeyDataSource struct {
	client *client.Client
}

type TSIGKeyDataSourceModel struct {
	ID           types.String `tfsdk:"id"`
	KeyName      types.String `tfsdk:"key_name"`
	Algorithm    types.String `tfsdk:"algorithm"`
	SharedSecret types.String `tfsdk:"shared_secret"`
}

func (d *TSIGKeyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tsig_key"
}

func (d *TSIGKeyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a TSIG key from the Technitium DNS Server by name.",
		Attributes: map[string]schema.Attribute{
			"id":            schema.StringAttribute{Computed: true, Description: "TSIG key identifier (same as key_name)."},
			"key_name":      schema.StringAttribute{Required: true, Description: "The TSIG key name to look up."},
			"algorithm":     schema.StringAttribute{Computed: true, Description: "HMAC algorithm of the TSIG key."},
			"shared_secret": schema.StringAttribute{Computed: true, Sensitive: true, Description: "Base64-encoded shared secret."},
		},
	}
}

func (d *TSIGKeyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	d.client = providerData.Client
}

func (d *TSIGKeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config TSIGKeyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := d.client.TSIGKeyGet(ctx, config.KeyName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading TSIG key",
			fmt.Sprintf("Could not find TSIG key %q: %s", config.KeyName.ValueString(), err.Error()))
		return
	}

	state := TSIGKeyDataSourceModel{
		ID:           types.StringValue(key.KeyName),
		KeyName:      types.StringValue(key.KeyName),
		Algorithm:    types.StringValue(key.AlgorithmName),
		SharedSecret: types.StringValue(key.SharedSecret),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
