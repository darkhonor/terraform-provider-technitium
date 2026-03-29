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

var _ datasource.DataSource = &RecordDataSource{}

func NewRecordDataSource() datasource.DataSource {
	return &RecordDataSource{}
}

type RecordDataSource struct {
	client *client.Client
}

type RecordDataSourceModel struct {
	ID       types.String          `tfsdk:"id"`
	Zone     types.String          `tfsdk:"zone"`
	Name     types.String          `tfsdk:"name"`
	Type     types.String          `tfsdk:"type"`
	Value    types.String          `tfsdk:"value"`
	TTL      types.Int64           `tfsdk:"ttl"`
	Records  []RecordDataItemModel `tfsdk:"records"`
}

type RecordDataItemModel struct {
	Value types.String `tfsdk:"value"`
	TTL   types.Int64  `tfsdk:"ttl"`
}

func (d *RecordDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record"
}

func (d *RecordDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads DNS records from a Technitium DNS zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Record identifier.",
				Computed:    true,
			},
			"zone": schema.StringAttribute{
				Description: "Parent zone name.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Fully qualified domain name.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "DNS record type to filter by.",
				Required:    true,
			},
			"value": schema.StringAttribute{
				Description: "Record value (populated when exactly one record matches).",
				Computed:    true,
			},
			"ttl": schema.Int64Attribute{
				Description: "Record TTL (populated when exactly one record matches).",
				Computed:    true,
			},
			"records": schema.ListNestedAttribute{
				Description: "All matching records (populated when multiple records match).",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"value": schema.StringAttribute{
							Description: "Record value.",
							Computed:    true,
						},
						"ttl": schema.Int64Attribute{
							Description: "Record TTL.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *RecordDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *RecordDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config RecordDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	records, err := d.client.RecordGet(ctx, config.Name.ValueString(), config.Zone.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading records", err.Error())
		return
	}

	// Filter by type
	recordType := config.Type.ValueString()
	var matching []client.Record
	for _, rec := range records {
		if rec.Type == recordType {
			matching = append(matching, rec)
		}
	}

	config.ID = types.StringValue(fmt.Sprintf("%s/%s/%s",
		config.Zone.ValueString(), config.Name.ValueString(), recordType))

	if len(matching) == 0 {
		resp.Diagnostics.AddError("No records found",
			fmt.Sprintf("No %s records found for %s in zone %s",
				recordType, config.Name.ValueString(), config.Zone.ValueString()))
		return
	}

	// Build records list
	config.Records = make([]RecordDataItemModel, len(matching))
	for i, rec := range matching {
		config.Records[i] = RecordDataItemModel{
			Value: types.StringValue(client.RecordValueFromRData(recordType, rec.RData)),
			TTL:   types.Int64Value(int64(rec.TTL)),
		}
	}

	// If single record, populate the singular fields
	if len(matching) == 1 {
		config.Value = types.StringValue(client.RecordValueFromRData(recordType, matching[0].RData))
		config.TTL = types.Int64Value(int64(matching[0].TTL))
	} else {
		config.Value = types.StringNull()
		config.TTL = types.Int64Null()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
