// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &ZoneDataSource{}

func NewZoneDataSource() datasource.DataSource {
	return &ZoneDataSource{}
}

// ZoneDataSource defines the data source implementation.
type ZoneDataSource struct {
	client *client.Client
}

// ZoneDataSourceModel describes the data source data model.
type ZoneDataSourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Type                types.String `tfsdk:"type"`
	Disabled            types.Bool   `tfsdk:"disabled"`
	DNSSECStatus        types.String `tfsdk:"dnssec_status"`
	SOASerial           types.Int64  `tfsdk:"soa_serial"`
	ZoneTransfer        types.String `tfsdk:"zone_transfer"`
	ZoneTransferACL     types.List   `tfsdk:"zone_transfer_acl"`
	Notify              types.String `tfsdk:"notify"`
	NotifyNameServers   types.List   `tfsdk:"notify_name_servers"`
}

func (d *ZoneDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zone"
}

func (d *ZoneDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a Technitium DNS zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Zone identifier (same as zone name).",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The domain name of the zone to look up.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of zone (Primary, Secondary, Stub, Forwarder).",
				Computed:    true,
			},
			"disabled": schema.BoolAttribute{
				Description: "Whether the zone is disabled.",
				Computed:    true,
			},
			"dnssec_status": schema.StringAttribute{
				Description: "DNSSEC signing status.",
				Computed:    true,
			},
			"soa_serial": schema.Int64Attribute{
				Description: "Current SOA serial number.",
				Computed:    true,
			},
			"zone_transfer": schema.StringAttribute{
				Description: "Zone transfer policy.",
				Computed:    true,
			},
			"zone_transfer_acl": schema.ListAttribute{
				Description: "Zone transfer network ACL.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"notify": schema.StringAttribute{
				Description: "Zone notify policy.",
				Computed:    true,
			},
			"notify_name_servers": schema.ListAttribute{
				Description: "Notify name server IP addresses.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (d *ZoneDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ZoneDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ZoneDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zoneName := config.Name.ValueString()

	// Get zone options
	zone, err := d.client.ZoneOptionsGet(ctx, zoneName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading zone",
			fmt.Sprintf("Could not read zone %q: %s", zoneName, err.Error()))
		return
	}

	config.ID = types.StringValue(zone.Name)
	config.Name = types.StringValue(zone.Name)
	config.Type = types.StringValue(zone.Type)
	config.Disabled = types.BoolValue(zone.Disabled)
	config.DNSSECStatus = types.StringValue(zone.DNSSECStatus)
	config.ZoneTransfer = types.StringValue(zone.ZoneTransfer)
	config.Notify = types.StringValue(zone.Notify)

	// Zone transfer ACL
	transferACL, diags := types.ListValueFrom(ctx, types.StringType, zone.ZoneTransferNetworkACL)
	resp.Diagnostics.Append(diags...)
	config.ZoneTransferACL = transferACL

	// Notify name servers
	notifyNS, diags := types.ListValueFrom(ctx, types.StringType, zone.NotifyNameServers)
	resp.Diagnostics.Append(diags...)
	config.NotifyNameServers = notifyNS

	// Get SOA serial from zone list
	zones, err := d.client.ZoneList(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing zones", err.Error())
		return
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, zoneName) {
			config.SOASerial = types.Int64Value(int64(z.SOASerial))
			break
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
