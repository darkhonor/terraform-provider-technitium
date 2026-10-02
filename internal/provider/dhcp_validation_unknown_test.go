// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Terraform validates a for_each/count resource block once before expansion,
// with every each.*/count.* reference unknown. The scope model's nested
// collections are native Go slices, which cannot represent unknown, so an
// unguarded Config.Get fails the whole plan with "Value Conversion Error ...
// Received unknown value". ValidateConfig must skip the not-fully-known pass.
// (Not an acceptance test: terraform-plugin-testing v1.16 cannot address
// string-indexed instances — "for_each is not supported".)
func TestDHCPScopeValidateConfig_UnknownConfigSkipped(t *testing.T) {
	ctx := context.Background()
	r := &DHCPScopeResource{}

	schemaResp := fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("schema error: %v", schemaResp.Diagnostics)
	}

	req := fwresource.ValidateConfigRequest{Config: tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), tftypes.UnknownValue),
	}}
	resp := fwresource.ValidateConfigResponse{}
	r.ValidateConfig(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unknown config must be skipped, got diagnostics: %v", resp.Diagnostics)
	}
}
