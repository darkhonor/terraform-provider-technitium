// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/inputvalidation"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// inputConfigValidator implements resource.ConfigValidator for input validation.
type inputConfigValidator struct {
	registry *inputvalidation.Registry
	resource inputvalidation.TargetResource
}

func newInputConfigValidator(registry *inputvalidation.Registry, resource inputvalidation.TargetResource) inputConfigValidator {
	return inputConfigValidator{registry: registry, resource: resource}
}

func (v inputConfigValidator) Description(_ context.Context) string {
	return "Validates resource configuration inputs have correct format and required fields"
}

func (v inputConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v inputConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	adapter := inputvalidation.NewTFConfigAdapter(ctx, req.Config)
	findings := v.registry.RunRules(ctx, v.resource, adapter)
	for _, f := range findings {
		resp.Diagnostics.AddAttributeError(
			path.Root(f.Attribute),
			f.Summary,
			f.Detail,
		)
	}
}
