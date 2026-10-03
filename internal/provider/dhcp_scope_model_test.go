// Copyright (c) 2026 Dustin Sweigart
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// scopeFromModel must preserve the nil/empty distinction of reserved_leases:
// nil omits the reservedLeases parameter, a declared list — even an empty
// one — sends it.
func TestDHCPScopeFromModel_ReservedLeasesNilVsEmpty(t *testing.T) {
	r := &DHCPScopeResource{}
	ctx := context.Background()

	base := func() DHCPScopeResourceModel {
		return DHCPScopeResourceModel{
			Name:            types.StringValue("lan"),
			StartingAddress: types.StringValue("10.0.0.50"),
			EndingAddress:   types.StringValue("10.0.0.250"),
			SubnetMask:      types.StringValue("255.255.255.0"),
		}
	}

	t.Run("nil attribute maps to nil slice", func(t *testing.T) {
		m := base()
		var diags diag.Diagnostics
		scope := r.scopeFromModel(ctx, &m, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if scope.ReservedLeases != nil {
			t.Errorf("ReservedLeases: got %v, want nil (parameter must be omitted)", scope.ReservedLeases)
		}
	})

	t.Run("declared empty list maps to non-nil empty slice", func(t *testing.T) {
		m := base()
		m.ReservedLeases = []DHCPReservedLeaseModel{}
		var diags diag.Diagnostics
		scope := r.scopeFromModel(ctx, &m, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if scope.ReservedLeases == nil {
			t.Error("ReservedLeases: got nil, want non-nil empty slice (parameter must be sent to clear)")
		}
		if len(scope.ReservedLeases) != 0 {
			t.Errorf("ReservedLeases: got %d entries, want 0", len(scope.ReservedLeases))
		}
	})

	t.Run("declared entries map through", func(t *testing.T) {
		m := base()
		m.ReservedLeases = []DHCPReservedLeaseModel{{
			HostName:        types.StringValue("printer"),
			HardwareAddress: types.StringValue("00-11-22-33-44-55"),
			Address:         types.StringValue("10.0.0.100"),
			Comments:        types.StringValue("note"),
		}}
		var diags diag.Diagnostics
		scope := r.scopeFromModel(ctx, &m, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if len(scope.ReservedLeases) != 1 || scope.ReservedLeases[0].HardwareAddress != "00-11-22-33-44-55" {
			t.Errorf("ReservedLeases: got %v, want the single declared reservation", scope.ReservedLeases)
		}
	})
}
