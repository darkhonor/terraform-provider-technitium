// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// BuildTestConfig — construct real tfsdk.Config from schema + attribute map
// ---------------------------------------------------------------------------

// BuildTestConfig constructs a tfsdk.Config from a resource schema and a map
// of attribute values. Attributes not in the map are set to null.
//
// The tftypes.NewValue constructor requires ALL keys to be present. This
// helper walks the full schema type tree and sets null for omitted attributes.
// For SingleNestedBlock, omitting means null object.
func BuildTestConfig(t *testing.T, s schema.Schema, attrs map[string]interface{}) tfsdk.Config {
	t.Helper()

	schemaType := s.Type().TerraformType(context.Background())
	raw := buildValue(t, schemaType, attrs)

	return tfsdk.Config{
		Raw:    raw,
		Schema: s,
	}
}

// buildValue recursively constructs a tftypes.Value from a type and attrs map.
func buildValue(t *testing.T, typ tftypes.Type, attrs map[string]interface{}) tftypes.Value {
	t.Helper()

	objType, isObj := typ.(tftypes.Object)
	if !isObj {
		t.Fatalf("buildValue: expected tftypes.Object, got %s", typ)
	}

	values := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for name, attrType := range objType.AttributeTypes {
		provided, ok := attrs[name]
		if !ok {
			// Attribute omitted — set to null
			values[name] = tftypes.NewValue(attrType, nil)
			continue
		}

		// Check if provided value is a nested map (for SingleNestedBlock)
		if nestedMap, isMap := provided.(map[string]interface{}); isMap {
			values[name] = buildValue(t, attrType, nestedMap)
			continue
		}

		// List value — tftypes.NewValue expects []tftypes.Value, not []string
		if listType, isList := attrType.(tftypes.List); isList {
			if strSlice, isStrSlice := provided.([]string); isStrSlice {
				vals := make([]tftypes.Value, len(strSlice))
				for i, s := range strSlice {
					vals[i] = tftypes.NewValue(listType.ElementType, s)
				}
				values[name] = tftypes.NewValue(listType, vals)
				continue
			}
		}

		// Scalar value
		values[name] = tftypes.NewValue(attrType, provided)
	}

	return tftypes.NewValue(objType, values)
}

// ---------------------------------------------------------------------------
// Zone resource schema — minimal copy for integration tests
// ---------------------------------------------------------------------------

// zoneResourceSchema returns a minimal zone resource schema for integration tests.
// This duplicates the schema from zone_resource.go to avoid circular imports.
// If the schema changes, update this copy. Integration tests will fail if
// they diverge (serving as a canary).
func zoneResourceSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id":                    schema.StringAttribute{Computed: true},
			"name":                  schema.StringAttribute{Required: true},
			"type":                  schema.StringAttribute{Required: true},
			"soa_serial_date_scheme": schema.BoolAttribute{Optional: true},
			"notify":                schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"allow_transfer":        schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"zone_transfer_tsig_key_names":          schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"primary_zone_transfer_tsig_key_name":   schema.StringAttribute{Optional: true},
			"soa_serial":    schema.Int64Attribute{Computed: true},
			"status":        schema.StringAttribute{Computed: true},
			"dnssec_status": schema.StringAttribute{Computed: true},
		},
		Blocks: map[string]schema.Block{
			"dnssec": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"enabled":   schema.BoolAttribute{Optional: true},
					"algorithm": schema.StringAttribute{Optional: true},
					"curve":     schema.StringAttribute{Optional: true},
					"nx_proof":  schema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// BuildTestConfig meta-tests
// ---------------------------------------------------------------------------

func TestBuildTestConfig_SimpleAttributes(t *testing.T) {
	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name":    schema.StringAttribute{Required: true},
			"enabled": schema.BoolAttribute{Optional: true},
		},
	}

	config := BuildTestConfig(t, s, map[string]interface{}{
		"name": "test",
		// "enabled" intentionally omitted — should be null
	})

	adapter := &TFConfigAdapter{Config: config}

	// "name" should be present
	val, ok := adapter.GetString("name")
	if !ok || val != "test" {
		t.Errorf("expected name='test', got %q ok=%v", val, ok)
	}

	// "enabled" should be null (omitted)
	if !adapter.IsNull("enabled") {
		t.Error("expected enabled to be null (omitted)")
	}
	if adapter.IsUnknown("enabled") {
		t.Error("expected enabled to NOT be unknown")
	}
}

func TestBuildTestConfig_NestedBlock(t *testing.T) {
	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{Required: true},
		},
		Blocks: map[string]schema.Block{
			"nested": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{Optional: true},
					"mode":    schema.StringAttribute{Optional: true},
				},
			},
		},
	}

	// Test with nested block omitted
	config := BuildTestConfig(t, s, map[string]interface{}{
		"name": "test",
	})
	adapter := &TFConfigAdapter{Config: config}
	if !adapter.IsNull("nested") {
		t.Error("expected nested block to be null when omitted")
	}
	if !adapter.IsNull("nested.enabled") {
		t.Error("expected nested.enabled to be null when parent block omitted")
	}

	// Test with nested block present
	config2 := BuildTestConfig(t, s, map[string]interface{}{
		"name": "test",
		"nested": map[string]interface{}{
			"enabled": true,
		},
	})
	adapter2 := &TFConfigAdapter{Config: config2}
	if adapter2.IsNull("nested") {
		t.Error("expected nested block to NOT be null when present")
	}
	val, ok := adapter2.GetBool("nested.enabled")
	if !ok || !val {
		t.Error("expected nested.enabled=true")
	}
	if !adapter2.IsNull("nested.mode") {
		t.Error("expected nested.mode to be null (omitted within present block)")
	}
}
