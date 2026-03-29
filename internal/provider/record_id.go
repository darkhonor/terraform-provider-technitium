// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

const recordIDSeparator = "::"

// buildRecordID constructs a composite record ID from the resource model.
//
// The ID format encodes type-specific fields to prevent collisions when
// multiple records share the same name and type (e.g., multiple MX records).
//
// Formats:
//   - Simple types (A, AAAA, CNAME, TXT, PTR, NS): zone::name::type::value
//   - MX: zone::name::MX::exchange:priority
//   - SRV: zone::name::SRV::target:priority:weight:port
//   - CAA: zone::name::CAA::value:flags:tag
func buildRecordID(model *RecordResourceModel) string {
	zone := model.Zone.ValueString()
	name := model.Name.ValueString()
	recordType := model.Type.ValueString()
	value := model.Value.ValueString()

	var valueSegment string
	switch recordType {
	case "MX":
		valueSegment = fmt.Sprintf("%s:%d", value, model.Priority.ValueInt64())
	case "SRV":
		valueSegment = fmt.Sprintf("%s:%d:%d:%d",
			value,
			model.Priority.ValueInt64(),
			model.Weight.ValueInt64(),
			model.Port.ValueInt64(),
		)
	case "CAA":
		valueSegment = fmt.Sprintf("%s:%d:%s",
			value,
			model.CAAFlags.ValueInt64(),
			model.CAATag.ValueString(),
		)
	default:
		valueSegment = value
	}

	return strings.Join([]string{zone, name, recordType, valueSegment}, recordIDSeparator)
}

// parseRecordID splits a composite ID into its four segments.
//
// Uses SplitN with limit 4 so that values containing "::" (e.g., IPv6
// addresses in AAAA records or TXT content) are preserved intact in the
// value segment.
func parseRecordID(id string) (zone, name, recordType, valueSegment string, err error) {
	parts := strings.SplitN(id, recordIDSeparator, 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", "", fmt.Errorf(
			"invalid record ID %q: expected format zone::name::type::value", id)
	}
	return parts[0], parts[1], parts[2], parts[3], nil
}

// parseImportValueSegment extracts value and type-specific fields from the
// value segment of an import ID.
//
// Formats:
//   - MX: exchange:priority (parsed from right via LastIndex)
//   - SRV: target:priority:weight:port (last 3 fields numeric, rest is target)
//   - CAA: value:flags:tag (last 2 fields are flags+tag, rest is value)
//   - Simple types: entire segment is the value
func parseImportValueSegment(recordType, valueSegment string) (
	value string, priority, weight, port, caaFlags int64, caaTag string, err error,
) {
	switch recordType {
	case "MX":
		idx := strings.LastIndex(valueSegment, ":")
		if idx < 0 {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid MX value segment %q: expected format exchange:priority", valueSegment)
		}
		value = valueSegment[:idx]
		p, parseErr := strconv.ParseInt(valueSegment[idx+1:], 10, 64)
		if parseErr != nil {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid MX priority in %q: %w", valueSegment, parseErr)
		}
		priority = p
		return value, priority, 0, 0, 0, "", nil

	case "SRV":
		// Format: target:priority:weight:port
		// Parse from the right: last 3 colon-separated fields are numeric.
		parts := strings.Split(valueSegment, ":")
		if len(parts) < 4 {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid SRV value segment %q: expected format target:priority:weight:port", valueSegment)
		}
		// Last 3 are priority, weight, port; everything before is the target.
		portStr := parts[len(parts)-1]
		weightStr := parts[len(parts)-2]
		priorityStr := parts[len(parts)-3]
		target := strings.Join(parts[:len(parts)-3], ":")

		p, parseErr := strconv.ParseInt(priorityStr, 10, 64)
		if parseErr != nil {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid SRV priority in %q: %w", valueSegment, parseErr)
		}
		w, parseErr := strconv.ParseInt(weightStr, 10, 64)
		if parseErr != nil {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid SRV weight in %q: %w", valueSegment, parseErr)
		}
		pt, parseErr := strconv.ParseInt(portStr, 10, 64)
		if parseErr != nil {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid SRV port in %q: %w", valueSegment, parseErr)
		}
		return target, p, w, pt, 0, "", nil

	case "CAA":
		// Format: value:flags:tag
		// Parse from the right: last field is tag, second-to-last is flags.
		parts := strings.Split(valueSegment, ":")
		if len(parts) < 3 {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid CAA value segment %q: expected format value:flags:tag", valueSegment)
		}
		tag := parts[len(parts)-1]
		flagsStr := parts[len(parts)-2]
		val := strings.Join(parts[:len(parts)-2], ":")

		f, parseErr := strconv.ParseInt(flagsStr, 10, 64)
		if parseErr != nil {
			return "", 0, 0, 0, 0, "", fmt.Errorf(
				"invalid CAA flags in %q: %w", valueSegment, parseErr)
		}
		return val, 0, 0, 0, f, tag, nil

	default:
		return valueSegment, 0, 0, 0, 0, "", nil
	}
}

// recordMatchesState returns true if an API record matches the Terraform state
// model. This is used to find the specific record when multiple records share
// the same name and type.
//
// Matching criteria by type:
//   - All types: match on type AND primary value (via client.RecordValueFromRData)
//   - MX: also match on preference (rData "preference") vs state.Priority
//   - SRV: also match on priority, weight, port rData fields
//   - CAA: also match on flags, tag rData fields
func recordMatchesState(rec client.Record, state *RecordResourceModel) bool {
	recordType := state.Type.ValueString()

	// Type must match.
	if rec.Type != recordType {
		return false
	}

	// Primary value must match.
	apiValue := client.RecordValueFromRData(recordType, rec.RData)
	if apiValue != state.Value.ValueString() {
		return false
	}

	// Type-specific field matching.
	switch recordType {
	case "MX":
		if pref, ok := rec.RData["preference"]; ok {
			if int64(toFloat64(pref)) != state.Priority.ValueInt64() {
				return false
			}
		}
	case "SRV":
		if p, ok := rec.RData["priority"]; ok {
			if int64(toFloat64(p)) != state.Priority.ValueInt64() {
				return false
			}
		}
		if w, ok := rec.RData["weight"]; ok {
			if int64(toFloat64(w)) != state.Weight.ValueInt64() {
				return false
			}
		}
		if pt, ok := rec.RData["port"]; ok {
			if int64(toFloat64(pt)) != state.Port.ValueInt64() {
				return false
			}
		}
	case "CAA":
		if f, ok := rec.RData["flags"]; ok {
			if int64(toFloat64(f)) != state.CAAFlags.ValueInt64() {
				return false
			}
		}
		if tag, ok := rec.RData["tag"]; ok {
			if fmt.Sprintf("%v", tag) != state.CAATag.ValueString() {
				return false
			}
		}
	}

	return true
}
