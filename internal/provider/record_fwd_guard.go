// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// Technitium identifies an FWD record by forwarder and protocol ONLY. Priority,
// dnssecValidation and the proxy settings are values, not identifiers, for
// every record operation that has to find an existing record. Measured against
// live Technitium 15.4 and 15.5.1 with two records sharing forwarder and
// protocol and differing by priority and dnssecValidation:
//
//   - delete, sending the second record's full identity, removed the
//     FIRST-CREATED record instead (whichever it was), reporting "ok";
//   - a TTL-only update of one record merged the two into one, reporting "ok";
//   - 15.4 accepted adding the second record; 15.5 refuses it ("record already
//     exists", upstream commit 119d61f5, which compares a partial FWD record
//     of protocol + forwarder).
//
// In the pair the documentation used to recommend -- a validating forwarder and
// a non-validating fallback to the same upstream -- the record silently lost
// was the validating one. On 15.5+ a Conditional Forwarder zone left with only
// a non-validating FWD record is a Negative Trust Anchor: DNSSEC validation is
// off for the whole namespace.
//
// The API offers no way to address one record of such a pair without the
// other, so the provider refuses to act on one rather than let the server pick.

// fwdProtocol normalizes an FWD protocol the way Technitium does: an unset
// protocol is Udp, and the enum is matched case-insensitively.
func fwdProtocol(p string) string {
	if p == "" {
		return "udp"
	}
	return strings.ToLower(p)
}

// modelFWDKey returns the forwarder and protocol a model identifies, in the
// form Technitium compares them.
func modelFWDKey(m *RecordResourceModel) (forwarder, protocol string) {
	return strings.ToLower(m.Value.ValueString()), fwdProtocol(m.Protocol.ValueString())
}

// countFWDMatches returns how many FWD records in records Technitium would
// consider the same record as forwarder + protocol.
func countFWDMatches(records []client.Record, forwarder, protocol string) int {
	n := 0
	for _, rec := range records {
		if rec.Type != "FWD" {
			continue
		}
		recProto := ""
		if p, ok := rec.RData["protocol"].(string); ok {
			recProto = p
		}
		if strings.ToLower(client.RecordValueFromRData("FWD", rec.RData)) == forwarder &&
			fwdProtocol(recProto) == protocol {
			n++
		}
	}
	return n
}

// fwdMatchCount reads the record set for m's name and counts the FWD records
// matching (forwarder, protocol).
func (r *RecordResource) fwdMatchCount(ctx context.Context, m *RecordResourceModel, forwarder, protocol string) (int, error) {
	records, err := r.client.RecordGet(ctx, m.Name.ValueString(), m.Zone.ValueString())
	if err != nil {
		if isRecordAlreadyGone(err) {
			return 0, nil
		}
		return 0, err
	}
	return countFWDMatches(records, forwarder, protocol), nil
}

// fwdCollisionDetail explains a collision and how to recover from it. It is the
// body of both the refusal errors and the refresh warning.
func fwdCollisionDetail(m *RecordResourceModel, n int) string {
	proto := m.Protocol.ValueString()
	if proto == "" {
		proto = "Udp"
	}
	return fmt.Sprintf(
		"Zone %q has %d FWD records for forwarder %q over %s. Technitium identifies an FWD "+
			"record by forwarder and protocol only -- priority and dnssec_validation do not tell "+
			"records apart -- so a delete or update aimed at one of them acts on whichever was "+
			"created first and reports success. In a validating/non-validating pair that silently "+
			"removes DNSSEC validation. The provider refuses to destroy or update these records "+
			"until each one is unique.\n\n"+
			"To recover, in a maintenance window:\n"+
			"  1. terraform state rm every technitium_record resource for this forwarder and protocol in the zone.\n"+
			"  2. Delete those records on the server (web console or API). Each delete removes one; repeat until none remain.\n"+
			"  3. Change the configuration so no two FWD records in the zone share both value and protocol.\n"+
			"  4. terraform apply to recreate them.\n\n"+
			"See \"DNSSEC validation on forwarders\" in the technitium_record documentation.",
		m.Zone.ValueString(), n, m.Value.ValueString(), proto)
}

// fwdCreateConflictDetail explains why an add was refused.
func fwdCreateConflictDetail(m *RecordResourceModel) string {
	proto := m.Protocol.ValueString()
	if proto == "" {
		proto = "Udp"
	}
	return fmt.Sprintf(
		"Zone %q already has an FWD record for forwarder %q over %s. Technitium identifies an "+
			"FWD record by forwarder and protocol only, so a second one -- even with a different "+
			"forwarder_priority or dnssec_validation -- could not be destroyed or updated without "+
			"acting on the first. Technitium 15.5 and later refuse it outright.\n\n"+
			"Give this forwarder a different value or protocol. If the existing record is the one "+
			"you mean to manage, import it instead of creating it.",
		m.Zone.ValueString(), m.Value.ValueString(), proto)
}

// guardFWDUpdate refuses an FWD update the server cannot apply to exactly one
// record: the record in state shares its forwarder and protocol with another,
// or the plan moves it onto a forwarder and protocol another record already
// uses. It reports false, with an error in diags, when the update must not be
// sent.
func (r *RecordResource) guardFWDUpdate(ctx context.Context, state, plan *RecordResourceModel, diags *diag.Diagnostics) bool {
	records, err := r.client.RecordGet(ctx, state.Name.ValueString(), state.Zone.ValueString())
	if err != nil {
		diags.AddError("Error checking forwarder records before update", err.Error())
		return false
	}

	oldFwd, oldProto := modelFWDKey(state)
	if n := countFWDMatches(records, oldFwd, oldProto); n > 1 {
		diags.AddError("Refusing to update an ambiguous forwarder record", fwdCollisionDetail(state, n))
		return false
	}

	newFwd, newProto := modelFWDKey(plan)
	if newFwd != oldFwd || newProto != oldProto {
		if countFWDMatches(records, newFwd, newProto) > 0 {
			diags.AddError("Forwarder record already exists", fwdCreateConflictDetail(plan))
			return false
		}
	}
	return true
}
