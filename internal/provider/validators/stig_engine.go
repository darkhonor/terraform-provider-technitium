// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// Categorization holds resolved C/I/A levels.
// Separate from provider.Categorization to avoid circular import.
type Categorization struct {
	Confidentiality string // "low", "moderate", "high"
	Integrity       string
	Availability    string
}

// EngineConfig holds operator compliance settings from the provider block.
type EngineConfig struct {
	Enabled        bool
	Enforcement    string   // "strict", "warn", "silent"
	Suppressions   []string // DNS-REQ-XXX IDs
	Categorization Categorization
	NSS            bool
}

// Engine is the stateless compliance evaluation engine.
type Engine struct {
	config       EngineConfig
	requirements map[string]DNSSecurityRequirement // indexed by ID
	baselines    map[string]string                  // control -> lowest baseline
	bindings     map[TargetResource][]ValidatorBinding
}

// NewEngine constructs an engine from config, indexing all requirements.
func NewEngine(config EngineConfig) *Engine {
	reqs := make(map[string]DNSSecurityRequirement, len(DNSSecurityRequirements))
	for _, req := range DNSSecurityRequirements {
		reqs[req.ID] = req
	}
	return &Engine{
		config:       config,
		requirements: reqs,
		baselines:    BaselineMembership,
		bindings:     make(map[TargetResource][]ValidatorBinding),
	}
}

// RegisterBindings adds validator bindings for a resource type.
func (e *Engine) RegisterBindings(resource TargetResource, bindings []ValidatorBinding) {
	e.bindings[resource] = bindings
}

// baselineOrdinal converts a baseline level string to an ordinal for comparison.
func (e *Engine) baselineOrdinal(level string) int {
	switch strings.ToLower(level) {
	case "low":
		return 1
	case "moderate":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}

// effectiveBaseline returns the highest of the three C/I/A categorization levels.
func (e *Engine) effectiveBaseline() string {
	levels := []string{
		e.config.Categorization.Confidentiality,
		e.config.Categorization.Integrity,
		e.config.Categorization.Availability,
	}

	maxOrd := 0
	maxLevel := "low"
	for _, l := range levels {
		ord := e.baselineOrdinal(l)
		if ord > maxOrd {
			maxOrd = ord
			maxLevel = strings.ToLower(l)
		}
	}
	return maxLevel
}

// controlInScope returns true if ANY of the given control IDs have a baseline
// level less than or equal to the effective baseline.
func (e *Engine) controlInScope(controlIDs []string) bool {
	effectiveOrd := e.baselineOrdinal(e.effectiveBaseline())
	for _, ctrl := range controlIDs {
		baselineLevel, ok := e.baselines[ctrl]
		if !ok {
			// Unknown control — treat as in scope (conservative).
			return true
		}
		controlOrd := e.baselineOrdinal(baselineLevel)
		if controlOrd <= effectiveOrd {
			return true
		}
	}
	return false
}

// isSuppressed checks if a requirement ID is in the suppressions list.
func (e *Engine) isSuppressed(reqID string) bool {
	for _, s := range e.config.Suppressions {
		if s == reqID {
			return true
		}
	}
	return false
}

// emitFinding formats and emits a diagnostic based on enforcement policy.
func (e *Engine) emitFinding(req DNSSecurityRequirement, diags *diag.Diagnostics) {
	if e.isSuppressed(req.ID) {
		// Suppressed findings always emit a warning, even in strict mode.
		summary := fmt.Sprintf("%s [%s] \u2014 %s (SUPPRESSED)",
			req.ID, strings.ToUpper(req.Severity), req.Title)

		var provenanceStrs []string
		for _, p := range req.Provenance {
			provenanceStrs = append(provenanceStrs, p.RuleID)
		}

		detail := fmt.Sprintf(
			"This finding is suppressed per operator configuration.\n"+
				"Ensure compensating controls are documented in the POA&M.\n\n"+
				"Controls: %s\n"+
				"Provenance: %s",
			strings.Join(req.Controls, ", "),
			strings.Join(provenanceStrs, ", "),
		)
		diags.AddWarning(summary, detail)
		return
	}

	// Unsuppressed finding — emit based on enforcement policy.
	summary := fmt.Sprintf("%s [%s] \u2014 %s",
		req.ID, strings.ToUpper(req.Severity), req.Title)

	var provenanceStrs []string
	for _, p := range req.Provenance {
		provenanceStrs = append(provenanceStrs, p.RuleID)
	}

	// Determine baseline label for display.
	baselineLabel := e.controlBaselineLabel(req.Controls)

	detail := fmt.Sprintf(
		"Controls: %s | Baseline: %s\n"+
			"Provenance: %s\n\n"+
			"Suppress with: suppress = [\"%s\"]",
		strings.Join(req.Controls, ", "),
		baselineLabel,
		strings.Join(provenanceStrs, ", "),
		req.ID,
	)

	switch e.config.Enforcement {
	case "strict":
		diags.AddError(summary, detail)
	case "warn":
		diags.AddWarning(summary, detail)
	case "silent":
		// No-op.
	}
}

// controlBaselineLabel returns a human-readable label for the lowest baseline
// among a requirement's controls.
func (e *Engine) controlBaselineLabel(controls []string) string {
	minOrd := 4
	minLevel := ""
	for _, ctrl := range controls {
		bl, ok := e.baselines[ctrl]
		if !ok {
			continue
		}
		ord := e.baselineOrdinal(bl)
		if ord < minOrd {
			minOrd = ord
			minLevel = strings.ToUpper(bl)
		}
	}
	if minLevel == "" {
		return "UNKNOWN"
	}
	if minOrd == 1 {
		return minLevel + " (always required)"
	}
	return minLevel
}

// ValidateConfig iterates bindings for the given resource, evaluates stateless
// validators, and emits findings based on enforcement policy.
func (e *Engine) ValidateConfig(ctx context.Context, resource TargetResource, config ConfigAccessor, diags *diag.Diagnostics) {
	if !e.config.Enabled {
		return
	}

	bindings, ok := e.bindings[resource]
	if !ok {
		return
	}

	for _, binding := range bindings {
		if !binding.Implemented {
			continue
		}
		if binding.StatelessFn == nil {
			continue
		}

		req, ok := e.requirements[binding.RequirementID]
		if !ok {
			continue
		}

		if !e.controlInScope(req.Controls) {
			continue
		}

		compliant := binding.StatelessFn(ctx, config)
		if !compliant {
			e.emitFinding(req, diags)
		}
	}
}

// ValidateProvider evaluates provider-level validators during Configure().
// Delegates to ValidateConfig with TargetProvider — same enforcement,
// suppression, and diagnostic logic as resource validators.
func (e *Engine) ValidateProvider(ctx context.Context, config ConfigAccessor, diags *diag.Diagnostics) {
	e.ValidateConfig(ctx, TargetProvider, config, diags)
}

// ValidatePlan iterates bindings for the given resource, evaluates stateful
// validators, and emits findings based on enforcement policy.
func (e *Engine) ValidatePlan(ctx context.Context, resource TargetResource, plan PlanAccessor, state StateAccessor, diags *diag.Diagnostics) {
	if !e.config.Enabled {
		return
	}

	bindings, ok := e.bindings[resource]
	if !ok {
		return
	}

	for _, binding := range bindings {
		if !binding.Implemented {
			continue
		}
		if binding.StatefulFn == nil {
			continue
		}

		req, ok := e.requirements[binding.RequirementID]
		if !ok {
			continue
		}

		if !e.controlInScope(req.Controls) {
			continue
		}

		compliant := binding.StatefulFn(ctx, plan, state)
		if !compliant {
			e.emitFinding(req, diags)
		}
	}
}
