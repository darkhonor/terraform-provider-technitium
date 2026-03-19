# Client-Side DNS Record Input Validation

**Vikunja Task:** #25
**Red Team Finding:** TPT-VULN-002 (NIST SI-10: Information Input Validation)
**Date:** 2026-03-19

## Problem

Record values are passed directly to the Technitium API without format validation.
Invalid input results in an API round-trip and an uninformative error (HTTP 500 or
similar). Users deserve clear, immediate feedback at plan time.

## Decision Summary

- **New package** `internal/provider/inputvalidation/` — fully decoupled from the STIG engine
- **Registry pattern** — resource-agnostic, extensible to zone and future resources
- **Hard errors only** — invalid input is not configurable; there is no warn/silent mode
- **No TXT length limit** — Technitium handles multi-string splitting internally
- **PTR accepts relative hostnames** — single-label names are valid (e.g., `rancher` in a reverse zone)
- **CAA included** — full coverage of all 9 supported record types
- **Both ConfigValidators coexist** — input validation and STIG run independently per Terraform framework standard behavior

## Architecture

### Package Structure

```
internal/provider/inputvalidation/
  engine.go        -- Registry, ConfigValidator adapter, error formatting
  dns_record.go    -- Record-type validators (A->IPv4, CNAME->FQDN, etc.)
  dns_zone.go      -- Zone attribute validators (future, empty initially)
  helpers.go       -- Shared helpers (isValidIPv4, isValidFQDN, etc.)
  helpers_test.go  -- Unit tests for helper functions
  dns_record_test.go -- Unit tests for record validation rules
```

### Core Types

```go
// TargetResource identifies which resource a rule applies to.
type TargetResource string

const (
    ResourceRecord TargetResource = "technitium_record"
    ResourceZone   TargetResource = "technitium_zone"
)

// ValidationRule defines a single input validation check.
type ValidationRule struct {
    Name        string
    Description string
    Resource    TargetResource
    Validate    func(ctx context.Context, config ConfigAccessor) []Finding
}

// Finding represents one validation failure.
type Finding struct {
    Attribute string
    Summary   string
    Detail    string
}

// ConfigAccessor abstracts Terraform config access (same pattern as STIG engine,
// own interface — no import dependency).
type ConfigAccessor interface {
    GetString(path string) (string, bool)
    GetBool(path string) (bool, bool)
    GetInt64(path string) (int64, bool)
    GetStringList(path string) ([]string, bool)
}
```

### Registry

```go
// Registry holds all validation rules indexed by resource.
type Registry struct {
    rules map[TargetResource][]ValidationRule
}

func NewRegistry() *Registry
func (r *Registry) Register(rule ValidationRule)
func (r *Registry) RulesFor(resource TargetResource) []ValidationRule
```

### ConfigValidator Adapter

```go
// NewResourceValidator returns a resource.ConfigValidator that runs all
// registered rules for the given target resource.
func NewResourceValidator(registry *Registry, target TargetResource) resource.ConfigValidator
```

## Validation Rules

### Record Types

| Record Type | Field(s) | Validation | Rejects |
|---|---|---|---|
| A | `value` | `isValidIPv4()` | IPv6, FQDN, CIDR, empty |
| AAAA | `value` | `isValidIPv6()` | IPv4, FQDN, empty |
| CNAME | `value` | `isValidFQDN()` | IP addresses, empty |
| MX | `value` | `isValidFQDN()` | IP addresses, empty |
| MX | `priority` | `isInRange(0, 65535)` | Out of range |
| NS | `value` | `isValidFQDN()` | IP addresses, empty |
| PTR | `value` | `isValidHostname()` | IP addresses, empty |
| SRV | `value` | `isValidFQDN()` | IP addresses, empty |
| SRV | `priority`, `weight`, `port` | `isInRange(0, 65535)` each | Out of range |
| TXT | `value` | Non-empty only | Empty string |
| CAA | `caa_flags` | Must be 0 or 128 | Any other value |
| CAA | `caa_tag` | Must be `issue`, `issuewild`, `iodef` | Any other value |
| CAA | `value` | Non-empty | Empty string |

### Shared Helpers

| Function | Description |
|---|---|
| `isValidIPv4(s string) bool` | `net.ParseIP` + `.To4() != nil` |
| `isValidIPv6(s string) bool` | `net.ParseIP` + NOT v4-mapped |
| `isValidFQDN(s string) bool` | RFC 1123 labels, requires at least one dot |
| `isValidHostname(s string) bool` | RFC 1123 labels, allows single-label names |
| `isIPAddress(s string) bool` | Rejects IPs in FQDN/hostname fields |
| `isInRange(val, min, max int64) bool` | Numeric range check |

### PTR Design Rationale

The HashiCorp DNS provider expects FQDNs for PTR values because it speaks RFC 2136
(wire-format dynamic DNS updates). Technitium's HTTP API accepts relative hostnames
within the zone context. A PTR record of `154` pointing to `rancher` in reverse zone
`11.110.10.in-addr.arpa` is valid usage. We validate hostname format, not qualification.

### TXT Design Rationale

RFC 1035 limits individual character-strings to 255 bytes, but Technitium handles
multi-string splitting internally. DKIM keys routinely exceed 255 characters. Enforcing
a length limit would produce false positives on legitimate records. We validate non-empty
only.

## Wiring

The record resource's `ConfigValidators()` adds the input validator unconditionally,
alongside the optional STIG validator:

```go
func (r *RecordResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
    validators := []resource.ConfigValidator{
        inputvalidation.NewResourceValidator(r.inputRegistry, inputvalidation.ResourceRecord),
    }
    if r.providerData != nil && r.providerData.STIGEngine != nil {
        validators = append(validators,
            newSTIGConfigValidator(r.providerData.STIGEngine, stigvalidators.ResourceRecord))
    }
    return validators
}
```

- Input validation runs unconditionally (no feature flag)
- Input validation is first in the slice (format errors before compliance findings)
- Both validators fire independently per Terraform Plugin Framework behavior
- No short-circuiting — standard practice, revisit only if it becomes a real problem

## Error Messages

Consistent format across all rules:

```
Invalid <TYPE> record <FIELD>: "<actual_value>" is not a valid <expected_format>.
<TYPE> records require <description> (e.g., "<example>").
```

Examples:
```
Invalid A record value: "2001:db8::1" is an IPv6 address.
A records require a valid IPv4 address (e.g., "192.0.2.1").

Invalid MX record value: "10.0.0.1" is an IP address.
MX records require a valid FQDN (e.g., "mail.example.com.").

Invalid CAA record caa_tag: "invalid" is not a recognized CAA tag.
CAA records require one of: "issue", "issuewild", "iodef".
```

## Testing Strategy

1. **Helper unit tests** (`helpers_test.go`): Table-driven tests for each helper function
   with valid and invalid inputs, edge cases (empty, whitespace, CIDR, v4-mapped v6, etc.)
2. **Rule unit tests** (`dns_record_test.go`): Table-driven tests per record type using
   mock ConfigAccessor. Verify correct Findings returned for valid/invalid inputs.
3. **Integration test**: Acceptance test confirming ConfigValidator fires during
   `terraform validate` with an invalid record config — verifies end-to-end wiring.

## Future Extension Points

- **Zone validators** (`dns_zone.go`): Zone attribute validation (zone name format,
  transfer network CIDRs, etc.)
- **Auto-PTR creation** (Vikunja #27): Optional boolean on A/AAAA records to
  auto-create associated PTR records
- **Additional record types**: As the provider adds support for more record types,
  validators slot into `dns_record.go` with a new rule registration
