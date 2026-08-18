---
page_title: "Technitium DNS Server Provider"
subcategory: ""
description: |-
  The Technitium DNS Server Terraform provider manages zones, records, server settings,
  TSIG keys, and access-control lists on a Technitium DNS Server instance. It includes
  optional STIG compliance enforcement for DoD and IC environments.
---

# Technitium DNS Server Provider

[Technitium DNS Server](https://technitium.com/dns/) is an open-source, cross-platform
DNS server designed for self-hosted deployments. It supports authoritative DNS, recursive
resolution, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), TSIG-signed zone transfers, and a
rich REST API that this provider uses to manage all configuration.

This provider allows you to manage Technitium DNS Server infrastructure as code using
Terraform. It covers zones, DNS records, server settings, TSIG keys, and blocked/allowed
zone lists — enabling repeatable, version-controlled DNS configuration for both
general-purpose and security-sensitive environments.

The provider is published at
[registry.terraform.io/darkhonor/technitium](https://registry.terraform.io/providers/darkhonor/technitium).
Source code and issue tracking are available on GitHub.

## Feature Highlights

* Manage authoritative DNS zones (`technitium_zone`)
* Create and update DNS records of all common types (`technitium_record`)
* Configure global server settings (`technitium_server_settings`)
* Manage TSIG keys for secure zone transfers (`technitium_tsig_key`)
* Maintain blocked and allowed zone lists (`technitium_blocked_zone`, `technitium_allowed_zone`, and collection variants)
* Vault-style TLS configuration: custom CA bundles, SNI override, and minimum TLS version enforcement
* Optional STIG compliance mode with per-resource validation and CNSSI 1253 security categorization

## STIG Compliance

~> **DoD / IC environments:** This provider includes built-in STIG compliance validation aligned
to [DoD STIG guidance](https://www.cyber.mil/stigs) for DNS infrastructure. Enable the
`stig_compliance` block to enforce DNS-REQ controls across all managed resources. See the
[STIG Compliance Guide](guides/stig-compliance.md) for a full walkthrough, including
National Security System (NSS) configuration and CNSSI 1253 categorization.

## Example Usage

```terraform
terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

provider "technitium" {
  server_url = var.technitium_server_url
  api_token  = var.technitium_api_token
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL"
  type        = string
  default     = "http://127.0.0.1:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}
```

## Connection and Authentication

The provider connects to a running Technitium DNS Server instance via its REST API. You must
supply the server URL and an API token. Both values can be provided via HCL attributes or
environment variables (environment variables take effect when the HCL attribute is omitted or
empty).

**Server URL** — set `server_url` in the provider block or export `TECHNITIUM_SERVER_URL`.
Use an HTTPS URL in production; HTTP is accepted for local development only.

**API Token** — set `api_token` in the provider block or export `TECHNITIUM_API_TOKEN`.
Tokens are created in the Technitium web console under *Administration → API Tokens*. Treat
tokens as credentials: use a sensitive Terraform variable or a secrets manager rather than
storing plaintext values in configuration files.

## TLS Configuration

The provider follows the same TLS configuration model as the
[HashiCorp Vault provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs):
each attribute accepts an HCL value with a corresponding environment-variable fallback.

| Attribute | Environment Variable | Purpose |
|---|---|---|
| `ca_cert_file` | `TECHNITIUM_CACERT` | Path to a PEM-encoded CA certificate file |
| `ca_cert_dir` | `TECHNITIUM_CAPATH` | Path to a directory of PEM-encoded CA certificate files |
| `tls_server_name` | `TECHNITIUM_TLS_SERVER_NAME` | SNI hostname override |
| `tls_min_version` | `TECHNITIUM_TLS_MIN_VERSION` | Minimum TLS version (`"1.2"` or `"1.3"`; default `"1.3"`) |
| `skip_tls_verify` | `TECHNITIUM_SKIP_TLS_VERIFY` | Disable TLS certificate verification (not recommended) |

When `stig_compliance.enabled = true`, the provider emits STIG warnings (or errors, depending
on `enforcement`) if `skip_tls_verify = true` or `tls_min_version = "1.2"` is configured.
NSS environments (`nss = true`) treat these conditions as hard errors regardless of
`enforcement`.

## STIG Compliance Configuration

The `stig_compliance` block activates the provider's built-in DNS STIG validation engine.
When enabled, every resource plan and apply is checked against applicable DNS-REQ controls.
Findings are reported as Terraform diagnostics — errors in `strict` mode (default), warnings
in `warn` mode, and suppressed in `silent` mode. (Action-consequence notices for destructive
DNSSEC changes are resource-emitted, sit outside the STIG finding pipeline, and still warn
under `silent` — see the STIG compliance guide.)

```hcl
provider "technitium" {
  server_url = var.technitium_server_url
  api_token  = var.technitium_api_token

  stig_compliance {
    enabled     = true
    nss         = false
    enforcement = "strict"
    suppress    = []

    categorization {
      baseline = "moderate"
    }
  }
}
```

For NSS environments, replace `baseline` with explicit per-objective levels:

```hcl
    categorization {
      confidentiality = "high"
      integrity       = "high"
      availability    = "moderate"
    }
```

**Enforcement modes:**

* `strict` (default) — STIG findings block `terraform apply`. Use in production and CI/CD pipelines.
* `warn` — Findings are reported as warnings but do not block apply. Useful during migration.
* `silent` — All STIG findings are suppressed (the destructive-DNSSEC-change notices still warn — they are action-consequence notices, not findings). Not recommended except for testing.

**Suppression:** Individual DNS-REQ controls can be suppressed by ID via the `suppress` list.
Suppressed controls emit warnings instead of errors, creating an auditable record without
blocking apply. Valid IDs follow the pattern `DNS-REQ-001` through `DNS-REQ-NNN`.

-> **Tip:** Run `terraform plan` with `enforcement = "warn"` to audit your existing configuration
before switching to `strict`. The plan output will identify all controls that need remediation.

## Argument Reference

### Connection

* `server_url` - (Required, String) Base URL of the Technitium DNS Server API
  (e.g., `https://dns.example.com:5380`). May be set via `TECHNITIUM_SERVER_URL`.

* `api_token` - (Required, String, Sensitive) API token used to authenticate with the
  Technitium REST API. May be set via `TECHNITIUM_API_TOKEN`.

### TLS

* `skip_tls_verify` - (Optional, Boolean) If `true`, TLS certificate verification is
  disabled. Generates a STIG diagnostic when `stig_compliance.enabled = true` (SC-8).
  May be set via `TECHNITIUM_SKIP_TLS_VERIFY`. Default: `false`.

* `ca_cert_file` - (Optional, String) Path to a PEM-encoded CA certificate file used to
  validate the server's TLS certificate. May be set via `TECHNITIUM_CACERT`.

* `ca_cert_dir` - (Optional, String) Path to a directory of PEM-encoded CA certificate
  files. Files that cannot be parsed are skipped. May be set via `TECHNITIUM_CAPATH`.

* `tls_server_name` - (Optional, String) SNI hostname to use when connecting to the server
  via TLS. Useful when the server certificate CN/SAN differs from the hostname in
  `server_url`. May be set via `TECHNITIUM_TLS_SERVER_NAME`.

* `tls_min_version` - (Optional, String) Minimum TLS protocol version accepted when
  connecting to the server. May be set via `TECHNITIUM_TLS_MIN_VERSION`.
  Default: `"1.3"`. Valid values are `"1.2"`, `"1.3"`.

### STIG Compliance

The `stig_compliance` block is optional. When omitted, no STIG validation is performed.

* `stig_compliance` - (Optional, Block) STIG compliance configuration.

  * `enabled` - (Optional, Boolean) Enable STIG validation on all resources. Default: `false`.

  * `nss` - (Optional, Boolean) National Security System mode. When `true`, full CNSSI 1253
    per-objective categorization is required (`confidentiality`, `integrity`, and
    `availability` must all be set), and conditions that are warnings in non-NSS mode become
    errors. Default: `false`.

  * `enforcement` - (Optional, String) STIG enforcement policy. Controls whether findings
    block apply or are reported as warnings. Default: `"strict"`.
    Valid values are `"strict"`, `"warn"`, `"silent"`. Under `"strict"`, destructive DNSSEC
    transitions (unsigning, key-regenerating re-signs) additionally require a per-zone
    `change_acknowledgment`; under `"silent"`, their notices still warn.

  * `suppress` - (Optional, List of String) List of DNS-REQ requirement IDs to suppress.
    Suppressed findings are downgraded to warnings instead of errors, creating an auditable
    record in plan output without blocking apply. Example: `["DNS-REQ-005", "DNS-REQ-012"]`.

  * `categorization` - (Optional, Block) Security categorization for STIG validation,
    aligned to [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800-53/r5/upd1/final)
    and [CNSSI 1253](https://www.cnss.gov/CNSS/issuances/Instructions.cfm).
    Required when `enabled = true`.

    * `baseline` - (Optional, String) Shorthand baseline level applied equally to
      confidentiality, integrity, and availability. Mutually exclusive with the individual
      objective attributes. Not permitted when `nss = true`.
      Valid values are `"low"`, `"moderate"`, `"high"`.

    * `confidentiality` - (Optional, String) Confidentiality objective level. Required when
      `nss = true`. Mutually exclusive with `baseline`.
      Valid values are `"low"`, `"moderate"`, `"high"`.

    * `integrity` - (Optional, String) Integrity objective level. Required when `nss = true`.
      Mutually exclusive with `baseline`.
      Valid values are `"low"`, `"moderate"`, `"high"`.

    * `availability` - (Optional, String) Availability objective level. Required when
      `nss = true`. Mutually exclusive with `baseline`.
      Valid values are `"low"`, `"moderate"`, `"high"`.

## Environment Variables

| Environment Variable | HCL Attribute |
|---|---|
| `TECHNITIUM_SERVER_URL` | `server_url` |
| `TECHNITIUM_API_TOKEN` | `api_token` |
| `TECHNITIUM_SKIP_TLS_VERIFY` | `skip_tls_verify` |
| `TECHNITIUM_CACERT` | `ca_cert_file` |
| `TECHNITIUM_CAPATH` | `ca_cert_dir` |
| `TECHNITIUM_TLS_SERVER_NAME` | `tls_server_name` |
| `TECHNITIUM_TLS_MIN_VERSION` | `tls_min_version` |
