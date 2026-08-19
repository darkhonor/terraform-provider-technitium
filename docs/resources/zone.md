---
subcategory: ""
page_title: "technitium_zone Resource - terraform-provider-technitium"
description: |-
  Manages a DNS zone on the Technitium DNS Server. Supports Primary, Secondary, Stub,
  and Forwarder zone types with optional DNSSEC signing and TSIG-authenticated zone
  transfers.
---

# technitium\_zone (Resource)

Manages a DNS zone on the Technitium DNS Server. Supports Primary, Secondary, Stub, and Forwarder zone types with optional DNSSEC signing and TSIG-authenticated zone transfers.

~> **DoD / IC environments:** This resource enforces multiple STIG controls when `stig_compliance` is enabled on the provider. Relevant controls include **DNS-REQ-001** (DNSSEC signing), **DNS-REQ-002** (TSIG-authenticated zone transfers), **DNS-REQ-004** (zone transfer ACL), **DNS-REQ-011** (NSEC3 proof of non-existence), **DNS-REQ-012** (FIPS-approved cryptographic algorithms), and **DNS-REQ-016** (notify configuration). See the [STIG Compliance Guide](../guides/stig-compliance.md) for a full walkthrough.

## Example Usage

### Basic Primary Zone

```terraform
resource "technitium_zone" "example" {
  name = "example.com"
  type = "Primary"
}
```

### Secondary Zone with TSIG Authentication

```hcl
resource "technitium_tsig_key" "transfer" {
  key_name  = "transfer.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "secondary" {
  name = "example.com"
  type = "Secondary"

  primary_zone_transfer_tsig_key_name = technitium_tsig_key.transfer.key_name
}
```

### DNSSEC-Enabled Zone

```hcl
resource "technitium_zone" "signed" {
  name = "secure.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
```

### NSS-Compliant Zone

```hcl
resource "technitium_tsig_key" "nss_transfer" {
  key_name  = "nss-transfer.example.mil"
  algorithm = "hmac-sha384"
}

resource "technitium_zone" "nss" {
  name = "example.mil"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }

  zone_transfer_tsig_key_names = [
    technitium_tsig_key.nss_transfer.key_name,
  ]

  notify         = ["10.0.1.2", "10.0.1.3"]
  allow_transfer = ["10.0.1.2", "10.0.1.3"]
}
```

### DNSSEC: EdDSA (Ed448)

```hcl
# EdDSA (Ed448) signing.
#
# Why choose it: Ed448 produces the smallest DNSKEY and RRSIG records of any
# algorithm DNSSEC currently specifies. NIST SP 800-81r3 notes that response
# size drives DNS truncation and TCP fallback, and recommends ECDSA and Ed448
# over RSA for exactly that reason.
#
# STIG standing: BIND-9X-002050 requires a DNSSEC algorithm number of 8
# (RSA/SHA-256) or higher. Ed448 is algorithm 16 and clears that floor.
#
# NOTE: this provider's DNS-REQ-012 validator currently accepts only ECDSA, so
# under strict enforcement this configuration draws a finding even though the
# STIG permits it. The validator is narrower than its own cited source; tracked
# in issue #98. Until that is resolved, either run this zone under `warn`
# enforcement or suppress DNS-REQ-012 explicitly.

resource "technitium_zone" "eddsa" {
  name = "ed.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "EDDSA"
    curve     = "ED448"
    nx_proof  = "NSEC3"
  }
}
```

### DNSSEC: RSA for Legacy Validator Interoperability

```hcl
# RSA signing, for interoperability with validators that predate elliptic-curve
# DNSSEC support.
#
# Why choose it: RSA/SHA-256 is DNSSEC algorithm 8 — the exact floor set by
# BIND-9X-002050 ("if the KSK DNSKEY is less than 8 (SHA256), this is a
# finding"). The Windows Server DNS STIG goes further and calls RSA "the
# recommended algorithm for this guideline". Every deployed validator
# understands it.
#
# Why not to choose it by default: RSA keys and signatures are far larger than
# their elliptic-curve equivalents, which inflates DNS responses and pushes
# queries to TCP. NIST SP 800-81r3 prefers ECDSA and Ed448 for that reason.
# Reach for RSA when you have a specific interoperability requirement.
#
# The `curve` attribute does not apply to RSA and is omitted here.
#
# NOTE: this provider's DNS-REQ-012 validator currently accepts only ECDSA, so
# under strict enforcement this configuration draws a finding even though both
# DNS STIGs permit RSA and one recommends it. Tracked in issue #98.

resource "technitium_zone" "rsa" {
  name = "legacy.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "RSA"
    nx_proof  = "NSEC3"
  }
}
```

### DNSSEC: Changing NSEC / NSEC3 (non-destructive)

```hcl
# Changing the proof-of-non-existence mechanism (NSEC <-> NSEC3).
#
# This is the ONE DNSSEC parameter change that is not destructive. The provider
# converts the zone in place: existing keys are kept, no re-signing ceremony is
# needed, the DS record in the parent is unaffected, and no
# `change_acknowledgment` is required.
#
# To change it, edit `nx_proof` and apply. That is the whole procedure.
#
# Which to use: NSEC3 prevents zone walking, where an attacker enumerates every
# name in a zone by following the NSEC chain. The Windows Server DNS STIG
# requires NSEC3 for all internal zones, and NIST SP 800-81r3 describes zone
# enumeration as "most likely a prelude to an attack". Use NSEC only when you
# have a specific reason and the zone contents are genuinely public.
#
# Applying this file to a zone currently signed with NSEC converts it to NSEC3.

resource "technitium_zone" "nxproof" {
  name = "walkable.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"

    # Changed from "NSEC". Converts in place; keys and DS records survive.
    nx_proof = "NSEC3"
  }
}
```

### DNSSEC: Rotating Algorithm or Curve (destructive)

```hcl
# Rotating the DNSSEC algorithm or curve on a zone that is already signed.
#
# THIS IS DESTRUCTIVE. Technitium cannot re-key a signed zone in place, so the
# provider unsigns the zone and re-signs it with the new parameters. Every key
# is regenerated. The zone is briefly unsigned during the apply, and the DS
# record published in the parent zone STOPS MATCHING the moment the new keys
# exist — resolvers that have cached the old DS will fail validation until you
# publish the new one.
#
# Because of that, the change is refused at plan time unless the zone declares
# an acknowledgment naming exactly the parameters you are moving to. The token
# is compared literally, so it must match the provider's spelling:
#
#     ECDSA/P384      moving to ECDSA with curve P384
#     EDDSA/ED448     moving to EdDSA with curve Ed448
#     RSA             moving to RSA (bare - RSA has no curve)
#
# PROCEDURE
#
#   1. Set the new algorithm/curve AND the matching change_acknowledgment, as
#      below. Apply. The provider unsigns and re-signs.
#   2. Export the new DS records from the server and publish them in the parent
#      zone, replacing the old ones (WDNS-22-000055 / WDNS-22-000056).
#   3. Redistribute trust anchors to any resolver configured with an explicit
#      anchor for this zone.
#   4. REMOVE the change_acknowledgment from your configuration.
#
# Step 4 matters. A token left in place remains standing consent for that same
# transition: if the zone is later re-signed out of band with other parameters,
# the next apply silently converges back destructively under the surviving
# token. Every plan warns while it sits there unused.
#
# The older workaround - set enabled = false, apply, then re-enable with new
# parameters - still works. Under strict enforcement its first step needs
# change_acknowledgment = "unsigned" (see dnssec-unsign.tf).

resource "technitium_zone" "rotating" {
  name = "rotate.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"

    # Changed from "P256". Requires the acknowledgment below.
    curve    = "P384"
    nx_proof = "NSEC3"

    # Authorizes THIS transition only. Remove after step 3 above.
    change_acknowledgment = "ECDSA/P384"
  }
}
```

### DNSSEC: Taking a Zone Insecure (destructive)

```hcl
# Taking a signed zone insecure (removing DNSSEC).
#
# THIS IS DESTRUCTIVE AND ORDER-SENSITIVE. Unsigning destroys the zone's keys.
# If the parent zone still publishes a DS record for this zone when the
# signatures disappear, validating resolvers will treat the zone as BOGUS and
# refuse to resolve it — a self-inflicted outage that persists until the DS
# record expires from caches. RFC 6781 section 4.2.1.2 covers the going-insecure
# procedure; the provider warns about it at plan time in every enforcement mode.
#
# CORRECT ORDER
#
#   1. Remove the DS record for this zone from the PARENT zone.
#   2. Wait out the parent DS record's TTL, so no resolver still has it cached.
#   3. Withdraw any trust anchors distributed for this zone.
#   4. Only then apply the configuration below.
#
# THE TRAP: keep the dnssec block, set enabled = false
#
# The acknowledgment lives INSIDE the dnssec block, so deleting the block
# outright leaves nowhere to carry the consent and the plan is refused under
# strict enforcement. Keep the block with enabled = false and the
# acknowledgment for the unsigning apply, then remove the whole block on a
# later apply once the zone is already unsigned.
#
# "unsigned" is standing consent, not a one-shot token: its target space has a
# single member, so it cannot be scoped per-transition the way an algorithm
# token is. While it sits in configuration with no unsign pending, every plan
# warns that it will authorize a future unsign. Remove it once the unsign has
# converged. That removal warning is the one notice `silent` enforcement
# suppresses.

resource "technitium_zone" "going_insecure" {
  name = "retiring.example.com"
  type = "Primary"

  dnssec {
    # Do not delete this block to unsign. Set enabled = false and keep the
    # acknowledgment; remove the block on a later apply.
    enabled = false

    change_acknowledgment = "unsigned"
  }
}
```

## Argument Reference

* `name` - (Required, String) Domain name for the zone. (Forces replacement.)

* `type` - (Required, String) Zone type. Valid values: `Primary`, `Secondary`, `Stub`, `Forwarder`. (Forces replacement.)

* `soa_serial_date_scheme` - (Optional, Boolean) Use date-based SOA serial numbering. Default: `true`.

* `notify` - (Optional, List of String) IP addresses to notify on zone changes.

* `allow_transfer` - (Optional, List of String) IP addresses allowed to perform zone transfers.

* `zone_transfer_tsig_key_names` - (Optional, List of String) TSIG key names authorized to perform zone transfers. Only valid for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones.

* `primary_zone_transfer_tsig_key_name` - (Optional, String) TSIG key name for authenticating zone transfers from the primary server. Only valid for `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones.

* `dnssec` - (Optional, Block) DNSSEC signing configuration. Only valid for `Primary` zones. See [dnssec](#dnssec) below.

### dnssec

~> **`Primary` zones only.** Technitium signs `Primary` zones and refuses every other type, so a `dnssec` block on a `Secondary`, `Stub`, `Forwarder`, `Catalog`, `SecondaryForwarder`, or `SecondaryCatalog` zone is rejected at plan time. A `Secondary` serves the signed data it receives from its primary by zone transfer rather than signing locally, so sign the zone on the primary instead.

The `dnssec` block supports the following arguments:

* `enabled` - (Optional, Boolean) Enable DNSSEC signing for the zone. Default: `true`.

* `algorithm` - (Optional, String) DNSSEC signing algorithm. Valid values: `ECDSA`, `EDDSA`, `RSA`. Default: `"ECDSA"`.

* `curve` - (Optional, String) Elliptic curve for `ECDSA` (`P256`, `P384`) or `EDDSA` (`ED25519`, `ED448`). Default: `"P256"`.

  -> **NSS environments:** When `nss = true` on the provider, `ECDSA` with `P256` is rejected. Use `P384` to comply with CNSSI 1253.

* `nx_proof` - (Optional, String) Proof of non-existence mechanism. Valid values: `NSEC`, `NSEC3`. Default: `"NSEC3"`. Changing this on a signed zone converts in place — no key regeneration.

* `change_acknowledgment` - (Optional, String) Operator acknowledgment authorizing a destructive DNSSEC transition on this zone. Set to `"<ALGORITHM>/<CURVE>"` (e.g. `"ECDSA/P384"`; bare `"RSA"` for RSA) to authorize an unsign/re-sign to those parameters (the value is compared literally and case-sensitively, exactly as the provider spells it), or `"unsigned"` to authorize unsigning (standing consent — remove after use; a stale value draws a removal warning on every plan except under `silent` enforcement). Required for in-place `algorithm`/`curve` changes in every posture, and for unsigning under `strict` enforcement. See the [STIG Compliance Guide](../guides/stig-compliance.md).

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Zone identifier (same as `name`).

* `soa_serial` - Current SOA serial number.

* `status` - Zone status. Value is `enabled` or `disabled`.

* `dnssec_status` - DNSSEC signing status as reported by the server (e.g., `Unsigned`, `Signed`).

## Import

DNS zones can be imported using the zone name.

```shell
terraform import technitium_zone.example example.com
```
