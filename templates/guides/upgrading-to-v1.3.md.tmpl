---
subcategory: ""
page_title: "Upgrading to v1.3 - Technitium DNS Server Provider"
description: |-
  Required actions when moving to provider v1.3 and to Technitium DNS Server 15.5 or later.
---

# Upgrading to v1.3

Provider v1.3 changes three behaviors that can stop an existing configuration from applying,
and it is the first release tested against **Technitium DNS Server 15.5**. Read this guide
before upgrading either the provider or the server.

## At a glance

| If you... | You must... |
|---|---|
| Run Technitium **older than 15.0** | Set `legacy_token_auth = true` before upgrading the provider, or upgrade the server first. |
| Have two `FWD` records in one zone with the same `value` **and** `protocol` | Rebuild them so each pair differs by `value` or `protocol`. The provider refuses to destroy or update either record until you do. |
| Reach the server through a reverse proxy, WAF, or a `server_url` that redirects | Allow `POST` with form bodies on `/api/*`, and set `server_url` to the final scheme and host. A `server_url` that only works by following an `http://` to `https://` redirect, including Technitium's own, now fails at provider configuration. |
| Plan to upgrade Technitium to **15.5 or later** | Review forwarder zones whose forwarders have `dnssec_validation = false`, and the comments on those records. |

Everyone else can upgrade without configuration changes.

## Supported server versions

| Technitium DNS Server | Status |
|---|---|
| **15.5.1 or later** | **Recommended.** The acceptance suite runs against 15.5.1. |
| 15.0 – 15.4 | Supported. Forwarder behavior in this guide was also verified on 15.4. |
| Older than 15.0 | Requires `legacy_token_auth = true`. Not covered by the acceptance suite. |

Technitium 15.5 and 15.5.1 fix several security issues in the server itself, including a
DNSSEC validation bypass, two cache-poisoning vulnerabilities, a packet-amplification vector,
an authorization bypass in the record API, and (15.5.1) a session-token disclosure. See the
[Technitium change log](https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md).
Upgrading the server is recommended independently of this provider.

## Change 1: the API token is sent as a header

The provider now sends the API token in an `Authorization: Bearer` header instead of a `token`
query parameter, so the token no longer appears in request URLs or in the access logs of any
reverse proxy in front of the server
([GHSA-27mx-6hfq-f887](https://github.com/darkhonor/terraform-provider-technitium/security/advisories/GHSA-27mx-6hfq-f887)).

Technitium accepts the header from **15.0** onward. An older server ignores it, and every
request fails as `invalid-token`. The provider's connection error then suggests the fix:

```hcl
provider "technitium" {
  server_url        = "https://dns.example.com"
  api_token         = var.technitium_api_token
  legacy_token_auth = true # or TECHNITIUM_LEGACY_TOKEN_AUTH=true
}
```

~> With `legacy_token_auth`, every request, reads included, is sent as a `POST` with the token
in the form body, so the token never appears in a URL. A proxy in front of a legacy server
must allow `POST` on `/api/*`. Treat the setting as a bridge while you upgrade the server, not
a permanent setting.

## Change 2: forwarder records that cannot be told apart are refused

Technitium identifies an `FWD` record by its forwarder address and protocol **only**.
`forwarder_priority` and `dnssec_validation` do not distinguish two records. Earlier versions
of this provider's documentation said otherwise and recommended separating a validating and a
non-validating forwarder to the same upstream by priority. That pattern was never safe: when
two records share an address and protocol, deleting one deletes whichever was created first,
and updating one merges the two, both reported as success. In the recommended pair, the record
silently lost was usually the DNSSEC-validating one.

Provider v1.3:

* refuses to **create** such a pair (`overwrite = false`) on every server version;
* refuses to **destroy or update** either record of an existing pair, before sending anything;
* shows a **warning on every plan** for each managed record that belongs to such a pair.

If the first plan after upgrading shows **"Forwarder records cannot be told apart"**, rebuild
the pair. The steps, and the safe alternative (give the two forwarders different protocols),
are in [DNSSEC validation on forwarders](../resources/record.md#dnssec-validation-on-forwarders).

This change does not affect forwarders that already differ by `value` or `protocol`.

## Change 3: writes are sent as form POSTs

Every API call that changes the server (records, zones, DNSSEC, blocked and allowed zones,
users, API tokens, sessions, cluster) now sends its parameters as a form-encoded `POST` body
instead of a `GET` query string, so record values, comments, and FWD proxy credentials no
longer appear in request URLs. Reads are unchanged, except with `legacy_token_auth`, where
they are `POST` too.

* A reverse proxy or WAF in front of the server must allow `POST` on `/api/*`.
* Point `server_url` at the final scheme and host. The provider follows a redirect only when
  the scheme and host stay the same (for example, a port or path change). It refuses any other
  redirect, including Technitium's own HTTP-to-HTTPS redirect, with an error naming both URLs,
  so the token and TLS settings never go somewhere `server_url` did not name. A 301, 302, or
  303 on a write fails regardless, because the request is re-sent as a `GET` without its body;
  with `legacy_token_auth` that applies to reads too.

## Upgrading Technitium to 15.5 or later

Two server changes in 15.5 interact with Terraform-managed forwarders. Both were verified
against 15.5.1.

**Duplicate forwarder records are refused by the server.** Technitium 15.5 rejects a second
`FWD` record with the same address and protocol (`Cannot add record: record already exists.`).
Pairs created on an older server survive the upgrade, but can no longer be recreated, and
they still cannot be destroyed or updated one at a time. Rebuild them, ideally before
upgrading the server.

**Non-validating forwarder zones become Negative Trust Anchors.** Technitium 15.5 implements
[draft-farrokhi-dnsop-ede-nta](https://datatracker.ietf.org/doc/html/draft-farrokhi-dnsop-ede-nta).
A Conditional Forwarder zone whose forwarder record has DNSSEC validation disabled answers
with an Extended DNS Error, `NegativeTrustAnchor`: DNSSEC validation is off for that whole
namespace, and the server says so to every client. Two consequences:

* Review every forwarder with `dnssec_validation = false`. On 15.5 it is an explicit trust
  anchor exemption, not just a per-forwarder preference.
* **The record's comment is returned to clients** as the EDE text. Anyone who can query the
  zone can read it. Keep anything that should not be public out of those comments.

## Recommended order

1. **Server older than 15.0?** Add `legacy_token_auth = true` to the provider block.
2. **Upgrade the provider** to `~> 1.3` and run `terraform init -upgrade`.
3. **Run `terraform plan`.** Resolve any "Forwarder records cannot be told apart" warning by
   rebuilding the pair, then apply.
4. **Upgrade Technitium** to 15.5.1 or later. Review non-validating forwarders and their
   comments as described above.
5. **Remove `legacy_token_auth`** if you set it, and run `terraform plan`. It should report no
   changes.

See the [CHANGELOG](https://github.com/darkhonor/terraform-provider-technitium/blob/main/CHANGELOG.md)
for the complete list of changes in v1.3.
