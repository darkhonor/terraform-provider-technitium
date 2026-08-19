---
subcategory: ""
page_title: "technitium_record Resource - terraform-provider-technitium"
description: |-
  Manages a DNS record in a Technitium DNS zone. Supports A, AAAA, CNAME, MX, TXT, SRV,
  PTR, NS, CAA, and FWD record types. Client-side validation ensures type/value compatibility
  before API calls.
---

# technitium\_record (Resource)

Manages a DNS record in a Technitium DNS zone. Supports A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA, and FWD record types. Client-side validation ensures type/value compatibility before API calls.

-> The `overwrite` attribute controls whether this record replaces existing records of the same type at the same name. Default is `true`.

## Example Usage

### A Record

```terraform
resource "technitium_record" "web" {
  zone  = "example.com"
  name  = "www.example.com"
  type  = "A"
  value = "192.168.1.100"
  ttl   = 3600
}
```

### MX Record

```hcl
resource "technitium_record" "mail" {
  zone     = "example.com"
  name     = "example.com"
  type     = "MX"
  value    = "mail.example.com"
  priority = 10
  ttl      = 3600
}
```

### SRV Record

```hcl
resource "technitium_record" "sip" {
  zone     = "example.com"
  name     = "_sip._tcp.example.com"
  type     = "SRV"
  value    = "sip.example.com"
  priority = 10
  weight   = 60
  port     = 5060
  ttl      = 3600
}
```

### CAA Record

```hcl
resource "technitium_record" "caa" {
  zone      = "example.com"
  name      = "example.com"
  type      = "CAA"
  value     = "letsencrypt.org"
  caa_flags = 0
  caa_tag   = "issue"
  ttl       = 3600
}
```

### Additional Record Types

```hcl
resource "technitium_record" "ipv6" {
  zone  = "example.com"
  name  = "www.example.com"
  type  = "AAAA"
  value = "2001:db8::1"
}

resource "technitium_record" "alias" {
  zone  = "example.com"
  name  = "app.example.com"
  type  = "CNAME"
  value = "www.example.com"
}

resource "technitium_record" "spf" {
  zone  = "example.com"
  name  = "example.com"
  type  = "TXT"
  value = "v=spf1 mx -all"
}

resource "technitium_record" "ns" {
  zone  = "example.com"
  name  = "sub.example.com"
  type  = "NS"
  value = "ns1.example.com"
}

resource "technitium_record" "ptr" {
  zone  = "1.168.192.in-addr.arpa"
  name  = "100.1.168.192.in-addr.arpa"
  type  = "PTR"
  value = "www.example.com"
}
```

### FWD Forwarder Records

Forwarder zones are created empty; each upstream forwarder is then managed as its own
`technitium_record` resource. The simplest case is a single forwarder:

```hcl
# Simplest case: forward everything to one upstream resolver.
#
# A Forwarder zone is created empty, then the forwarder itself is a separate
# FWD record. dnssec_validation is optional and can be left out entirely — with
# a single forwarder there is nothing for it to be confused with.
resource "technitium_zone" "forwarder" {
  name = "."
  type = "Forwarder"
}

resource "technitium_record" "upstream" {
  zone      = technitium_zone.forwarder.name
  name      = "."
  type      = "FWD"
  value     = "1.1.1.1"
  protocol  = "Udp"
  overwrite = false
}
```

A fuller example, with DNSSEC validation over DNS-over-TLS and a plain fallback:

```hcl
# Full example: a primary forwarder with DNSSEC validation over DNS-over-TLS,
# plus a plain fallback.
resource "technitium_zone" "root_forwarder" {
  name = "."
  type = "Forwarder"
}

resource "technitium_record" "quad9_forwarder" {
  zone               = technitium_zone.root_forwarder.name
  name               = "."
  type               = "FWD"
  value              = "dns.quad9.net:853 (9.9.9.9)"
  protocol           = "Tls"
  forwarder_priority = 1
  dnssec_validation  = true
  overwrite          = false
}

# Lower priority is queried first, so this is the fallback. It also differs from
# the record above by value and protocol, which keeps the two independently
# addressable.
#
# When several forwarders share a zone, make sure any two differ by something
# other than dnssec_validation alone — value, protocol or forwarder_priority.
# Records that differ ONLY by dnssec_validation cannot be told apart by the
# Technitium API and one of them can be silently lost. See "DNSSEC validation on
# forwarders" in the resource documentation.
resource "technitium_record" "cloudflare_fallback" {
  zone               = technitium_zone.root_forwarder.name
  name               = "."
  type               = "FWD"
  value              = "1.1.1.1"
  protocol           = "Udp"
  forwarder_priority = 2
  dnssec_validation  = false
  overwrite          = false
}
```

Conditional forwarding — send a single internal namespace to the resolvers authoritative
for it, with a redundant pair of upstreams:

```hcl
# Conditional forwarding: send one internal namespace to the resolvers that are
# authoritative for it, while everything else follows the server's normal path.
#
# The Forwarder zone is named for the domain being forwarded rather than "." —
# only queries under that domain are forwarded.
resource "technitium_zone" "corp_internal" {
  name = "corp.example.net"
  type = "Forwarder"
}

# Two upstreams for redundancy. They differ by value, so they remain
# individually addressable; the priorities set which is tried first.
resource "technitium_record" "corp_dns_primary" {
  zone               = technitium_zone.corp_internal.name
  name               = technitium_zone.corp_internal.name
  type               = "FWD"
  value              = "10.10.0.53"
  protocol           = "Udp"
  forwarder_priority = 1
  overwrite          = false
}

resource "technitium_record" "corp_dns_secondary" {
  zone               = technitium_zone.corp_internal.name
  name               = technitium_zone.corp_internal.name
  type               = "FWD"
  value              = "10.20.0.53"
  protocol           = "Udp"
  forwarder_priority = 2
  overwrite          = false
}

# Internal resolvers usually serve names that do not validate publicly, so
# DNSSEC validation is left off here. Set dnssec_validation = true only for
# upstreams you expect to return signed, publicly-validatable answers.
```

#### DNSSEC validation on forwarders

**If you have a single forwarder, none of this applies** — `dnssec_validation` is optional,
and leaving it out is fine.

~> **With several forwarders on one zone, do not let any two differ only by
`dnssec_validation`.** If two `FWD` records share the same `value`, `protocol` and
`forwarder_priority`, Technitium cannot tell them apart, and you may silently lose one.
Terraform cannot protect you from it.

You do not need to know anything about DNSSEC for this to affect you — it is enough that
two forwarder records look identical apart from that one true/false setting.

**What goes wrong.** The Technitium API identifies a forwarder record by its forwarder
address, protocol and priority. `dnssec_validation` is not part of that lookup, so when two
records match on the first three:

* **Destroying one destroys the wrong one.** The API deletes whichever record was created
  first and reports success. Terraform believes it removed the resource you asked for.
* **Changing one merges the two.** An in-place update rewrites one record onto the other,
  leaving a single record where there were two — again reported as success.

Verified against Technitium DNS Server 15.2 and 15.4.

**What the provider does about it.** Changing `dnssec_validation` is treated as requiring
replacement, so the provider never issues the in-place update that merges records. That
protects the ordinary case of a single forwarder whose setting you want to change. It
cannot rescue a pair that already collides, because the API offers no way to address one
without the other.

**How to stay safe.** Give forwarders that should coexist a distinguishing
`forwarder_priority` (or a different `value` or `protocol`). All three are part of the
record's identity, so records that differ by any of them are addressed correctly. Priority
is usually the natural choice, since it also controls query order — lower is tried first:

```hcl
resource "technitium_record" "validating" {
  zone               = technitium_zone.fwd.name
  name               = technitium_zone.fwd.name
  type               = "FWD"
  value              = "1.1.1.1"
  protocol           = "Udp"
  forwarder_priority = 1
  dnssec_validation  = true
}

resource "technitium_record" "non_validating" {
  zone               = technitium_zone.fwd.name
  name               = technitium_zone.fwd.name
  type               = "FWD"
  value              = "1.1.1.1"
  protocol           = "Udp"
  forwarder_priority = 2 # distinct priority keeps the two records addressable
  dnssec_validation  = false
}
```

If you have already created a colliding pair, remove both records and recreate them with
distinct priorities rather than trying to delete one.

### Multiple Records at Same Name (Round-Robin)

```hcl
resource "technitium_record" "web1" {
  zone      = "example.com"
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.100"
  overwrite = false
}

resource "technitium_record" "web2" {
  zone      = "example.com"
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.101"
  overwrite = false
}
```

-> When creating multiple records at the same name and type, set `overwrite = false` on each resource to prevent them from replacing each other.

## Argument Reference

* `zone` - (Required, String) Parent zone name. (Forces replacement.)

* `name` - (Required, String) FQDN for the record. (Forces replacement.)

* `type` - (Required, String) Record type. Valid values: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `PTR`, `NS`, `CAA`, `FWD`. (Forces replacement.)

* `value` - (Required, String) Record data. For `FWD`, this is the forwarder address using Technitium name-server address syntax, e.g. `1.1.1.1`, `dns.quad9.net:853 (9.9.9.9)`, or a DoH URL.

* `ttl` - (Optional, Integer) TTL in seconds. Default: `3600`.

* `priority` - (Optional, Integer) Priority for MX and SRV records.

* `weight` - (Optional, Integer) Weight for SRV records.

* `port` - (Optional, Integer) Port for SRV records.

* `caa_flags` - (Optional, Integer) CAA flags. `0` = non-critical, `128` = critical.

* `caa_tag` - (Optional, String) CAA tag. Valid values: `issue`, `issuewild`, `iodef`.

* `protocol` - (Optional, String) Protocol for `FWD` records. Valid values: `Udp`, `Tcp`, `Tls`, `Https`, `Quic`.

* `forwarder_priority` - (Optional, Integer) Priority for `FWD` records. Lower values are queried first.

* `dnssec_validation` - (Optional, Boolean) Enable DNSSEC validation for `FWD` records.
  Changing this value forces the record to be **replaced** (destroyed and recreated) rather
  than updated in place. See [DNSSEC validation on forwarders](#dnssec-validation-on-forwarders)
  before defining two forwarders that differ only by this setting.

* `proxy_type`, `proxy_address`, `proxy_port`, `proxy_username`, `proxy_password` - (Optional) Proxy settings for `FWD` records. `proxy_password` is sensitive.

* `overwrite` - (Optional, Boolean) Replace existing record set. Default: `true`.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Record identifier (`zone::name::type::value` composite key). For MX records: `zone::name::MX::exchange:priority`. For SRV records: `zone::name::SRV::target:priority:weight:port`. For CAA records: `zone::name::CAA::value:flags:tag`. For FWD records: `zone::name::FWD::forwarder:protocol:priority:dnssecValidation`. The `dnssecValidation` field distinguishes otherwise-identical forwarders; the legacy 3-field form `forwarder:protocol:priority` is still accepted on import for backward compatibility.

* `last_modified` - Timestamp of last modification.

## Import

DNS records can be imported using the `::` separator with the format `zone::name::type::value`.

```shell
# A record
terraform import technitium_record.web "example.com::www.example.com::A::192.168.1.100"

# MX record (exchange:priority)
terraform import technitium_record.mail "example.com::example.com::MX::mail.example.com:10"

# SRV record (target:priority:weight:port)
terraform import technitium_record.sip "example.com::_sip._tcp.example.com::SRV::sip.example.com:10:60:5060"

# CAA record (value:flags:tag)
terraform import technitium_record.caa "example.com::example.com::CAA::letsencrypt.org:0:issue"

# FWD record (forwarder:protocol:priority:dnssecValidation)
terraform import technitium_record.forwarder ".::.::FWD::1.1.1.1:Udp:2:true"

# FWD record, legacy 3-field form (still accepted; dnssec_validation is left unset)
terraform import technitium_record.forwarder_legacy ".::.::FWD::1.1.1.1:Udp:2"
```
