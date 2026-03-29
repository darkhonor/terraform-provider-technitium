---
subcategory: ""
page_title: "technitium_record Resource - Technitium DNS Server"
description: |-
  Manages a DNS record in a Technitium DNS zone. Supports A, AAAA, CNAME, MX, TXT, SRV,
  PTR, NS, and CAA record types. Client-side validation ensures type/value compatibility
  before API calls.
---

# technitium\_record (Resource)

Manages a DNS record in a Technitium DNS zone. Supports A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, and CAA record types. Client-side validation ensures type/value compatibility before API calls.

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

* `type` - (Required, String) Record type. Valid values: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `PTR`, `NS`, `CAA`. (Forces replacement.)

* `value` - (Required, String) Record data.

* `ttl` - (Optional, Integer) TTL in seconds. Default: `3600`.

* `priority` - (Optional, Integer) Priority for MX and SRV records.

* `weight` - (Optional, Integer) Weight for SRV records.

* `port` - (Optional, Integer) Port for SRV records.

* `caa_flags` - (Optional, Integer) CAA flags. `0` = non-critical, `128` = critical.

* `caa_tag` - (Optional, String) CAA tag. Valid values: `issue`, `issuewild`, `iodef`.

* `overwrite` - (Optional, Boolean) Replace existing record set. Default: `true`.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Record identifier (`zone::name::type::value` composite key). For MX records: `zone::name::MX::exchange:priority`. For SRV records: `zone::name::SRV::target:priority:weight:port`. For CAA records: `zone::name::CAA::value:flags:tag`.

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
```
