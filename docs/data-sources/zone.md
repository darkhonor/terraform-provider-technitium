---
subcategory: ""
page_title: "technitium_zone Data Source - terraform-provider-technitium"
description: |-
  Reads a DNS zone from the Technitium DNS Server. Use this data source to
  reference zone properties such as DNSSEC status, SOA serial, and zone
  transfer policy in other resources or outputs.
---

# technitium\_zone (Data Source)

Reads a DNS zone from the Technitium DNS Server. Use this data source to reference zone properties such as DNSSEC status, SOA serial, and zone transfer policy in other resources or outputs.

## Example Usage

```terraform
data "technitium_zone" "example" {
  name = "example.com"
}

output "zone_dnssec_status" {
  value = data.technitium_zone.example.dnssec_status
}
```

## Argument Reference

* `name` - (Required, String) The domain name of the zone to look up.

## Attributes Reference

* `id` - Zone identifier (same as `name`).

* `type` - Zone type (e.g., `Primary`, `Secondary`, `Stub`, `Forwarder`).

* `disabled` - Whether the zone is disabled.

* `dnssec_status` - DNSSEC signing status as reported by the server (e.g., `Unsigned`, `Signed`).

* `soa_serial` - Current SOA serial number.

* `zone_transfer` - Zone transfer policy.

* `zone_transfer_acl` - List of network addresses in the zone transfer ACL.

* `notify` - Zone notify policy.

* `notify_name_servers` - List of name server IP addresses that receive notify messages.

* `primary_name_server_addresses` - List of primary name server addresses of a `Secondary`, `SecondaryForwarder`, `SecondaryCatalog`, or `Stub` zone, as normalised by the server (for example `10.0.0.1:853` under `Tls`). Null for other zone types.

* `zone_transfer_protocol` - Protocol (`Tcp`, `Tls`, `Quic`) used to transfer the zone from its primary. Null for zone types that do not transfer.
