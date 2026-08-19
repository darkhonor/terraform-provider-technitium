---
subcategory: ""
page_title: "technitium_blocked_zones Data Source - terraform-provider-technitium"
description: |-
  Retrieves the full set of domains in the Technitium DNS Server blocked zone
  list. Use this data source to enumerate or count all blocked domains.
---

# technitium\_blocked\_zones (Data Source)

Retrieves the full set of domains in the Technitium DNS Server blocked zone list. Use this data source to enumerate all blocked domains, count them, or cross-reference them against other configuration.

## Example Usage

```terraform
data "technitium_blocked_zones" "all" {}

output "blocked_domain_count" {
  value = length(data.technitium_blocked_zones.all.domains)
}
```

## Argument Reference

This data source has no required or optional arguments. All attributes are computed.

## Attributes Reference

* `id` - Fixed identifier for this data source (`"blocked-zones"`).

* `domains` - Set of all domain names currently present in the blocked zone list.
