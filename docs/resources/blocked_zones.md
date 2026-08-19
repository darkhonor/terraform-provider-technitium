---
subcategory: ""
page_title: "technitium_blocked_zones Resource - terraform-provider-technitium"
description: |-
  Manages a set of domain entries in the Technitium DNS Server blocked zone list.
---

# technitium\_blocked\_zones (Resource)

Manages a set of domain entries in the Technitium DNS Server blocked zone list.

-> This resource manages a set of domains. Terraform reconciles the declared set with the server — adding missing domains and removing undeclared ones from this resource's management.

## Example Usage

```terraform
resource "technitium_blocked_zones" "malware" {
  domains = [
    "malware.example.com",
    "phishing.example.com",
    "tracking.example.com",
  ]
}
```

## Argument Reference

* `domains` - (Required, Set of String) Set of domain names to block.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Generated UUID, stable for the lifetime of this resource.
