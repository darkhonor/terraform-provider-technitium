---
subcategory: ""
page_title: "technitium_allowed_zones Resource - terraform-provider-technitium"
description: |-
  Manages a set of domain entries in the Technitium DNS Server allowed zone list.
---

# technitium\_allowed\_zones (Resource)

Manages a set of domain entries in the Technitium DNS Server allowed zone list.

-> This resource manages a set of domains. Terraform reconciles the declared set with the server — adding missing domains and removing undeclared ones from this resource's management.

## Example Usage

```terraform
resource "technitium_allowed_zones" "corporate" {
  domains = [
    "internal.example.com",
    "vpn.example.com",
    "mail.example.com",
  ]
}
```

## Argument Reference

* `domains` - (Required, Set of String) Set of domain names to allow.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Generated UUID, stable for the lifetime of this resource.
