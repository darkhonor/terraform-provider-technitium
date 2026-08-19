---
subcategory: ""
page_title: "technitium_server_settings Resource - terraform-provider-technitium"
description: |-
  Manages Technitium DNS Server global settings.
---

# technitium\_server\_settings (Resource)

Manages Technitium DNS Server global settings.

~> **Singleton resource:** Only one instance of this resource may exist per provider configuration. The resource ID is always `"server-settings"`. Attempting to declare a second instance will produce a conflict in state.

~> **DoD / IC environments:** This resource enforces multiple STIG controls when `stig_compliance` is enabled on the provider. Relevant controls include **DNS-REQ-004** through **DNS-REQ-016** and **DNS-REQ-028**. See the [STIG Compliance Guide](../guides/stig-compliance.md) for a full walkthrough.

## Example Usage

### Basic Configuration

```terraform
resource "technitium_server_settings" "main" {
  dnssec_validation = true
  recursion         = "AllowOnlyForPrivateNetworks"
  log_queries       = true
}
```

### STIG-Hardened

```hcl
resource "technitium_server_settings" "stig" {
  # DNS Resolution (DNS-REQ-005, DNS-REQ-006, DNS-REQ-014, DNS-REQ-015)
  dnssec_validation  = true
  recursion          = "AllowOnlyForPrivateNetworks"
  qname_minimization = true
  randomize_name     = true

  # Logging (DNS-REQ-007, DNS-REQ-008, DNS-REQ-009, DNS-REQ-010)
  log_queries       = true
  logging_type      = "FileAndConsole"
  max_log_file_days = 365

  # Forwarding (DNS-REQ-013, DNS-REQ-028)
  forwarders         = ["9.9.9.9", "149.112.112.112"]
  forwarder_protocol = "Tls"

  # Encrypted transport (SC-8)
  enable_dns_over_tls   = true
  enable_dns_over_https = true

  # Zone Transfer ACL (DNS-REQ-004)
  zone_transfer_allowed_networks = ["10.0.0.0/8"]
}
```

### NSS-Hardened

```hcl
resource "technitium_server_settings" "nss" {
  # DNS Resolution — locked down for classified environments
  dnssec_validation  = true
  recursion          = "Deny"
  qname_minimization = true
  randomize_name     = true

  # Logging — maximum retention
  log_queries       = true
  logging_type      = "FileAndConsole"
  max_log_file_days = 365

  # Forwarding — US government-controlled resolvers only
  forwarders         = var.approved_forwarders
  forwarder_protocol = "Tls"

  # Encrypted transport
  enable_dns_over_tls   = true
  enable_dns_over_https = true

  # Strict zone transfer controls
  zone_transfer_allowed_networks = var.authorized_networks
  notify_allowed_networks        = var.authorized_networks
}
```

### DNS Forwarding

```hcl
resource "technitium_server_settings" "forwarding" {
  forwarders         = ["1.1.1.1", "8.8.8.8"]
  forwarder_protocol = "Tls"
  recursion          = "AllowOnlyForPrivateNetworks"

  serve_stale      = true
  udp_payload_size = 1232
}
```

## Argument Reference

### DNS Resolution

* `dnssec_validation` - (Optional, Boolean) Enable DNSSEC validation. STIG BIND-9X-001650 (SC-21). Default: `true`.

* `recursion` - (Optional, String) Recursion policy. STIG BIND-9X-001380 (SC-5). Valid values: `Allow`, `Deny`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworkACL`. Default: `"AllowOnlyForPrivateNetworks"`.

* `recursion_network_acl` - (Optional, List of String) Network ACL for recursion when `recursion` is set to `UseSpecifiedNetworkACL`. STIG BIND-9X-001740 (SC-5).

* `qname_minimization` - (Optional, Boolean) Enable QNAME minimization to reduce information leakage. STIG BIND-9X-002440 (CM-6). Default: `true`.

* `randomize_name` - (Optional, Boolean) Randomize query name case (0x20 encoding) to harden against spoofing. STIG BIND-9X-001490 (CM-6). Default: `true`.

### Logging

* `log_queries` - (Optional, Boolean) Enable query logging. STIG BIND-9X-001110 (AU-12). Default: `true`.

* `logging_type` - (Optional, String) Logging output type. STIG BIND-9X-001900 (AU-4). Valid values: `None`, `File`, `Console`, `FileAndConsole`. Default: `"FileAndConsole"`.

* `max_log_file_days` - (Optional, Integer) Maximum number of days to retain log files. STIG BIND-9X-001890 (AU-4). Default: `365`.

### Blocking

* `enable_blocking` - (Optional, Boolean) Enable DNS blocking. Default: `true`.

* `allow_txt_blocking_report` - (Optional, Boolean) Allow TXT record blocking report queries. Default: `true`.

* `blocking_bypass_list` - (Optional, List of String) Domains or networks that bypass blocking.

* `blocking_type` - (Optional, String) Blocking response type. Valid values: `NxDomain`, `AnyAddress`, `TxtRecord`, `CustomAddress`. Default: `"NxDomain"`.

* `blocking_answer_ttl` - (Optional, Integer) TTL in seconds for blocking responses. Default: `30`.

* `custom_blocking_addresses` - (Optional, List of String) Custom IP addresses returned for blocked queries. Only used when `blocking_type` is `CustomAddress`.

* `block_list_urls` - (Optional, List of String) URLs of block list feeds to subscribe to.

* `block_list_update_interval_hours` - (Optional, Integer) Hours between block list update checks. Default: `24`.

### Forwarding

* `forwarders` - (Optional, List of String) Forwarder addresses. STIG BIND-9X-001360 (SC-20).

* `forwarder_protocol` - (Optional, String) Forwarder transport protocol. STIG SC-8. Valid values: `Udp`, `Tcp`, `Tls`, `Https`, `Quic`. Default: `"Tls"`.

* `serve_stale` - (Optional, Boolean) Serve stale cached records when upstream resolvers are unavailable. Default: `true`.

### Encrypted Transport

* `enable_dns_over_tls` - (Optional, Boolean) Enable DNS-over-TLS listener. STIG SC-8. Default: `false`.

* `enable_dns_over_https` - (Optional, Boolean) Enable DNS-over-HTTPS listener. STIG SC-8. Default: `false`.

### Zone Transfer

* `zone_transfer_allowed_networks` - (Optional, List of String) Networks allowed to perform zone transfers. STIG BIND-9X-001010 (AC-10).

* `notify_allowed_networks` - (Optional, List of String) Networks allowed to send NOTIFY messages. STIG BIND-9X-001390 (SC-20).

### Cache

* `udp_payload_size` - (Optional, Integer) EDNS UDP payload size in bytes. Default: `1232`.

* `cache_minimum_record_ttl` - (Optional, Integer) Minimum TTL for cached records in seconds. Default: `10`.

* `cache_maximum_record_ttl` - (Optional, Integer) Maximum TTL for cached records in seconds. Default: `604800`.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Fixed identifier: `server-settings`.

* `version` - Technitium DNS Server version string.

* `uptime` - Server uptime timestamp as reported by the server.

## Import

The server settings singleton can be imported using the fixed ID `server-settings`.

```shell
terraform import technitium_server_settings.main server-settings
```
