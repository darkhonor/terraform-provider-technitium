resource "technitium_dhcp_scope" "lan" {
  name             = "lan"
  starting_address = "192.168.1.50"
  ending_address   = "192.168.1.250"
  subnet_mask      = "255.255.255.0"

  enabled = true

  lease_time_days = 7

  domain_name = "home.lan"
  dns_updates = true
  dns_ttl     = 900

  router_address      = "192.168.1.1"
  use_this_dns_server = true

  exclusions = [
    {
      starting_address = "192.168.1.50"
      ending_address   = "192.168.1.60"
    }
  ]

  reserved_leases = [
    {
      host_name        = "printer"
      hardware_address = "00-11-22-33-44-55"
      address          = "192.168.1.100"
      comments         = "office printer"
    }
  ]
}
