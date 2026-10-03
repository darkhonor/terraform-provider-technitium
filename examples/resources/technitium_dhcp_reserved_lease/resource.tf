resource "technitium_dhcp_scope" "lan" {
  name             = "lan"
  starting_address = "192.168.1.50"
  ending_address   = "192.168.1.250"
  subnet_mask      = "255.255.255.0"
}

resource "technitium_dhcp_reserved_lease" "nas" {
  scope            = technitium_dhcp_scope.lan.name
  hardware_address = "00-11-22-33-44-66"
  ip_address       = "192.168.1.110"
  host_name        = "nas"
  comments         = "storage box"
}
