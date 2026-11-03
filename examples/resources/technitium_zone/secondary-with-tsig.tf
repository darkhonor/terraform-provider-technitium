resource "technitium_tsig_key" "transfer" {
  key_name  = "transfer.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "secondary" {
  name = "example.com"
  type = "Secondary"

  # The primary(ies) to transfer from. The first transfer happens while the zone
  # is created, so the primary must be reachable and allow this server.
  primary_name_server_addresses = ["10.0.10.12"]
  zone_transfer_protocol        = "Tcp"

  primary_zone_transfer_tsig_key_name = technitium_tsig_key.transfer.key_name
}
