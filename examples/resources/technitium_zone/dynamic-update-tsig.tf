# cert-manager solves ACME DNS-01 challenges with RFC 2136 dynamic updates.
# The key may only change TXT records below apps.example.com, and only from
# the cluster network.
resource "technitium_tsig_key" "cert_manager" {
  key_name  = "cert-manager"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "example" {
  name = "example.com"
  type = "Primary"

  dynamic_update             = "UseSpecifiedNetworkACL"
  dynamic_update_network_acl = ["192.0.2.0/24"]

  dynamic_update_security_policies = [
    {
      tsig_key_name = technitium_tsig_key.cert_manager.key_name
      domain        = "*.apps.example.com"
      allowed_types = ["TXT"]
    },
  ]
}
