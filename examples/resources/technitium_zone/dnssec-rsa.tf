# RSA signing, for interoperability with validators that predate elliptic-curve
# DNSSEC support.
#
# Why choose it: RSA/SHA-256 is DNSSEC algorithm 8 — the exact floor set by
# BIND-9X-002050 ("if the KSK DNSKEY is less than 8 (SHA256), this is a
# finding"). The Windows Server DNS STIG goes further and calls RSA "the
# recommended algorithm for this guideline". Every deployed validator
# understands it.
#
# Why not to choose it by default: RSA keys and signatures are far larger than
# their elliptic-curve equivalents, which inflates DNS responses and pushes
# queries to TCP. NIST SP 800-81r3 prefers ECDSA and Ed448 for that reason.
# Reach for RSA when you have a specific interoperability requirement.
#
# The `curve` attribute does not apply to RSA and is omitted here.
#
# NOTE: this provider's DNS-REQ-012 validator currently accepts only ECDSA, so
# under strict enforcement this configuration draws a finding even though both
# DNS STIGs permit RSA and one recommends it. Tracked in issue #98.

resource "technitium_zone" "rsa" {
  name = "legacy.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "RSA"
    nx_proof  = "NSEC3"
  }
}
