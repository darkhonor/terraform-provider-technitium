# EdDSA (Ed448) signing.
#
# Why choose it: Ed448 produces the smallest DNSKEY and RRSIG records of any
# algorithm DNSSEC currently specifies. NIST SP 800-81r3 notes that response
# size drives DNS truncation and TCP fallback, and recommends ECDSA and Ed448
# over RSA for exactly that reason.
#
# STIG standing: BIND-9X-002050 requires a DNSSEC algorithm number of 8
# (RSA/SHA-256) or higher. Ed448 is algorithm 16 and clears that floor.
#
# NOTE: this provider's DNS-REQ-012 validator currently accepts only ECDSA, so
# under strict enforcement this configuration draws a finding even though the
# STIG permits it. The validator is narrower than its own cited source; tracked
# in issue #98. Until that is resolved, either run this zone under `warn`
# enforcement or suppress DNS-REQ-012 explicitly.

resource "technitium_zone" "eddsa" {
  name = "ed.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "EDDSA"
    curve     = "ED448"
    nx_proof  = "NSEC3"
  }
}
