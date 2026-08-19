# Changing the proof-of-non-existence mechanism (NSEC <-> NSEC3).
#
# This is the ONE DNSSEC parameter change that is not destructive. The provider
# converts the zone in place: existing keys are kept, no re-signing ceremony is
# needed, the DS record in the parent is unaffected, and no
# `change_acknowledgment` is required.
#
# To change it, edit `nx_proof` and apply. That is the whole procedure.
#
# Which to use: NSEC3 prevents zone walking, where an attacker enumerates every
# name in a zone by following the NSEC chain. The Windows Server DNS STIG
# requires NSEC3 for all internal zones, and NIST SP 800-81r3 describes zone
# enumeration as "most likely a prelude to an attack". Use NSEC only when you
# have a specific reason and the zone contents are genuinely public.
#
# Applying this file to a zone currently signed with NSEC converts it to NSEC3.

resource "technitium_zone" "nxproof" {
  name = "walkable.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"

    # Changed from "NSEC". Converts in place; keys and DS records survive.
    nx_proof = "NSEC3"
  }
}
