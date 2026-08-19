# Rotating the DNSSEC algorithm or curve on a zone that is already signed.
#
# THIS IS DESTRUCTIVE. Technitium cannot re-key a signed zone in place, so the
# provider unsigns the zone and re-signs it with the new parameters. Every key
# is regenerated. The zone is briefly unsigned during the apply, and the DS
# record published in the parent zone STOPS MATCHING the moment the new keys
# exist — resolvers that have cached the old DS will fail validation until you
# publish the new one.
#
# Because of that, the change is refused at plan time unless the zone declares
# an acknowledgment naming exactly the parameters you are moving to. The token
# is compared literally, so it must match the provider's spelling:
#
#     ECDSA/P384      moving to ECDSA with curve P384
#     EDDSA/ED448     moving to EdDSA with curve Ed448
#     RSA             moving to RSA (bare - RSA has no curve)
#
# PROCEDURE
#
#   1. Set the new algorithm/curve AND the matching change_acknowledgment, as
#      below. Apply. The provider unsigns and re-signs.
#   2. Export the new DS records from the server and publish them in the parent
#      zone, replacing the old ones (WDNS-22-000055 / WDNS-22-000056).
#   3. Redistribute trust anchors to any resolver configured with an explicit
#      anchor for this zone.
#   4. REMOVE the change_acknowledgment from your configuration.
#
# Step 4 matters. A token left in place remains standing consent for that same
# transition: if the zone is later re-signed out of band with other parameters,
# the next apply silently converges back destructively under the surviving
# token. Every plan warns while it sits there unused.
#
# The older workaround - set enabled = false, apply, then re-enable with new
# parameters - still works. Under strict enforcement its first step needs
# change_acknowledgment = "unsigned" (see dnssec-unsign.tf).

resource "technitium_zone" "rotating" {
  name = "rotate.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"

    # Changed from "P256". Requires the acknowledgment below.
    curve    = "P384"
    nx_proof = "NSEC3"

    # Authorizes THIS transition only. Remove after step 3 above.
    change_acknowledgment = "ECDSA/P384"
  }
}
