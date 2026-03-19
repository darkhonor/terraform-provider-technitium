terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with STIG compliance enforcement
# TLS 1.3 is the default and required for STIG compliance (SC-8).
# The STIG engine validates TLS configuration at plan time:
#   - server_url must use HTTPS (warning in warn mode, error in strict)
#   - tls_min_version must be "1.3" (warning if "1.2" in warn mode)
#   - skip_tls_verify must not be true
provider "technitium" {
  server_url   = var.technitium_server_url
  api_token    = var.technitium_api_token
  ca_cert_file = var.technitium_ca_cert_file

  stig_compliance {
    enabled     = true
    enforcement = "strict"

    categorization {
      baseline = "moderate"
    }
  }
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS required for STIG)"
  type        = string
  default     = "https://dns.example.com:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}

variable "technitium_ca_cert_file" {
  description = "Path to PEM-encoded CA certificate file"
  type        = string
}
