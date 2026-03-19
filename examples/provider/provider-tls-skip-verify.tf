terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with TLS verification disabled
# Use ONLY for development or HomeLab environments where certificate
# management is not a priority. Not available when STIG compliance is enabled.
provider "technitium" {
  server_url      = var.technitium_server_url
  api_token       = var.technitium_api_token
  skip_tls_verify = true
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS)"
  type        = string
  default     = "https://dns.homelab.local:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}
