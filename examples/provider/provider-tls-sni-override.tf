terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with SNI hostname override
# Use when connecting through a reverse proxy (e.g., Traefik, HAProxy)
# where the TLS certificate hostname differs from the connection address.
provider "technitium" {
  server_url      = var.technitium_server_url
  api_token       = var.technitium_api_token
  ca_cert_file    = var.technitium_ca_cert_file
  tls_server_name = var.technitium_tls_server_name
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS)"
  type        = string
  default     = "https://10.0.1.50:5380"
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

variable "technitium_tls_server_name" {
  description = "SNI hostname for TLS connection (must match server certificate)"
  type        = string
  default     = "dns.example.com"
}
