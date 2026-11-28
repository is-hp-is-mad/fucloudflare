# What the terraform job of .github/workflows/compat.yml applies to a
# throwaway local fucf: a zone, two records and two T3 rulesets. Example data
# only. The token comes from CLOUDFLARE_API_TOKEN, the address and the account
# id from TF_VAR_base_url and TF_VAR_account_id.

terraform {
  required_version = "= 1.16.7"
  required_providers {
    # v5: the first major version whose provider takes a base_url (v4 always
    # speaks https to api_hostname, so it cannot reach a plain-HTTP loopback API).
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.25.0"
    }
  }
}

variable "base_url" {
  type = string
}

variable "account_id" {
  type = string
}

provider "cloudflare" {
  base_url = var.base_url
}

resource "cloudflare_zone" "compat" {
  account = {
    id = var.account_id
  }
  name = "example.com"
  type = "full"
}

# Proxied, so the edge answers for it and the firewall rule below can be seen
# working; the origin (documentation range) is never reached.
resource "cloudflare_dns_record" "www" {
  zone_id = cloudflare_zone.compat.id
  name    = "www.example.com"
  type    = "A"
  content = "192.0.2.10"
  ttl     = 1
  proxied = true
}

resource "cloudflare_dns_record" "api_v6" {
  zone_id = cloudflare_zone.compat.id
  name    = "api.example.com"
  type    = "AAAA"
  content = "2001:db8::10"
  ttl     = 300
  proxied = false
  comment = "compat check"
}

# fucf keeps no ruleset name or description (every entrypoint answers
# "default" and ""), so they are written that way here; anything else would
# read back different and make Terraform report an inconsistent result.
# No rule sets a ref: fucf's ref is always the rule's own id.
resource "cloudflare_ruleset" "firewall" {
  zone_id     = cloudflare_zone.compat.id
  name        = "default"
  description = ""
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules = [
    {
      action      = "block"
      expression  = "http.request.uri.path eq \"/compat-blocked\""
      description = "compat: block one path"
      enabled     = true
    }
  ]
}

resource "cloudflare_ruleset" "request_headers" {
  zone_id     = cloudflare_zone.compat.id
  name        = "default"
  description = ""
  kind        = "zone"
  phase       = "http_request_late_transform"
  rules = [
    {
      action      = "rewrite"
      expression  = "starts_with(http.request.uri.path, \"/api/\")"
      description = "compat: tag api requests"
      enabled     = true
      action_parameters = {
        headers = {
          "x-compat-check" = {
            operation = "set"
            value     = "1"
          }
        }
      }
    }
  ]
}

output "zone_id" {
  value = cloudflare_zone.compat.id
}

output "firewall_ruleset_id" {
  value = cloudflare_ruleset.firewall.id
}

output "request_headers_ruleset_id" {
  value = cloudflare_ruleset.request_headers.id
}
