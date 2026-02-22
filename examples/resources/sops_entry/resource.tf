provider "sops" {}

resource "sops_entry" "secrets" {
  file = "config.enc.yaml"

  entries = {
    db_password    = var.db_password
    api_key        = var.api_key
    redis_password = var.redis_password
  }
}

output "all_config" {
  value     = resource.sops_entry.secrets.data
  sensitive = true
}
