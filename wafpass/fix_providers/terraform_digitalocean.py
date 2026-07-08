"""Terraform DigitalOcean defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_DIGITALOCEAN_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("digitalocean_droplet", "tags"): [],
    ("digitalocean_droplet", "ssh_keys"): [],
    ("digitalocean_droplet", "vpc_uuid"): "",
    ("digitalocean_droplet", "backups"): True,
    ("digitalocean_droplet", "ipv6"): False,
    ("digitalocean_droplet", "monitoring"): True,
    ("digitalocean_droplet", "user_data"): "",
    ("digitalocean_droplet", "volume_ids"): [],
    ("digitalocean_volume", "tags"): [],
    ("digitalocean_volume", "size"): 10,
    ("digitalocean_volume", "region"): "nyc1",
    ("digitalocean_volume", "initial_filesystem_type"): "ext4",
    ("digitalocean_volume_attachment", "droplet_id"): 0,
    ("digitalocean_vpc", "tags"): [],
    ("digitalocean_vpc", "ip_range"): "10.0.0.0/16",
    ("digitalocean_vpc", "region"): "nyc1",
    ("digitalocean_firewall", "tags"): [],
    ("digitalocean_firewall", "inbound_rule"): {
        "protocol": "tcp",
        "port_range": "443",
        "source_addresses": ["0.0.0.0/0"],
    },
    ("digitalocean_firewall", "outbound_rule"): {
        "protocol": "tcp",
        "port_range": "443",
        "destination_addresses": ["0.0.0.0/0"],
    },
    ("digitalocean_loadbalancer", "tags"): [],
    ("digitalocean_loadbalancer", "region"): "nyc1",
    ("digitalocean_loadbalancer", "size"): "lb-small",
    ("digitalocean_loadbalancer", "forwarding_rule"): {
        "entry_protocol": "https",
        "entry_port": 443,
        "target_protocol": "http",
        "target_port": 80,
    },
    ("digitalocean_loadbalancer", "healthcheck"): {
        "protocol": "http",
        "port": 80,
        "path": "/",
    },
    ("digitalocean_certificate", "tags"): [],
    ("digitalocean_certificate", "type"): "lets_encrypt",
    ("digitalocean_domain", "tags"): [],
    ("digitalocean_domain", "ip_address"): "",
    ("digitalocean_record", "type"): "A",
    ("digitalocean_record", "ttl"): 3600,
    ("digitalocean_record", "value"): "",
    ("digitalocean_spaces_bucket", "tags"): [],
    ("digitalocean_spaces_bucket", "region"): "nyc3",
    ("digitalocean_spaces_bucket", "versioning"): {
        "enabled": True,
    },
    ("digitalocean_spaces_bucket", "cors_rule"): {
        "allowed_headers": [],
        "allowed_methods": ["GET"],
        "allowed_origins": [],
        "max_age_seconds": 3000,
    },
    ("digitalocean_database_cluster", "tags"): [],
    ("digitalocean_database_cluster", "size"): "db-s-1vcpu-1gb",
    ("digitalocean_database_cluster", "region"): "nyc1",
    ("digitalocean_database_cluster", "version"): "16",
    ("digitalocean_database_cluster", "backup_restore"): {
        "database_name": "",
    },
    ("digitalocean_database_cluster", "maintenance_window"): {
        "day": "monday",
        "hour": "02:00:00",
    },
    ("digitalocean_database_db", "tags"): [],
    ("digitalocean_database_user", "tags"): [],
    ("digitalocean_database_replica", "tags"): [],
    ("digitalocean_kubernetes_cluster", "tags"): [],
    ("digitalocean_kubernetes_cluster", "region"): "nyc1",
    ("digitalocean_kubernetes_cluster", "version"): "1.28",
    ("digitalocean_kubernetes_cluster", "node_pool"): {
        "name": "default",
        "size": "s-1vcpu-2gb",
        "node_count": 1,
        "auto_scale": False,
    },
    ("digitalocean_kubernetes_node_pool", "tags"): [],
    ("digitalocean_kubernetes_node_pool", "size"): "s-1vcpu-2gb",
    ("digitalocean_kubernetes_node_pool", "node_count"): 1,
    ("digitalocean_kubernetes_node_pool", "auto_scale"): False,
    ("digitalocean_container_registry", "tags"): [],
    ("digitalocean_container_registry", "subscription_tier_slug"): "starter",
    ("digitalocean_app", "tags"): [],
    ("digitalocean_app", "spec"): {
        "name": "app",
        "region": "nyc",
        "service": {
            "name": "web",
            "instance_count": 1,
            "instance_size_slug": "basic-xxs",
        },
    },
    ("digitalocean_monitor_alert", "tags"): [],
    ("digitalocean_monitor_alert", "notifications"): [],
    ("digitalocean_uptime_check", "tags"): [],
    ("digitalocean_uptime_alert", "tags"): [],
    ("digitalocean_project", "description"): "Managed by Terraform",
    ("digitalocean_project", "purpose"): "Service or API",
    ("digitalocean_project", "environment"): "Production",
    ("digitalocean_project_resources", "project_id"): "",
    ("digitalocean_ssh_key", "public_key"): "",
    ("digitalocean_tag", "name"): "",
    # Provider-level defaults for provider "digitalocean" {} blocks.
    ("digitalocean", "region"): "nyc1",
    ("digitalocean", "token"): "",
    # Generic tag-only controls can apply to any DigitalOcean resource.
    ("*", "tags"): [],
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_digitalocean",
        frameworks=["terraform"],
        providers=["digitalocean", "do"],
        block_defaults=_TERRAFORM_DIGITALOCEAN_BLOCK_DEFAULTS,
        resource_type_prefixes=["digitalocean_"],
        provider_block_types=["digitalocean"],
    )
)
