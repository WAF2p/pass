"""Terraform Hetzner Cloud (hcloud) defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_HCLOUD_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("hcloud_server", "labels"): {},
    ("hcloud_server", "backups"): True,
    ("hcloud_server", "delete_protection"): True,
    ("hcloud_server", "rebuild_protection"): True,
    ("hcloud_server", "placement_group"): {"id": ""},
    ("hcloud_server", "firewall_ids"): [],
    ("hcloud_server", "network"): {
        "network_id": 0,
        "ip": "",
        "alias_ips": [],
    },
    ("hcloud_floating_ip", "labels"): {},
    ("hcloud_floating_ip", "home_location"): "",
    ("hcloud_floating_ip_assignment", "server_id"): 0,
    ("hcloud_volume", "labels"): {},
    ("hcloud_volume", "size"): 10,
    ("hcloud_volume", "format"): "ext4",
    ("hcloud_volume", "delete_protection"): True,
    ("hcloud_network", "labels"): {},
    ("hcloud_network", "ip_range"): "10.0.0.0/16",
    ("hcloud_network_subnet", "type"): "cloud",
    ("hcloud_network_subnet", "ip_range"): "10.0.1.0/24",
    ("hcloud_network_subnet", "network_zone"): "eu-central",
    ("hcloud_firewall", "labels"): {},
    ("hcloud_firewall", "rule"): {
        "direction": "in",
        "protocol": "tcp",
        "port": "443",
        "source_ips": ["0.0.0.0/0"],
    },
    ("hcloud_load_balancer", "labels"): {},
    ("hcloud_load_balancer", "load_balancer_type"): "lb11",
    ("hcloud_load_balancer", "location"): "nbg1",
    ("hcloud_load_balancer_service", "protocol"): "https",
    ("hcloud_load_balancer_service", "listen_port"): 443,
    ("hcloud_load_balancer_service", "destination_port"): 443,
    ("hcloud_load_balancer_target", "type"): "server",
    ("hcloud_certificate", "labels"): {},
    ("hcloud_certificate", "domain_names"): [],
    ("hcloud_primary_ip", "labels"): {},
    ("hcloud_primary_ip", "assignee_type"): "server",
    ("hcloud_primary_ip", "auto_delete"): False,
    ("hcloud_rdns", "dns_ptr"): "",
    ("hcloud_ssh_key", "labels"): {},
    ("hcloud_snapshot", "labels"): {},
    ("hcloud_image", "labels"): {},
    # Provider-level defaults for provider "hcloud" {} blocks.
    ("hcloud", "token"): "",
    ("hcloud", "region"): "nbg1",
    # Generic tag/label controls can apply to any hcloud resource.
    ("*", "labels"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_hcloud",
        frameworks=["terraform"],
        providers=["hcloud", "hetzner"],
        block_defaults=_TERRAFORM_HCLOUD_BLOCK_DEFAULTS,
        resource_type_prefixes=["hcloud_"],
        provider_block_types=["hcloud"],
    )
)
