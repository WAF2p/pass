"""Terraform STACKIT defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_STACKIT_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("stackit_object_storage_bucket", "versioning"): {"status": "Enabled"},
    ("stackit_object_storage_bucket", "labels"): {},
    ("stackit_object_storage_bucket", "region"): "eu01",
    ("stackit_server", "boot_volume"): {"size": 32, "type": "storage_premium"},
    ("stackit_server", "network_interfaces"): [],
    ("stackit_server", "labels"): {},
    ("stackit_server", "availability_zone"): "eu01-1",
    ("stackit_volume", "labels"): {},
    ("stackit_volume", "size"): 32,
    ("stackit_network", "labels"): {},
    ("stackit_network", "ipv4_prefix_length"): 24,
    ("stackit_network_interface", "labels"): {},
    ("stackit_ske_cluster", "node_pools"): [],
    ("stackit_ske_cluster", "maintenance"): {
        "enable_kubernetes_version_updates": True,
        "enable_machine_image_version_updates": True,
    },
    ("stackit_ske_cluster", "labels"): {},
    ("stackit_postgresql_flex_instance", "backup_schedule"): {
        "enabled": True,
        "retention_period_days": 7,
    },
    ("stackit_postgresql_flex_instance", "version"): "16",
    ("stackit_postgresql_flex_instance", "labels"): {},
    ("stackit_redis_instance", "backup_schedule"): {
        "enabled": True,
        "retention_period_days": 7,
    },
    ("stackit_redis_instance", "labels"): {},
    ("stackit_logme_instance", "labels"): {},
    ("stackit_loadbalancer", "labels"): {},
    ("stackit_loadbalancer", "listeners"): [],
    ("stackit_resource", "labels"): {},
    ("stackit_credential", "labels"): {},
    ("stackit_argus_instance", "labels"): {},
    ("stackit_observability_instance", "plans"): [],
    # Provider-level defaults for provider "stackit" {} blocks.
    ("stackit", "region"): "eu01",
    ("stackit", "project_id"): "",
    # Generic tag/label controls can apply to any STACKIT resource.
    ("*", "labels"): {},
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_stackit",
        frameworks=["terraform"],
        providers=["stackit"],
        block_defaults=_TERRAFORM_STACKIT_BLOCK_DEFAULTS,
        resource_type_prefixes=["stackit_"],
        provider_block_types=["stackit"],
    )
)
