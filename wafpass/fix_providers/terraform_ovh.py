"""Terraform OVHcloud defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_OVH_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("ovh_cloud_project_instance", "labels"): {},
    ("ovh_cloud_project_instance", "region"): "GRA7",
    ("ovh_cloud_project_instance", "ssh_key"): {"id": ""},
    ("ovh_cloud_project_instance", "boot_from"): {"image_id": ""},
    ("ovh_cloud_project_instance", "ssh_key_ids"): [],
    ("ovh_cloud_project_storage", "labels"): {},
    ("ovh_cloud_project_storage", "region"): "GRA7",
    ("ovh_cloud_project_storage", "type"): "classic",
    ("ovh_cloud_project_network_private", "labels"): {},
    ("ovh_cloud_project_network_private", "regions"): ["GRA7"],
    ("ovh_cloud_project_network_private_subnet", "region"): "GRA7",
    ("ovh_cloud_project_network_private_subnet", "network"): "192.168.0.0/24",
    ("ovh_cloud_project_network_private_subnet", "start"): "192.168.0.100",
    ("ovh_cloud_project_network_private_subnet", "end"): "192.168.0.254",
    ("ovh_cloud_project_network_private_subnet", "dhcp"): True,
    ("ovh_cloud_project_kube", "region"): "GRA7",
    ("ovh_cloud_project_kube", "version"): "1.28",
    ("ovh_cloud_project_kube", "labels"): {},
    ("ovh_cloud_project_kube", "update_policy"): "MINIMAL_DOWNTIME",
    ("ovh_cloud_project_kube_nodepool", "labels"): {},
    ("ovh_cloud_project_kube_nodepool", "desired_nodes"): 1,
    ("ovh_cloud_project_kube_nodepool", "min_nodes"): 1,
    ("ovh_cloud_project_kube_nodepool", "max_nodes"): 3,
    ("ovh_cloud_project_kube_nodepool", "flavor_name"): "b2-7",
    ("ovh_cloud_project_database", "region"): "GRA7",
    ("ovh_cloud_project_database", "flavor"): "db1-2",
    ("ovh_cloud_project_database", "backup_time"): "02:00:00",
    ("ovh_cloud_project_database", "backup_regions"): [],
    ("ovh_cloud_project_database", "maintenance_time"): "04:00:00",
    ("ovh_cloud_project_database", "labels"): {},
    ("ovh_vrack_cloudproject", "vrack_id"): "",
    ("ovh_vrack_cloudproject", "project_id"): "",
    ("ovh_domain_zone_record", "ttl"): 3600,
    ("ovh_domain_zone_record", "target"): "",
    ("ovh_iam_policy", "identities"): [],
    ("ovh_iam_policy", "resources"): [],
    ("ovh_iam_policy", "allow"): False,
    ("ovh_iam_policy", "except"): False,
    ("ovh_me_identity_user", "group"): "DEFAULT",
    ("ovh_me_ssh_key", "key"): "",
    # Provider-level defaults for provider "ovh" {} blocks.
    ("ovh", "region"): "GRA7",
    ("ovh", "endpoint"): "ovh-eu",
    # Generic tag/label controls can apply to any OVHcloud resource.
    ("*", "labels"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_ovh",
        frameworks=["terraform"],
        providers=["ovh", "ovhcloud"],
        block_defaults=_TERRAFORM_OVH_BLOCK_DEFAULTS,
        resource_type_prefixes=["ovh_"],
        provider_block_types=["ovh"],
    )
)
