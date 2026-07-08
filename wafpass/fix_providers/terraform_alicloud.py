"""Terraform Alibaba Cloud defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_ALICLOUD_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("alicloud_oss_bucket", "versioning"): {"status": "Enabled"},
    ("alicloud_oss_bucket", "server_side_encryption_rule"): {
        "sse_algorithm": "AES256"
    },
    ("alicloud_oss_bucket", "logging"): {"target_bucket": "", "target_prefix": ""},
    ("alicloud_oss_bucket", "lifecycle_rule"): {
        "id": "default",
        "enabled": True,
        "expiration": {"days": 365},
    },
    ("alicloud_oss_bucket", "transfer_acceleration"): {"status": "Enabled"},
    ("alicloud_ecs_instance", "metadata_options"): {
        "http_tokens": "required",
        "http_endpoint": "enabled",
    },
    ("alicloud_ecs_instance", "user_data"): "",
    ("alicloud_ecs_instance", "vpc_id"): "",
    ("alicloud_ecs_instance", "vswitch_id"): "",
    ("alicloud_ecs_instance", "security_groups"): [],
    ("alicloud_vpc", "tags"): {},
    ("alicloud_vswitch", "tags"): {},
    ("alicloud_security_group", "tags"): {},
    ("alicloud_security_group_rule", "port_range"): "443/443",
    ("alicloud_security_group_rule", "cidr_ip"): "0.0.0.0/0",
    ("alicloud_rds_instance", "tags"): {},
    ("alicloud_rds_instance", "backup_retention_period"): 7,
    ("alicloud_rds_instance", "ssl_enabled"): True,
    ("alicloud_polardb_cluster", "tags"): {},
    ("alicloud_polardb_cluster", "backup_retention_policy_on_cluster"): {
        "preferred_backup_period": ["Tuesday"],
        "preferred_backup_time": "02:00Z-03:00Z",
        "backup_retention_period": 7,
    },
    ("alicloud_redis_instance", "tags"): {},
    ("alicloud_redis_instance", "backup_period"): ["Tuesday"],
    ("alicloud_kms_key", "automatic_rotation"): "Enabled",
    ("alicloud_kms_key", "rotation_interval"): "365d",
    ("alicloud_kms_secret", "tags"): {},
    ("alicloud_ram_role", "max_session_duration"): 3600,
    ("alicloud_ram_policy", "policy"): "",
    ("alicloud_fc_service", "role"): "",
    ("alicloud_fc_service", "log_config"): {"project": "", "logstore": ""},
    ("alicloud_fc_function", "timeout"): 30,
    ("alicloud_fc_function", "memory_size"): 128,
    ("alicloud_fc_function", "environment_variables"): {},
    ("alicloud_slb", "tags"): {},
    ("alicloud_slb_listener", "tls_cipher_policy"): "tls_cipher_policy_1_2",
    ("alicloud_waf_instance", "resource_group_id"): "",
    ("alicloud_actiontrail_trail", "event_rw"): "Write",
    ("alicloud_actiontrail_trail", "trail_region"): "All",
    # Provider-level defaults for provider "alicloud" {} blocks.
    ("alicloud", "region"): "eu-central-1",
    ("alicloud", "access_key"): "",
    # Generic tag-only controls can apply to any Alibaba Cloud resource.
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_alicloud",
        frameworks=["terraform"],
        providers=["alicloud", "alibabacloud"],
        block_defaults=_TERRAFORM_ALICLOUD_BLOCK_DEFAULTS,
        resource_type_prefixes=["alicloud_"],
        provider_block_types=["alicloud"],
    )
)
