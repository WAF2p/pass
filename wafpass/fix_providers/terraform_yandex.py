"""Terraform Yandex Cloud defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_YANDEX_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("yandex_compute_instance", "labels"): {},
    ("yandex_compute_instance", "metadata"): {"ssh-keys": ""},
    ("yandex_compute_instance", "boot_disk"): {
        "initialize_params": {
            "image_id": "",
            "type": "network-hdd",
            "size": 20,
        },
    },
    ("yandex_compute_instance", "network_interface"): {
        "subnet_id": "",
        "nat": False,
        "security_group_ids": [],
    },
    ("yandex_compute_instance", "resources"): {
        "cores": 2,
        "memory": 2,
        "core_fraction": 100,
    },
    ("yandex_compute_instance", "scheduling_policy"): {"preemptible": False},
    ("yandex_compute_instance", "placement_policy"): {"placement_group_id": ""},
    ("yandex_compute_disk", "labels"): {},
    ("yandex_compute_disk", "size"): 20,
    ("yandex_compute_disk", "type"): "network-hdd",
    ("yandex_compute_disk", "image_id"): "",
    ("yandex_vpc_network", "labels"): {},
    ("yandex_vpc_subnet", "labels"): {},
    ("yandex_vpc_subnet", "zone"): "ru-central1-a",
    ("yandex_vpc_subnet", "network_id"): "",
    ("yandex_vpc_subnet", "route_table_id"): "",
    ("yandex_vpc_subnet", "v4_cidr_blocks"): ["192.168.0.0/24"],
    ("yandex_vpc_security_group", "labels"): {},
    ("yandex_vpc_security_group", "ingress"): {
        "protocol": "TCP",
        "port": 443,
        "v4_cidr_blocks": ["0.0.0.0/0"],
    },
    ("yandex_vpc_security_group", "egress"): {
        "protocol": "ANY",
        "v4_cidr_blocks": ["0.0.0.0/0"],
    },
    ("yandex_vpc_route_table", "labels"): {},
    ("yandex_vpc_route_table", "static_route"): {
        "destination_prefix": "0.0.0.0/0",
        "next_hop_address": "",
    },
    ("yandex_container_registry", "labels"): {},
    ("yandex_kubernetes_cluster", "labels"): {},
    ("yandex_kubernetes_cluster", "master"): {
        "zonal": {
            "zone": "ru-central1-a",
            "subnet_id": "",
        },
        "public_ip": False,
        "version": "1.28",
    },
    ("yandex_kubernetes_cluster", "network_policy"): {"provider": "CALICO"},
    ("yandex_kubernetes_node_group", "labels"): {},
    ("yandex_kubernetes_node_group", "instance_template"): {
        "platform_id": "standard-v2",
        "resources_spec": {"memory": 2, "cores": 2},
        "boot_disk_spec": {"type": "network-hdd", "size": 32},
    },
    ("yandex_kubernetes_node_group", "scale_policy"): {
        "fixed_scale": {"size": 1}
    },
    ("yandex_mdb_postgresql_cluster", "labels"): {},
    ("yandex_mdb_postgresql_cluster", "config"): {
        "version": "16",
        "backup_retain_period_days": 7,
    },
    ("yandex_mdb_postgresql_cluster", "host"): {
        "zone": "ru-central1-a",
        "subnet_id": "",
        "assign_public_ip": False,
    },
    ("yandex_mdb_mysql_cluster", "labels"): {},
    ("yandex_mdb_mysql_cluster", "config"): {
        "version": "8.0",
        "backup_retain_period_days": 7,
    },
    ("yandex_mdb_redis_cluster", "labels"): {},
    ("yandex_mdb_redis_cluster", "config"): {
        "version": "7.0",
        "backup_retain_period_days": 7,
    },
    ("yandex_iam_service_account", "description"): "Managed by Terraform",
    ("yandex_iam_service_account_static_access_key", "description"): "",
    ("yandex_kms_symmetric_key", "labels"): {},
    ("yandex_kms_symmetric_key", "default_algorithm"): "AES_256",
    ("yandex_kms_symmetric_key", "rotation_period"): "8760h",
    ("yandex_storage_bucket", "labels"): {},
    ("yandex_storage_bucket", "versioning"): {},
    ("yandex_storage_bucket", "server_side_encryption_configuration"): {
        "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}
    },
    ("yandex_message_queue", "labels"): {},
    ("yandex_function", "labels"): {},
    ("yandex_function", "memory"): 128,
    ("yandex_function", "execution_timeout"): "3s",
    ("yandex_function", "environment"): {},
    ("yandex_function_trigger", "labels"): {},
    ("yandex_dns_zone", "labels"): {},
    ("yandex_dns_recordset", "ttl"): 3600,
    ("yandex_dns_recordset", "data"): [],
    ("yandex_logging_group", "labels"): {},
    ("yandex_monitoring_dashboard", "labels"): {},
    # Provider-level defaults for provider "yandex" {} blocks.
    ("yandex", "region"): "ru-central1",
    ("yandex", "zone"): "ru-central1-a",
    ("yandex", "folder_id"): "",
    ("yandex", "token"): "",
    # Generic tag/label controls can apply to any Yandex Cloud resource.
    ("*", "labels"): {},
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_yandex",
        frameworks=["terraform"],
        providers=["yandex"],
        block_defaults=_TERRAFORM_YANDEX_BLOCK_DEFAULTS,
        resource_type_prefixes=["yandex_"],
        provider_block_types=["yandex"],
    )
)
