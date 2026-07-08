"""Terraform GCP defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_GCP_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("google_storage_bucket", "versioning"): {"enabled": True},
    ("google_storage_bucket", "encryption"): {"default_kms_key_name": ""},
    ("google_storage_bucket", "logging"): {"log_bucket": "", "log_object_prefix": ""},
    ("google_storage_bucket", "lifecycle_rule"): {
        "action": {"type": "Delete"},
        "condition": {"age": 365},
    },
    ("google_storage_bucket", "uniform_bucket_level_access"): True,
    ("google_compute_instance", "shielded_instance_config"): {
        "enable_secure_boot": True,
        "enable_vtpm": True,
        "enable_integrity_monitoring": True,
    },
    ("google_compute_instance", "metadata"): {"enable-oslogin": "TRUE"},
    ("google_compute_instance", "boot_disk"): {
        "initialize_params": {"image": "debian-cloud/debian-11"},
        "kms_key_self_link": "",
    },
    ("google_compute_instance", "service_account"): {
        "scopes": ["cloud-platform"],
    },
    ("google_compute_subnetwork", "private_ip_google_access"): True,
    ("google_compute_network", "auto_create_subnetworks"): False,
    ("google_compute_firewall", "source_ranges"): [],
    ("google_compute_firewall", "destination_ranges"): [],
    ("google_compute_project_metadata", "metadata"): {"enable-oslogin": "TRUE"},
    ("google_sql_database_instance", "settings"): {
        "backup_configuration": {"enabled": True, "binary_log_enabled": True},
        "ip_configuration": {"ipv4_enabled": False, "private_network": ""},
    },
    ("google_container_cluster", "network_policy"): {"enabled": True},
    ("google_container_cluster", "enable_intranode_visibility"): True,
    ("google_container_cluster", "release_channel"): {"channel": "REGULAR"},
    ("google_container_cluster", "node_config"): {
        "oauth_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        "metadata": {"disable-legacy-endpoints": "true"},
    },
    ("google_container_node_pool", "node_config"): {
        "oauth_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        "metadata": {"disable-legacy-endpoints": "true"},
    },
    ("google_bigquery_dataset", "access"): [],
    ("google_bigquery_table", "encryption_configuration"): {"kms_key_name": ""},
    ("google_kms_crypto_key", "rotation_period"): "7776000s",
    ("google_kms_crypto_key", "version_template"): {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
    ("google_secret_manager_secret", "replication"): {"automatic": {}},
    ("google_pubsub_topic", "message_storage_policy"): {"allowed_persistence_regions": []},
    ("google_pubsub_subscription", "expiration_policy"): {"ttl": "2678400s"},
    ("google_cloudfunctions_function", "environment_variables"): {},
    ("google_cloudfunctions_function", "vpc_connector"): "",
    ("google_cloud_run_service", "template"): {
        "spec": {
            "containers": {"resources": {"limits": {"cpu": "1", "memory": "512Mi"}}}
        }
    },
    ("google_logging_project_sink", "destination"): "",
    ("google_monitoring_alert_policy", "alert_strategy"): {},
    ("google_monitoring_alert_policy", "notification_channels"): [],
    ("google_service_account", "description"): "Managed by Terraform",
    ("google_project_iam_audit_config", "audit_log_config"): {},
    ("google_compute_router_nat", "log_config"): {"enable": True, "filter": "ERRORS_ONLY"},
    ("google_compute_global_address", "purpose"): "VPC_PEERING",
    ("google_dns_managed_zone", "dnssec_config"): {
        "state": "on",
        "default_key_specs": {
            "algorithm": "rsasha256",
            "key_length": 2048,
            "key_type": "keySigning",
        },
    },
    # Provider-level defaults for provider "google" {} blocks.
    ("google", "region"): "europe-west3",
    ("google", "project"): "",
    # Generic tag/label controls can apply to any GCP resource.
    ("*", "labels"): {},
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_gcp",
        frameworks=["terraform"],
        providers=["gcp", "google"],
        block_defaults=_TERRAFORM_GCP_BLOCK_DEFAULTS,
        resource_type_prefixes=["google_"],
        provider_block_types=["google"],
    )
)
