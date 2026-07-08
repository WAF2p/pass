"""Terraform OCI defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_OCI_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("oci_objectstorage_bucket", "versioning"): {"status": "Enabled"},
    ("oci_objectstorage_bucket", "kms_key_id"): "",
    ("oci_objectstorage_bucket", "object_events_enabled"): True,
    ("oci_objectstorage_bucket", "auto_tiering"): {"auto_tiering_status": "Disabled"},
    ("oci_core_instance", "agent_config"): {
        "is_management_disabled": False,
        "is_monitoring_disabled": False,
    },
    ("oci_core_instance", "metadata"): {"ssh_authorized_keys": ""},
    ("oci_core_instance", "preserve_boot_volume"): False,
    ("oci_core_instance", "shape_config"): {"ocpus": 1, "memory_in_gbs": 8},
    ("oci_core_vcn", "dns_label"): "vcn",
    ("oci_core_subnet", "prohibit_public_ip_on_vnic"): True,
    ("oci_core_subnet", "route_table_id"): "",
    ("oci_core_security_list", "ingress_security_rules"): [],
    ("oci_core_security_list", "egress_security_rules"): [],
    ("oci_kms_vault", "vault_type"): "DEFAULT",
    ("oci_kms_key", "key_shape"): {"algorithm": "AES", "length": 32},
    ("oci_database_db_system", "db_home"): {
        "database": {
            "admin_password": "TODO-fill-in",
            "db_name": "TODO",
        },
    },
    ("oci_database_db_system", "data_storage_size_in_gb"): 256,
    ("oci_database_db_system", "backup_subnet_id"): "",
    ("oci_mysql_db_system", "admin_password"): "TODO-fill-in",
    ("oci_mysql_db_system", "backup_policy"): {"is_enabled": True, "retention_in_days": 7},
    ("oci_artifacts_container_repository", "is_immutable"): True,
    ("oci_artifacts_container_repository", "is_public"): False,
    ("oci_functions_function", "trace_config"): {"is_enabled": True},
    ("oci_functions_function", "timeout_in_seconds"): 30,
    ("oci_functions_function", "memory_in_mbs"): 128,
    ("oci_logging_log_group", "description"): "Managed by Terraform",
    ("oci_monitoring_alarm", "destinations"): [],
    ("oci_monitoring_alarm", "metric_compartment_id"): "",
    ("oci_identity_compartment", "description"): "Managed by Terraform",
    ("oci_identity_policy", "statements"): [],
    # Provider-level defaults for provider "oci" {} blocks.
    ("oci", "region"): "eu-frankfurt-1",
    ("oci", "tenancy_ocid"): "",
    ("oci", "user_ocid"): "",
    # Generic tag controls can apply to any OCI resource.
    ("*", "freeform_tags"): {},
    ("*", "defined_tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_oci",
        frameworks=["terraform"],
        providers=["oci", "oracle"],
        block_defaults=_TERRAFORM_OCI_BLOCK_DEFAULTS,
        resource_type_prefixes=["oci_"],
        provider_block_types=["oci"],
    )
)
