"""Terraform AzureRM defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_AZURE_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("azurerm_storage_account", "blob_properties"): {
        "versioning_enabled": True,
        "delete_retention_policy": {"days": 7},
        "container_delete_retention_policy": {"days": 7},
    },
    ("azurerm_storage_account", "network_rules"): {
        "default_action": "Deny",
        "bypass": ["AzureServices"],
    },
    ("azurerm_storage_account", "identity"): {"type": "SystemAssigned"},
    ("azurerm_storage_account", "encryption"): {},
    ("azurerm_linux_function_app", "site_config"): {
        "application_insights_key": "",
        "application_insights_connection_string": "",
        "ftps_state": "Disabled",
        "http2_enabled": True,
        "min_tls_version": "1.2",
    },
    ("azurerm_windows_function_app", "site_config"): {
        "application_insights_key": "",
        "application_insights_connection_string": "",
        "ftps_state": "Disabled",
        "http2_enabled": True,
        "min_tls_version": "1.2",
    },
    ("azurerm_linux_web_app", "site_config"): {
        "ftps_state": "Disabled",
        "http2_enabled": True,
        "min_tls_version": "1.2",
    },
    ("azurerm_windows_web_app", "site_config"): {
        "ftps_state": "Disabled",
        "http2_enabled": True,
        "min_tls_version": "1.2",
    },
    ("azurerm_key_vault", "network_acls"): {
        "default_action": "Deny",
        "bypass": "AzureServices",
    },
    ("azurerm_key_vault", "purge_protection_enabled"): True,
    ("azurerm_key_vault", "soft_delete_retention_days"): 90,
    ("azurerm_key_vault_key", "expiration_date"): "",
    ("azurerm_sql_server", "extended_auditing_policy"): {
        "storage_endpoint": "",
        "retention_days": 90,
    },
    ("azurerm_mssql_server", "extended_auditing_policy"): {
        "storage_endpoint": "",
        "retention_days": 90,
    },
    ("azurerm_mssql_server", "azuread_administrator"): {
        "login_username": "TODO-fill-in",
        "object_id": "TODO-fill-in",
    },
    ("azurerm_postgresql_server", "ssl_enforcement_enabled"): True,
    ("azurerm_postgresql_server", "ssl_minimal_tls_version_enforced"): "TLS1_2",
    ("azurerm_postgresql_flexible_server", "ssl_enforcement_enabled"): True,
    ("azurerm_mysql_server", "ssl_enforcement_enabled"): True,
    ("azurerm_mysql_server", "ssl_minimal_tls_version_enforced"): "TLS1_2",
    ("azurerm_cosmosdb_account", "capabilities"): [],
    ("azurerm_cosmosdb_account", "backup"): {
        "type": "Periodic",
        "interval_in_minutes": 240,
        "retention_in_hours": 8,
    },
    ("azurerm_app_configuration", "encryption"): {},
    ("azurerm_app_service_plan", "sku"): {"tier": "Standard", "size": "S1"},
    ("azurerm_monitor_log_profile", "locations"): [],
    ("azurerm_monitor_log_profile", "categories"): [],
    ("azurerm_monitor_diagnostic_setting", "log"): [],
    ("azurerm_monitor_diagnostic_setting", "metric"): [],
    ("azurerm_network_security_group", "security_rule"): [],
    ("azurerm_virtual_network", "ddos_protection_plan"): {"id": ""},
    ("azurerm_public_ip", "sku"): {"name": "Standard", "tier": "Regional"},
    ("azurerm_network_watcher_flow_log", "retention_policy"): {"enabled": True, "days": 7},
    ("azurerm_redis_cache", "redis_configuration"): {
        "enable_authentication": True,
        "maxmemory_policy": "allkeys-lru",
    },
    ("azurerm_redis_cache", "minimum_tls_version"): "1.2",
    ("azurerm_container_registry", "network_rule_set"): {
        "default_action": "Deny",
    },
    ("azurerm_container_registry", "trust_policy"): {"enabled": True},
    ("azurerm_kubernetes_cluster", "default_node_pool"): {
        "vm_size": "Standard_DS2_v2",
        "min_count": 1,
        "max_count": 3,
    },
    ("azurerm_kubernetes_cluster", "network_profile"): {
        "network_plugin": "azure",
        "network_policy": "calico",
    },
    ("azurerm_kubernetes_cluster", "identity"): {"type": "SystemAssigned"},
    ("azurerm_kubernetes_cluster", "azure_active_directory_role_based_access_control"): {
        "managed": True,
    },
    ("azurerm_log_analytics_workspace", "retention_in_days"): 90,
    ("azurerm_automation_account", "sku_name"): "Basic",
    ("azurerm_servicebus_namespace", "network_rule_set"): {
        "default_action": "Deny",
    },
    ("azurerm_eventhub_namespace", "network_rulesets"): {
        "default_action": "Deny",
    },
    ("azurerm_data_factory", "github_configuration"): {},
    ("azurerm_data_factory", "identity"): {"type": "SystemAssigned"},
    ("azurerm_databricks_workspace", "custom_parameters"): {
        "no_public_ip": True,
    },
    ("azurerm_synapse_workspace", "sql_administrator_login"): "TODO-fill-in",
    ("azurerm_synapse_workspace", "sql_administrator_login_password"): "TODO-fill-in",
    ("azurerm_synapse_workspace", "aad_admin"): {
        "login": "TODO-fill-in",
        "object_id": "TODO-fill-in",
        "tenant_id": "TODO-fill-in",
    },
    # Provider-level defaults for provider "azurerm" {} blocks.
    ("azurerm", "features"): {},
    ("azurerm", "subscription_id"): "",
    ("azurerm", "tenant_id"): "",
    # Generic tag-only controls can apply to any AzureRM resource.
    ("*", "tags"): {},
}


# Multiple Azure Terraform providers exist: azurerm, azapi, azuread, azurestack.
# Register one family with all relevant prefixes so controls for any Azure
# provider can benefit from the same defaults where applicable.
fix_provider_registry.register(
    FixProvider(
        name="terraform_azure",
        frameworks=["terraform"],
        providers=["azure", "azurerm", "azapi", "azuread", "azurestack"],
        block_defaults=_TERRAFORM_AZURE_BLOCK_DEFAULTS,
        resource_type_prefixes=["azurerm_", "azapi_", "azuread_", "azurestack_"],
        provider_block_types=["azurerm", "azapi", "azuread", "azurestack"],
    )
)
