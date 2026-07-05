"""Parse ``terraform show -json <plan>`` output into a compact change summary.

The canonical way to produce the input file is::

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    wafpass check --plan-file plan.json ...

The parser also tolerates the streaming log format produced by
``terraform plan -json`` (newline-delimited JSON objects) by picking up
every ``change_summary`` event and ``planned_change`` action events.

The normalised output schema is::

    {
      "terraform_version": "1.7.0",
      "format_version":    "1.2",
      "scanned_at":        "2026-03-28T12:00:00Z",
      "summary": {
        "add":     3,
        "change":  2,
        "destroy": 0,
        "replace": 1,
        "no_op":   45
      },
      "changes": [
        {
          "address":        "aws_s3_bucket.logs",
          "module_address": null,
          "type":           "aws_s3_bucket",
          "name":           "logs",
          "provider":       "aws",
          "action":         "create"   // create | update | delete | replace | no-op
        }
      ],
      "by_provider": {
        "aws":      {"add": 2, "change": 1, "destroy": 0, "replace": 1},
        "azurerm":  {"add": 1, "change": 0, "destroy": 0, "replace": 0},
        ...
      },
      "by_action": {
        "create":   [{"address": "...", "type": "...", "provider": "..."}],
        "update":   [...],
        "delete":   [...],
        "replace":  [...]
      },
      "regions": ["us-east-1", "eu-central-1", ...],
      "provider_insights": {
        "aws": {
          "resource_types": {"s3_bucket": 3, "ec2_instance": 2},
          "estimated_cost_impact": "low|medium|high"
        }
      }
    }
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any



_ACTION_MAP: dict[tuple[str, ...], str] = {
    ("no-op",):           "no-op",
    ("create",):          "create",
    ("update",):          "update",
    ("delete",):          "delete",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}


def _normalise_actions(actions: list[str]) -> str:
    key = tuple(a.lower() for a in actions)
    return _ACTION_MAP.get(key, actions[0] if actions else "unknown")


def _provider_short(provider_name: str) -> str:
    """'registry.terraform.io/hashicorp/aws' → 'aws'"""
    return provider_name.rstrip("/").rsplit("/", 1)[-1] if provider_name else ""


def _resource_type_to_name(res_type: str) -> str:
    """'aws_s3_bucket' → 's3_bucket'"""
    return res_type.split("_", 1)[-1] if res_type and "_" in res_type else res_type


# ── Cloud provider cost factors (relative, arbitrary units) ───────────────────

_COST_FACTORS: dict[str, float] = {
    # AWS
    "s3_bucket":          0.5,    # very low cost
    "s3_object":          0.1,
    "ec2_instance":       50,     # medium - depends on instance type
    "ec2_security_group": 1,
    "ec2_vpc":            10,
    "ec2_subnet":         2,
    "ec2_route_table":    1,
    "ec2_internet_gateway": 1,
    "ec2_nat_gateway":    20,     # high cost
    "elasticip":          5,      # medium - if not attached
    "iam_role":           0.1,
    "iam_policy":         0.1,
    "lambda_function":    5,      # low-medium based on usage
    "cloudwatch_log_group": 1,
    "kms_key":            10,     # medium
    "secretsmanager_secret": 1,
    "rds_instance":       100,    # high - database
    "rds_snapshot":       50,
    "elasticloadbalancing": 20,
    "api_gateway":        30,
    "cloudfront_distribution": 10,
    "eks_cluster":        100,    # high - EKS control plane
    "eks_node_group":     50,     # depends on node count
    "dynamodb_table":     50,     # medium-high
    "elasticache_cluster": 30,
    "acm_certificate":    1,
    "route53_zone":       1,
    "sqs_queue":          0.5,
    "sns_topic":          0.5,
    "firehose_delivery_stream": 20,
    "glacier_vault":      5,
    "opensearch_domain":  50,
    "datasync_task":      10,
    "transfer_server":    20,
    "workspaces_workspace": 50,
    # Azure
    "azurerm_resource_group": 1,
    "azurerm_virtual_network": 10,
    "azurerm_subnet":         2,
    "azurerm_network_security_group": 1,
    "azurerm_linux_virtual_machine": 50,
    "azurerm_windows_virtual_machine": 50,
    "azurerm_storage_account": 5,
    "azurerm_storage_blob":    0.5,
    "azurerm_storage_queue":   0.5,
    "azurerm_sql_database":    100,
    "azurerm_app_service":     30,
    "azurerm_application_insights": 10,
    "azurerm_key_vault":       10,
    "azurerm_key_vault_secret": 0.5,
    "azurerm_function_app":    15,
    "azurerm_container_registry": 20,
    "azurerm_cosmosdb_account": 80,
    "azurerm_managed_disk":    10,
    "azurerm_public_ip":       5,
    "azurerm_lb":              20,
    "azurerm_dns_zone":        1,
    "azurerm_log_analytics_workspace": 30,
    # GCP
    "google_compute_instance":         50,
    "google_compute_disk":             10,
    "google_compute_firewall":         1,
    "google_compute_network":          10,
    "google_compute_subnetwork":       2,
    "google_compute_route":            1,
    "google_compute_address":          5,
    "google_compute_region_backend_service": 20,
    "google_compute_global_address":   1,
    "google_project_service":          1,
    "google_storage_bucket":           0.5,
    "google_storage_bucket_object":    0.1,
    "google_sql_database":             100,
    "google_compute_autoscaler":       5,
    "google_container_cluster":        100,
    "google_container_node_pool":      50,
    "google_bigquery_dataset":         10,
    "google_bigquery_table":           10,
    "google_pubsub_topic":             1,
    "google_pubsub_subscription":      0.5,
    "google_iap_tunnel":               1,
    "google_kms_key_ring":             5,
    "google_kms_crypto_key":           10,
    "google_dataproc_cluster":         80,
    "google_apigee_organization":      100,
    # Oracle Cloud
    "oci_core_instance":               50,
    "oci_core_volume":                 10,
    "oci_core_vcn":                    10,
    "oci_core_subnet":                 2,
    "oci_core_security_list":          1,
    "oci_core_route_table":            1,
    "oci_core_internet_gateway":       1,
    "oci_core_nat_gateway":            20,
    "oci_core_service_gateway":        1,
    "oci_database_db_system":          150,
    "oci_database_autonomous_database": 100,
    "oci_objectstorage_bucket":        0.5,
    "oci_load_balancer":               30,
    "oci_dns_zone":                    1,
    "oci_core_virtual_network_gateway": 50,
    # Alibaba Cloud
    "alicloud_instance":               50,
    "alicloud_disk":                   10,
    "alicloud_vpc":                    10,
    "alicloud_vswitch":                2,
    "alicloud_security_group":         1,
    "alicloud_route_table":            1,
    "alicloud_route_table_association": 1,
    "alicloud_ess_scaling_configuration": 1,
    "alicloud_ess_scaling_group":      5,
    "alicloud_ess_scaling_rule":       1,
    "alicloud_oss_bucket":             0.5,
    "alicloud_oss_bucket_object":      0.1,
    "alicloud_rds_instance":           100,
    "alicloud_slb":                    30,
    "alicloud_slb_listener":           5,
    "alicloud_alidns_domain":          1,
    "alicloud_alidns_record":          0.1,
    "alicloud_table_store_table":      10,
    "alicloud_api_gateway_service":    30,
    # Yandex Cloud
    "yandex_compute_instance":         50,
    "yandex_compute_disk":             10,
    "yandex_vpc_network":              10,
    "yandex_vpc_subnet":               2,
    "yandex_vpc_security_group":       1,
    "yandex_vpc_route_table":          1,
    "yandex_container_registry":       10,
    "yandex_container_repository":     5,
    "yandex_mdb_mysql_cluster":        100,
    "yandex_mdb_postgresql_cluster":   100,
    "yandex_mdb_redis_cluster":        50,
    "yandex_compute_instance_group":   30,
    "yandex_load_balancer":            30,
    "yandex_vpc_gateway":              20,
    "yandex_iam_service_account":      1,
    "yandex_storage_bucket":           0.5,
    # OVH / Cloud providers
    "ovh_cloud_project_keystone":      1,
    "ovh_cloud_project_database":      100,
    "ovh_public_cloud":                50,
    "ovh_vps":                         30,
    "ovh_dedicated_server":            100,
    # Hetzner
    "hcloud_server":                   50,
    "hcloud_volume":                   10,
    "hcloud_network":                  10,
    "hcloud_firewall":                 1,
    "hcloud_load_balancer":            30,
    "hcloud_dns_zone":                 1,
    "hcloud_ssh_key":                  0.1,
    # Hetzner (with provider name prefix)
    "hetzner_server":                  50,
    "hetzner_volume":                  10,
    "hetzner_network":                 10,
    "hetzner_firewall":                1,
    # Cleura
    "cleura_server":                   50,
    "cleura_volume":                   10,
    "cleura_network":                  10,
    "cleura_firewall":                 1,
    # StackIT
    "stackit_compute_instance":        50,
    "stackit_compute_volume":          10,
    "stackit_compute_keypair":         0.1,
    "stackit_rds_instance":            100,
    "stackit_rds_cluster":             150,
    "stackit_dns_zone":                1,
    "stackit_loadbalancer":            30,
    # Infomaniak
    "infomaniak_server":               50,
    "infomaniak_volume":               10,
    "infomaniak_network":              10,
    "infomaniak_firewall":             1,
    "infomaniak_database":             100,
    # Leafcloud
    "leafcloud_server":                50,
    "leafcloud_volume":                10,
    "leafcloud_network":               10,
    "leafcloud_firewall":              1,
    "leafcloud_database":              100,
    # T Cloud Public
    "tcloud_server":                   50,
    "tcloud_volume":                   10,
    "tcloud_network":                  10,
    "tcloud_firewall":                 1,
    # Seeweb
    "seeweb_server":                   50,
    "seeweb_volume":                   10,
    "seeweb_network":                  10,
    "seeweb_firewall":                 1,
    # Exoscale
    "exoscale_compute_instance":       50,
    "exoscale_volume":                 10,
    "exoscale_network":                10,
    "exoscale_firewall":               1,
    "exoscale_database":               100,
    "exoscale_object_bucket":          0.5,
    # Cyso
    "cyso_server":                     50,
    "cyso_volume":                     10,
    "cyso_network":                    10,
    "cyso_firewall":                   1,
    # Numspot
    "numspot_server":                  50,
    "numspot_volume":                  10,
    "numspot_network":                 10,
    "numspot_firewall":                1,
    # plusserver
    "plusserver_server":               50,
    "plusserver_volume":               10,
    "plusserver_network":              10,
    "plusserver_firewall":             1,
    # SysEleven
    "syselev_server":                  50,
    "syselev_volume":                  10,
    "syselev_network":                 10,
    "syselev_firewall":                1,
    # Outscale
    "outscale_compute_instance":       50,
    "outscale_volume":                 10,
    "outscale_network":                10,
    "outscale_firewall":               1,
    "outscale_database":               100,
    # Leaseweb
    "leaseweb_server":               50,
    "leaseweb_volume":               10,
    "leaseweb_network":              10,
    "leaseweb_firewall":             1,
    # Scaleway
    "scaleway_instance_server":        50,
    "scaleway_instance_ip":            5,
    "scaleway_instance_volume":        10,
    "scaleway_instance_security_group": 1,
    "scaleway_database":               100,
    "scaleway_object_bucket":          0.5,
    "scaleway_kubernetes_cluster":     100,
    # IONOS
    "ionos_compute_instance":          50,
    "ionos_compute_volume":            10,
    "ionos_network":                   10,
    "ionos_firewall":                  1,
    "ionos_database":                  100,
    "ionos_loadbalancer":              30,
    # UpCloud
    "upcloud_compute_instance":        50,
    "upcloud_storage":                 10,
    "upcloud_network":                 10,
    "upcloud_firewall":                1,
    "upcloud_database":                100,
    "upcloud_kubernetes_cluster":      100,
    # OpenStack (common resources)
    "openstack_compute_instance":      50,
    "openstack_compute_volume":        10,
    "openstack_compute_server_group":  1,
    "openstack_networking_network":    10,
    "openstack_networking_subnet":     2,
    "openstack_networking_router":     20,
    "openstack_compute_keypair":       0.1,
    "openstack_compute_security_group": 1,
    "openstack_blockstorage_volume":   10,
    "openstack_objectstore_container": 0.5,
}


def _estimate_cost_impact(provider: str, resource_type: str) -> str:
    """Estimate cost impact based on resource type."""
    key = resource_type.lower()
    factor = _COST_FACTORS.get(key, 10)

    if factor < 1:
        return "negligible"
    elif factor < 5:
        return "low"
    elif factor < 20:
        return "low-medium"
    elif factor < 50:
        return "medium"
    elif factor < 100:
        return "medium-high"
    else:
        return "high"


# ── Plan parsing helpers ──────────────────────────────────────────────────────

def _parse_structured(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a ``terraform show -json`` structured plan object."""
    changes: list[dict[str, Any]] = []
    summary: dict[str, int] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}

    # Track provider statistics
    by_provider: dict[str, dict[str, int]] = {}
    by_action: dict[str, list[dict[str, Any]]] = {
        "create": [], "update": [], "delete": [], "replace": [], "no-op": []
    }
    regions: set[str] = set()
    resource_types: dict[str, dict[str, int]] = {}  # provider -> {type: count}

    for rc in data.get("resource_changes", []):
        change = rc.get("change", {})
        actions: list[str] = change.get("actions", ["no-op"])
        action = _normalise_actions(actions)

        provider = _provider_short(rc.get("provider_name", ""))
        res_type = rc.get("type", "")
        res_name = rc.get("name", "")

        # Track resource type per provider
        if provider not in resource_types:
            resource_types[provider] = {}
        type_name = _resource_type_to_name(res_type)
        resource_types[provider][type_name] = resource_types[provider].get(type_name, 0) + 1

        # Track regions if available in attributes
        after = change.get("after", {})
        if isinstance(after, dict):
            for attr in ("region", "location", "zone", "availability_zone"):
                region = after.get(attr)
                if isinstance(region, str) and region:
                    regions.add(region)

        entry: dict[str, Any] = {
            "address":        rc.get("address", ""),
            "module_address": rc.get("module_address"),
            "type":           res_type,
            "name":           res_name,
            "provider":       provider,
            "action":         action,
            "after":          after,
        }
        changes.append(entry)

        # Update summary
        if action == "no-op":
            summary["no_op"] += 1
        elif action == "create":
            summary["add"] += 1
        elif action == "update":
            summary["change"] += 1
        elif action == "delete":
            summary["destroy"] += 1
        elif action == "replace":
            summary["replace"] += 1

        # Update by_provider
        if provider not in by_provider:
            by_provider[provider] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}
        if action != "no-op":
            by_provider[provider][action] += 1

        # Update by_action (excluding no-op)
        if action != "no-op":
            by_action[action].append({
                "address": entry["address"],
                "type": res_type,
                "name": res_name,
                "provider": provider,
            })

    # Build provider insights
    provider_insights: dict[str, dict[str, Any]] = {}
    for provider, types in resource_types.items():
        if provider not in provider_insights:
            provider_insights[provider] = {"resource_types": types}

        # Estimate cost impact
        total_cost = 0
        for res_type, count in types.items():
            key = res_type.lower()
            factor = _COST_FACTORS.get(key, 10)
            total_cost += factor * count

        if total_cost < 10:
            cost_impact = "negligible"
        elif total_cost < 50:
            cost_impact = "low"
        elif total_cost < 150:
            cost_impact = "low-medium"
        elif total_cost < 400:
            cost_impact = "medium"
        elif total_cost < 800:
            cost_impact = "medium-high"
        else:
            cost_impact = "high"

        provider_insights[provider]["estimated_cost_impact"] = cost_impact
        provider_insights[provider]["total_resources"] = sum(types.values())

    return {
        "terraform_version": data.get("terraform_version", ""),
        "format_version":    data.get("format_version", ""),
        "scanned_at":        datetime.now(timezone.utc).isoformat(),
        "summary":           summary,
        "changes":           [c for c in changes if c["action"] != "no-op"],
        "by_provider":       {k: v for k, v in by_provider.items() if v["add"] + v["change"] + v["destroy"] + v["replace"] > 0},
        "by_action":         {k: v for k, v in by_action.items() if v},
        "regions":           sorted(regions),
        "provider_insights": provider_insights,
    }


def _parse_streaming(lines: list[str]) -> dict[str, Any]:
    """Parse newline-delimited JSON produced by ``terraform plan -json``."""
    changes: list[dict[str, Any]] = []
    summary: dict[str, int] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}
    tf_version = ""

    # Track provider statistics
    by_provider: dict[str, dict[str, int]] = {}
    by_action: dict[str, list[dict[str, Any]]] = {
        "create": [], "update": [], "delete": [], "replace": [], "no-op": []
    }
    regions: set[str] = set()
    resource_types: dict[str, dict[str, int]] = {}  # provider -> {type: count}

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_type = obj.get("type", "")

        if msg_type == "version":
            tf_version = obj.get("terraform", "")

        elif msg_type == "planned_change":
            change = obj.get("change", {})
            action = change.get("action", "no-op").lower()
            resource = change.get("resource", {})
            addr = resource.get("addr", "")
            res_type = resource.get("resource_type", "")
            res_name = resource.get("resource_name", "")
            module = resource.get("module", "")

            # Map streaming action strings to normalised names
            action_map = {
                "no-op":   "no-op",
                "add":     "create",
                "change":  "update",
                "remove":  "delete",
                "replace": "replace",
            }
            normalised = action_map.get(action, action)

            # Determine provider from resource type
            provider = ""
            if res_type and "_" in res_type:
                provider = res_type.split("_", 1)[0]

            # Track resource type per provider
            if provider not in resource_types:
                resource_types[provider] = {}
            type_name = _resource_type_to_name(res_type)
            resource_types[provider][type_name] = resource_types[provider].get(type_name, 0) + 1

            # Try to extract region from resource attributes
            after = resource.get("after", {})
            if isinstance(after, dict):
                for attr in ("region", "location", "zone", "availability_zone"):
                    region = after.get(attr)
                    if isinstance(region, str) and region:
                        regions.add(region)

            entry: dict[str, Any] = {
                "address":        addr,
                "module_address": module or None,
                "type":           res_type,
                "name":           res_name,
                "provider":       provider,
                "action":         normalised,
            }
            changes.append(entry)

            # Update summary
            if normalised == "no-op":
                summary["no_op"] += 1
            elif normalised == "create":
                summary["add"] += 1
            elif normalised == "update":
                summary["change"] += 1
            elif normalised == "delete":
                summary["destroy"] += 1
            elif normalised == "replace":
                summary["replace"] += 1

            # Update by_provider
            if provider not in by_provider:
                by_provider[provider] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}
            if normalised != "no-op":
                by_provider[provider][normalised] += 1

            # Update by_action (excluding no-op)
            if normalised != "no-op":
                by_action[normalised].append({
                    "address": entry["address"],
                    "type": res_type,
                    "name": res_name,
                    "provider": provider,
                })

    # Build provider insights
    provider_insights: dict[str, dict[str, Any]] = {}
    for provider, types in resource_types.items():
        if not provider:
            continue
        if provider not in provider_insights:
            provider_insights[provider] = {"resource_types": types}

        # Estimate cost impact
        total_cost = 0
        for res_type, count in types.items():
            key = res_type.lower()
            factor = _COST_FACTORS.get(key, 10)
            total_cost += factor * count

        if total_cost < 10:
            cost_impact = "negligible"
        elif total_cost < 50:
            cost_impact = "low"
        elif total_cost < 150:
            cost_impact = "low-medium"
        elif total_cost < 400:
            cost_impact = "medium"
        elif total_cost < 800:
            cost_impact = "medium-high"
        else:
            cost_impact = "high"

        provider_insights[provider]["estimated_cost_impact"] = cost_impact
        provider_insights[provider]["total_resources"] = sum(types.values())

    return {
        "terraform_version": tf_version,
        "format_version":    "streaming",
        "scanned_at":        datetime.now(timezone.utc).isoformat(),
        "summary":           summary,
        "changes":           [c for c in changes if c["action"] != "no-op"],
        "by_provider":       {k: v for k, v in by_provider.items() if v["add"] + v["change"] + v["destroy"] + v["replace"] > 0},
        "by_action":         {k: v for k, v in by_action.items() if v},
        "regions":           sorted(regions),
        "provider_insights": provider_insights,
    }


def parse_plan_file(path: Path) -> dict[str, Any]:
    """Parse a terraform plan JSON file and return a normalised change summary.

    Accepts both:
    - ``terraform show -json <plan>``  → single structured JSON object
    - ``terraform plan -json``         → newline-delimited JSON stream

    Returns:
        Dict with the following structure:

        - ``summary``: Action counts (add, change, destroy, replace, no_op)
        - ``changes``: List of actual resource changes (excludes no-op)
        - ``by_provider``: Action counts broken down by provider
        - ``by_action``: Resources grouped by action type
        - ``regions``: List of detected cloud regions
        - ``provider_insights``: Cost impact and resource type breakdown per provider
        - ``terraform_version``: Version used to generate the plan
    """
    raw = path.read_text(encoding="utf-8")

    # Try single structured JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and ("resource_changes" in data or "format_version" in data):
            return _parse_structured(data)
    except json.JSONDecodeError:
        pass

    # Fall back to streaming format
    return _parse_streaming(raw.splitlines())
