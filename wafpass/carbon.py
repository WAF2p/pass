"""Carbon footprint estimator for WAF++ PASS.

Estimates monthly cloud infrastructure CO2 emissions from the parsed IaC state
using:

1. A resource-type power lookup table (Watts per running instance)
2. Per-region grid emission factors (kgCO2e / kWh)
3. Monthly hours (730 h/month)
4. An optional waste multiplier derived from failing WAF-COST controls
   (rightsizing, lifecycle, commitment) — unoptimised workloads consume more
   energy than necessary.

All figures are *estimates* for directional guidance. Actual cloud footprint
depends on real workload, provider-specific renewable energy purchases (RECs),
and hardware utilisation rates that are not visible in static IaC.

Data sources
------------
- Grid carbon intensity: IEA 2023 electricity emissions + AWS/Azure/GCP carbon
  reports; U.S. eGRID 2022; European Environment Agency 2022.
- Instance power: SPECpower, Teads Engineering estimates, Cloud Carbon Footprint
  project (https://www.cloudcarbonfootprint.org/).
- Equivalences: EPA GHG equivalencies calculator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from wafpass.iac.base import IaCBlock, IaCState
from wafpass.models import Report

# ── Region grid emission factors (kgCO2e / kWh) ──────────────────────────────
# Sources: IEA 2023, EEA 2022, eGRID 2022, AWS/Azure/GCP carbon data

REGION_CARBON_INTENSITY: dict[str, float] = {
    # AWS — Europe
    "eu-central-1":   0.338,   # Germany (Frankfurt)
    "eu-central-2":   0.029,   # Switzerland (Zurich) — mostly hydro
    "eu-west-1":      0.316,   # Ireland (Dublin)
    "eu-west-2":      0.233,   # UK (London)
    "eu-west-3":      0.052,   # France (Paris) — nuclear-heavy
    "eu-south-1":     0.233,   # Italy (Milan)
    "eu-south-2":     0.165,   # Spain (Madrid)
    "eu-north-1":     0.008,   # Sweden (Stockholm) — hydro + nuclear
    # AWS — North America
    "us-east-1":      0.415,   # Virginia (N. Virginia)
    "us-east-2":      0.410,   # Ohio (Columbus)
    "us-west-1":      0.274,   # California (N. California)
    "us-west-2":      0.136,   # Oregon (Portland) — hydro-heavy
    "ca-central-1":   0.130,   # Canada (Montreal)
    "ca-west-1":      0.016,   # Canada (Calgary)
    # AWS — Asia Pacific
    "ap-east-1":      0.710,   # Hong Kong
    "ap-south-1":     0.708,   # India (Mumbai) — coal-heavy
    "ap-south-2":     0.708,   # India (Hyderabad)
    "ap-southeast-1": 0.431,   # Singapore
    "ap-southeast-2": 0.610,   # Australia (Sydney)
    "ap-southeast-3": 0.760,   # Indonesia (Jakarta)
    "ap-northeast-1": 0.453,   # Japan (Tokyo)
    "ap-northeast-2": 0.415,   # South Korea (Seoul)
    "ap-northeast-3": 0.453,   # Japan (Osaka)
    # AWS — Middle East & Africa
    "me-south-1":     0.700,   # Bahrain
    "me-central-1":   0.700,   # UAE (Dubai)
    "af-south-1":     0.900,   # South Africa (Cape Town)
    # AWS — South America
    "sa-east-1":      0.074,   # Brazil (São Paulo) — hydro
    # Azure — selected
    "northeurope":    0.316,
    "westeurope":     0.338,
    "germanywestcentral": 0.338,
    "francecentral":  0.052,
    "uksouth":        0.233,
    "swedencentral":  0.008,
    "eastus":         0.415,
    "westus2":        0.136,
    "australiaeast":  0.610,
    "southeastasia":  0.431,
    # GCP — selected
    "europe-west1":   0.052,   # Belgium — wind
    "europe-west4":   0.338,   # Netherlands
    "us-central1":    0.410,
    "us-east1":       0.415,
    "us-west1":       0.136,
    "asia-east1":     0.710,   # Taiwan
    "asia-southeast1": 0.431,
}

_DEFAULT_INTENSITY = 0.400   # global average fallback

# Greenest-region reference for "what if" comparison
_GREENEST_REGION = "eu-north-1"
_GREENEST_LABEL  = "eu-north-1 (Sweden)"
_GREENEST_INTENSITY = REGION_CARBON_INTENSITY["eu-north-1"]

# ── Resource type power lookup (Watts per running instance) ───────────────────
# Based on Cloud Carbon Footprint project + SPECpower data.
# Values represent typical idle-to-moderate utilisation.

_RESOURCE_WATTS: dict[str, float] = {
    # ── Compute ───────────────────────────────────────────────────────────────
    "aws_instance":                        18.0,   # EC2 instance (t3.large equivalent)
    "aws_launch_template":                  0.0,   # template only, no running resource
    "aws_launch_configuration":             0.0,
    "aws_autoscaling_group":               18.0,   # assume 1 instance base
    # ── EKS ───────────────────────────────────────────────────────────────────
    "aws_eks_cluster":                     12.0,   # control plane overhead
    "aws_eks_node_group":                  18.0,   # per node group (1 node assumed)
    # ── Lambda ────────────────────────────────────────────────────────────────
    "aws_lambda_function":                  2.0,   # very low — invocation-based
    # ── RDS / Aurora ──────────────────────────────────────────────────────────
    "aws_db_instance":                     25.0,   # RDS instance
    "aws_db_cluster":                      50.0,   # Aurora cluster (2 AZs)
    "aws_db_cluster_instance":             20.0,   # per Aurora instance
    # ── DynamoDB ──────────────────────────────────────────────────────────────
    "aws_dynamodb_table":                   4.0,   # very managed, low power
    # ── ElastiCache ───────────────────────────────────────────────────────────
    "aws_elasticache_cluster":             12.0,
    "aws_elasticache_replication_group":   20.0,
    # ── Kinesis ───────────────────────────────────────────────────────────────
    "aws_kinesis_stream":                   5.0,
    "aws_kinesis_firehose_delivery_stream": 3.0,
    # ── S3 ────────────────────────────────────────────────────────────────────
    "aws_s3_bucket":                        2.0,   # per bucket (storage power is volume-based; this is control-plane)
    # ── Load Balancers ────────────────────────────────────────────────────────
    "aws_lb":                              10.0,
    "aws_alb":                             10.0,
    "aws_elb":                              8.0,
    # ── Networking ────────────────────────────────────────────────────────────
    "aws_vpc":                              0.5,
    "aws_nat_gateway":                      5.0,
    "aws_internet_gateway":                 1.0,
    "aws_vpn_gateway":                      3.0,
    "aws_transit_gateway":                  8.0,
    # ── Monitoring ────────────────────────────────────────────────────────────
    "aws_cloudwatch_log_group":             0.5,
    "aws_cloudwatch_metric_alarm":          0.2,
    "aws_cloudtrail":                       1.0,
    "aws_config_configuration_recorder":    0.5,
    # ── IAM / Security ────────────────────────────────────────────────────────
    "aws_iam_role":                         0.0,   # metadata only
    "aws_iam_policy":                       0.0,
    "aws_kms_key":                          0.5,
    "aws_secretsmanager_secret":            0.3,
    "aws_wafv2_web_acl":                    2.0,
    # ── Containers ────────────────────────────────────────────────────────────
    "aws_ecs_cluster":                      5.0,
    "aws_ecs_service":                     10.0,
    # ── SNS / SQS ─────────────────────────────────────────────────────────────
    "aws_sns_topic":                        0.3,
    "aws_sqs_queue":                        0.3,
    # ── CDN / DNS ─────────────────────────────────────────────────────────────
    "aws_cloudfront_distribution":          5.0,
    "aws_route53_zone":                     0.5,
    # ── Azure equivalents ─────────────────────────────────────────────────────
    "azurerm_virtual_machine":             18.0,
    "azurerm_linux_virtual_machine":       18.0,
    "azurerm_windows_virtual_machine":     22.0,
    "azurerm_kubernetes_cluster":          30.0,
    "azurerm_sql_database":                20.0,
    "azurerm_postgresql_server":           20.0,
    "azurerm_cosmosdb_account":            15.0,
    "azurerm_storage_account":              2.0,
    "azurerm_function_app":                 2.0,
    # ── GCP equivalents ───────────────────────────────────────────────────────
    "google_compute_instance":             18.0,
    "google_container_cluster":            30.0,
    "google_sql_database_instance":        20.0,
    "google_storage_bucket":               2.0,
    "google_cloudfunctions_function":       2.0,
    "google_bigtable_instance":            10.0,
    "google_bigquery_dataset":              4.0,
}

_HOURS_PER_MONTH = 730.0   # average hours in a month

# ── WAF-COST control IDs that indicate over-provisioning / waste ──────────────
# If these controls FAIL, we apply a waste multiplier to the footprint estimate.
_WASTE_CONTROL_IDS = {
    "WAF-COST-030",   # rightsizing not reviewed
    "WAF-COST-040",   # storage & retention lifecycle undefined
    "WAF-COST-060",   # FinOps review cadence missing
    "WAF-COST-070",   # observability cost tier not set
    "WAF-COST-080",   # no reserved capacity / commitment
}
_WASTE_MULTIPLIER = 1.25   # 25 % over-consumption estimate for unoptimised infra

# ── Real-world equivalences ───────────────────────────────────────────────────
# Source: EPA GHG equivalencies calculator (2023)
_KG_CO2_PER_MILE_CAR        = 0.404   # average passenger vehicle per mile
_KG_CO2_PER_TREE_YEAR       = 21.77   # CO2 absorbed per tree per year
_KG_CO2_PER_SMARTPHONE_CHARGE = 0.0082  # per charge cycle
_KG_CO2_PER_FLIGHT_HOUR     = 90.0    # economy seat per flight hour (shorthaul)


# ── Result types ──────────────────────────────────────────────────────────────

class ResourceFootprint(NamedTuple):
    resource_type: str
    count: int
    watts_each: float
    monthly_kwh: float
    monthly_co2e_kg: float


@dataclass
class CarbonResult:
    """Full carbon footprint analysis result."""

    # Core metrics
    total_monthly_kwh: float
    total_monthly_co2e_kg: float
    total_annual_co2e_kg: float

    # Per-resource breakdown
    breakdown: list[ResourceFootprint]

    # Region info
    detected_regions: list[tuple[str, str]]   # [(provider, region), …]
    primary_region: str
    primary_intensity: float                  # kgCO2e/kWh
    greenest_region_label: str
    greenest_intensity: float
    greenest_monthly_co2e_kg: float           # what footprint would be in greenest region
    savings_vs_greenest_kg: float

    # Waste factor
    waste_applied: bool
    waste_multiplier: float
    baseline_co2e_kg: float                   # before waste multiplier
    waste_co2e_kg: float                      # extra CO2 from unoptimised infra

    # Equivalences (monthly)
    eq_car_miles: float
    eq_trees_needed: float                    # trees needed to offset annual footprint
    eq_smartphone_charges: float
    eq_flight_hours: float

    # Optimisation potential
    savings_if_optimised_kg: float            # CO2 saved by fixing waste controls
    savings_if_greenest_kg: float             # CO2 saved by moving to greenest region


# ── Helpers ───────────────────────────────────────────────────────────────────

_PREFERRED_PROVIDERS = {"aws", "azurerm", "google", "azure"}


def _detect_primary_region(detected_regions: list[tuple[str, str]]) -> str:
    """Pick the most representative region from the detected list.

    Each entry in *detected_regions* is a ``(region_name, provider)`` tuple
    (the same format used by ``IaCPlugin.extract_regions()`` and stored on
    :class:`Report.detected_regions <wafpass.models.Report>`).

    Preference order:
    1. First entry from a major provider (AWS / Azure / GCP) whose region is
       present in the carbon intensity lookup table.
    2. First entry from any provider that is in the lookup table.
    3. First entry from a major provider (even if the region is unknown).
    4. Fall back to the first entry's region string.
    """
    if not detected_regions:
        return "eu-central-1"

    # 1. Prefer major provider + known region
    for region, provider in detected_regions:
        if provider.lower() in _PREFERRED_PROVIDERS and region in REGION_CARBON_INTENSITY:
            return region

    # 2. Any known region
    for region, _provider in detected_regions:
        if region in REGION_CARBON_INTENSITY:
            return region

    # 3. Major provider fallback
    for region, provider in detected_regions:
        if provider.lower() in _PREFERRED_PROVIDERS:
            return region

    return detected_regions[0][0]


def _count_resources(state: IaCState) -> dict[str, int]:
    """Count resource instances by type."""
    counts: dict[str, int] = {}
    for block in state.resources:
        counts[block.type] = counts.get(block.type, 0) + 1
    return counts


def _has_waste_controls_failing(report: Report) -> bool:
    """Return True if any waste-relevant WAF-COST controls failed."""
    for cr in report.results:
        if cr.control.id in _WASTE_CONTROL_IDS and cr.status == "FAIL":
            return True
    return False


# ── Main analysis ─────────────────────────────────────────────────────────────

def compute_carbon(
    state: IaCState,
    report: Report,
    detected_regions: list[tuple[str, str]],
) -> CarbonResult:
    """Compute the estimated monthly carbon footprint of the IaC infrastructure.

    Args:
        state:            Parsed IaC state (resources list used for power lookup).
        report:           WAF++ check report (used to detect waste-control failures).
        detected_regions: List of ``(provider, region)`` tuples from the IaC parser.

    Returns:
        :class:`CarbonResult` with full breakdown and equivalences.
    """
    counts = _count_resources(state)
    primary_region = _detect_primary_region(detected_regions)
    intensity = REGION_CARBON_INTENSITY.get(primary_region, _DEFAULT_INTENSITY)

    # ── Per-type footprint ────────────────────────────────────────────────────
    breakdown: list[ResourceFootprint] = []
    total_watts = 0.0

    for rtype, count in sorted(counts.items()):
        watts = _RESOURCE_WATTS.get(rtype, 0.0)
        if watts == 0.0:
            continue
        monthly_kwh = watts * count * _HOURS_PER_MONTH / 1000.0
        monthly_co2e = monthly_kwh * intensity
        breakdown.append(ResourceFootprint(
            resource_type=rtype,
            count=count,
            watts_each=watts,
            monthly_kwh=monthly_kwh,
            monthly_co2e_kg=monthly_co2e,
        ))
        total_watts += watts * count

    breakdown.sort(key=lambda r: r.monthly_co2e_kg, reverse=True)

    total_monthly_kwh = total_watts * _HOURS_PER_MONTH / 1000.0
    baseline_co2e = total_monthly_kwh * intensity

    # ── Waste multiplier ──────────────────────────────────────────────────────
    waste_applied = _has_waste_controls_failing(report)
    multiplier = _WASTE_MULTIPLIER if waste_applied else 1.0
    total_monthly_co2e = baseline_co2e * multiplier
    waste_co2e = total_monthly_co2e - baseline_co2e

    # ── Greenest region comparison ────────────────────────────────────────────
    greenest_monthly = total_monthly_kwh * _GREENEST_INTENSITY
    savings_vs_greenest = total_monthly_co2e - greenest_monthly

    # ── Equivalences (monthly) ────────────────────────────────────────────────
    eq_car_miles = total_monthly_co2e / _KG_CO2_PER_MILE_CAR
    eq_trees_year = (total_monthly_co2e * 12) / _KG_CO2_PER_TREE_YEAR
    eq_phones = total_monthly_co2e / _KG_CO2_PER_SMARTPHONE_CHARGE
    eq_flight_h = total_monthly_co2e / _KG_CO2_PER_FLIGHT_HOUR

    return CarbonResult(
        total_monthly_kwh=total_monthly_kwh,
        total_monthly_co2e_kg=total_monthly_co2e,
        total_annual_co2e_kg=total_monthly_co2e * 12,
        breakdown=breakdown,
        detected_regions=detected_regions,
        primary_region=primary_region,
        primary_intensity=intensity,
        greenest_region_label=_GREENEST_LABEL,
        greenest_intensity=_GREENEST_INTENSITY,
        greenest_monthly_co2e_kg=greenest_monthly,
        savings_vs_greenest_kg=max(0.0, savings_vs_greenest),
        waste_applied=waste_applied,
        waste_multiplier=multiplier,
        baseline_co2e_kg=baseline_co2e,
        waste_co2e_kg=waste_co2e,
        eq_car_miles=eq_car_miles,
        eq_trees_needed=eq_trees_year,
        eq_smartphone_charges=eq_phones,
        eq_flight_hours=eq_flight_h,
        savings_if_optimised_kg=waste_co2e,
        savings_if_greenest_kg=max(0.0, savings_vs_greenest),
    )
