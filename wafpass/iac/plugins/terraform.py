"""Terraform / HCL2 IaC plugin for WAF++ PASS.

This plugin parses Terraform ``.tf`` files using ``python-hcl2`` and exposes
the result as a generic :class:`~wafpass.iac.base.IaCState`.  It also handles
cloud-region detection across all providers supported by the WAF++ framework.

The plugin self-registers with the global registry when this module is imported.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import hcl2

from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState
from wafpass.iac.registry import registry

logger = logging.getLogger(__name__)


# ── Region extraction helpers ─────────────────────────────────────────────────

_AZ_RE = re.compile(r"^([a-z]{2}-[a-z]+-\d+)[a-z]$")
_REGION_IN_STRING_RE = re.compile(
    r"\b([a-z]{2}-(?:central|west|east|north|south|southeast|northeast|northwest|southwest)-\d+)\b"
)


def _is_literal_string(val: object) -> bool:
    """Return True if *val* is a plain string, not a Terraform expression."""
    if not isinstance(val, str):
        return False
    v = val.strip()
    return bool(v) and "${" not in v and not v.startswith("var.") and not v.startswith("local.")


def _region_from_az(val: str) -> str | None:
    """Return the AWS region from an AZ string, e.g. ``'eu-central-1a'`` → ``'eu-central-1'``."""
    m = _AZ_RE.match(val.strip())
    return m.group(1) if m else None


def _normalize_region_for_zone_grouping(region: str, provider: str) -> str:
    """Normalize region by stripping numeric zone suffixes for grouping.

    Some providers (like OpenStack/SINA Cloud, IONOS, UpCloud, OVH) use region names that
    include zone numbers (e.g., 'de-ham-1', 'de-fra-2', 'fi-hel1', 'gra2-ovh').
    This function strips those suffixes so all zones of the same region are grouped together.

    Args:
        region: The region name (may include zone suffix)
        provider: The cloud provider

    Returns:
        Normalized region name without zone suffix for grouping purposes
    """
    r = region.lower().strip()
    logger.debug("=== NORMALIZE DEBUG: input region=%s provider=%s", region, provider)

    # Providers that use numeric zone suffixes (region-N or regionN)
    # All zones of the same datacenter should be grouped under one region
    providers_with_numeric_zones = {
        "openstack", "sinacloud", "ionos", "upcloud", "hetzner", "cleura",
        "ovh", "infomaniak", "leafcloud", "tcloud", "seeweb", "exoscale",
        "cyso", "numspot", "plusserver", "syselev", "outscale", "leaseweb",
        "scaleway"
    }

    if provider not in providers_with_numeric_zones:
        logger.debug("=== NORMALIZE DEBUG: provider not in list, returning %s", region)
        return region

    # For providers that use "region-provider" format in region-data.ts,
    # we need to strip numeric suffixes but KEEP the provider suffix.

    # All providers with provider suffixes
    provider_suffixes = {"-ovh", "-infomaniak", "-leafcloud", "-tcloud", "-seeweb", "-exoscale",
                         "-cyso", "-numspot", "-plusserver", "-syselev", "-outscale", "-leaseweb",
                         "-stackit", "-sinacloud", "-upcloud", "-scaleway", "-ionos", "-hetzner", "-cleura"}

    # Strip provider suffix to get the base region for numeric suffix stripping
    for suffix in provider_suffixes:
        if r.endswith(suffix):
            r = r[:-len(suffix)]
            logger.debug("=== NORMALIZE DEBUG: stripped suffix %s, now r=%s", suffix, r)
            break

    # Pattern 1: region-1, region-2, region-3 (e.g., de-ham-1, de-fra-2)
    m = re.match(r"^(.+)-(\d+)$", r)
    if m:
        r = m.group(1)
        logger.debug("=== NORMALIZE DEBUG: Pattern 1 matched, now r=%s", r)

    # Pattern 2: region1, region2, region3 (e.g., fi-hel1, de-fra1)
    m = re.match(r"^(.+)(\d+)$", r)
    if m:
        base, num = m.groups()
        if base and base[-1].isalpha():
            r = base
            logger.debug("=== NORMALIZE DEBUG: Pattern 2 matched, now r=%s", r)

    # Re-add provider suffix
    provider_suffix_map = {
        "ovh": "-ovh", "infomaniak": "-infomaniak", "leafcloud": "-leafcloud",
        "tcloud": "-tcloud", "seeweb": "-seeweb", "exoscale": "-exoscale",
        "cyso": "-cyso", "numspot": "-numspot", "plusserver": "-plusserver",
        "syselev": "-syselev", "outscale": "-outscale", "leaseweb": "-leaseweb",
        "stackit": "-stackit", "sinacloud": "-sinacloud", "upcloud": "-upcloud",
        "scaleway": "-scaleway", "ionos": "-ionos", "hetzner": "-hetzner", "cleura": "-cleura"
    }

    if provider in provider_suffix_map and not r.endswith(provider_suffix_map[provider]):
        r = r + provider_suffix_map[provider]
        logger.debug("=== NORMALIZE DEBUG: re-added suffix, final r=%s", r)
    else:
        logger.debug("=== NORMALIZE DEBUG: suffix already present or provider not in map")

    return r


def _region_from_zone(val: str) -> str | None:
    """Return region from an Alibaba/Yandex zone string or region with provider suffix.

    Examples: ``'cn-hangzhou-b'`` → ``'cn-hangzhou'``, ``'ru-central1-a'`` → ``'ru-central1'``.
    Also handles provider suffixes: ``'par-1-scaleway'`` → ``'par-1'``, ``'de-fra-1-ionos'`` → ``'de-fra-1'``.
    Handles Azure-style: ``'westeurope'``, ``'northeurope'``, ``'germanywestcentral'``.
    Handles GCP-style: ``'europe-west1'``, ``'us-central1'``, ``'europe-central2'``.

    Returns ``None`` if *val* doesn't look like a zone/region identifier.
    """
    v = val.strip()

    # GCP multi-region values like EU, US, ASIA (uppercase)
    # These are valid GCP regions for sovereign/cloud-specific deployments
    if v in ("EU", "US", "ASIA"):
        return v

    # Azure-style regions like westeurope, northeurope, francecentral, germanywestcentral
    # Pattern: [direction][europe|north|south|central|west|east]+ (no digits)
    azure_pattern = re.compile(r"^(west|east|north|south|central|southeast|northeast|northwest|southwest)(europe|north|south|central|west|east)$")
    if azure_pattern.match(v):
        return v

    # GCP-style regions like europe-west1, us-central1, europe-central2
    # Pattern: word-word-digit (word can be europe, us, etc.)
    # Also handle zones like europe-west1-a, europe-west1-b
    gcp_pattern = re.compile(r"^(europe|us|ap|southamerica|northamerica|australia|africa|me|il|sa)-([a-z]+)\d+(-[a-z])?$")
    m = gcp_pattern.match(v)
    if m:
        # Return the base region without the zone suffix (e.g., europe-west1-a -> europe-west1)
        base = m.group(0)
        if m.group(3):  # zone suffix exists like "-a" (group 3 is the optional (-[a-z]) part)
            base = base[:-len(m.group(3))]
        return base

    # Alibaba Cloud regions like cn-hangzhou, cn-shanghai, cn-beijing
    # Pattern: two-letter country code followed by region name (no trailing digit)
    if re.match(r"^[a-z]{2}-[a-z]+$", v):
        return v

    # AWS-style regions like eu-central-1, us-east-1, ap-northeast-1
    if re.match(r"^[a-z]{2}-[a-z]+-\d+$", v):
        return v

    parts = v.split("-")
    if len(parts) >= 3:
        # Check if last part is a provider suffix
        last = parts[-1].lower()
        provider_suffixes = {"scaleway", "ionos", "upcloud", "cleura", "infomaniak", "leafcloud", "tcloud", "seeweb", "exoscale", "cyso", "numspot", "plusserver", "syselev", "outscale", "leaseweb"}
        if last in provider_suffixes:
            return "-".join(parts[:-1])
        # Also handle single letter zone suffixes (like 'a', 'b', 'c')
        if len(parts[-1]) == 1 and parts[-1].isalpha():
            return "-".join(parts[:-1])
    return None


def _region_from_string(val: str) -> str | None:
    """Extract an AWS region embedded in an arbitrary string (e.g. service endpoint)."""
    m = _REGION_IN_STRING_RE.search(val)
    return m.group(1) if m else None


def _get_label_or_tag_value(block: IaCBlock, key: str) -> str | None:
    """Extract a value from labels or tags on a resource block.

    Some providers (like Scaleway, IONOS) store region info in labels/tags
    instead of direct attributes.
    """
    labels = block.attributes.get("labels")
    if isinstance(labels, dict) and key in labels:
        val = labels[key]
        if _is_literal_string(val):
            return str(val).strip()

    tags = block.attributes.get("tags")
    if isinstance(tags, dict) and key in tags:
        val = tags[key]
        if _is_literal_string(val):
            return str(val).strip()

    return None


def _detect_ovh_provider_from_region(region: str) -> str:
    """Detect which OVH-like provider is being used based on region name suffix.

    Supports: infomaniak, leafcloud, tcloud, seeweb, exoscale,
    cyso, numspot, plusserver, syselev, outscale, leaseweb.

    Returns 'ovh' if no specific provider is detected.
    """
    r = region.lower().strip()
    if r.endswith("-infomaniak"):
        return "infomaniak"
    if r.endswith("-leafcloud"):
        return "leafcloud"
    if r.endswith("-tcloud"):
        return "tcloud"
    if r.endswith("-seeweb"):
        return "seeweb"
    if r.endswith("-exoscale"):
        return "exoscale"
    if r.endswith("-cyso"):
        return "cyso"
    if r.endswith("-numspot"):
        return "numspot"
    if r.endswith("-plusserver"):
        return "plusserver"
    if r.endswith("-syselev"):
        return "syselev"
    if r.endswith("-outscale"):
        return "outscale"
    if r.endswith("-leaseweb"):
        return "leaseweb"
    return "ovh"


# ── HCL2 compatibility helpers ───────────────────────────────────────────────

def _unquote(s: object) -> object:
    """Strip surrounding quotes that hcl2 v8+ wraps around identifier keys.

    hcl2 >= 8.0 returns block-label keys (resource types, resource names,
    provider names, etc.) as quoted strings, e.g. ``'"aws_instance"'``.
    This helper normalises them back to bare identifiers.
    """
    if isinstance(s, str) and len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


def _unquote_attrs(val: object) -> object:
    """Recursively strip hcl2 v8+ quote-wrapping from attribute values."""
    if isinstance(val, str):
        return _unquote(val)
    if isinstance(val, dict):
        return {_unquote(k): _unquote_attrs(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_unquote_attrs(item) for item in val]
    return val


# ── HCL2 block parsers ────────────────────────────────────────────────────────

def _parse_resource_blocks(raw_list: list, state: IaCState) -> None:
    """Parse ``resource`` blocks.

    HCL2 format: ``[{"aws_s3_bucket": {"my_bucket": {...attrs...}}}, ...]``
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for resource_type, names_dict in item.items():
            resource_type = _unquote(resource_type)
            if not isinstance(names_dict, dict):
                continue
            for resource_name, attrs_raw in names_dict.items():
                resource_name = _unquote(resource_name)
                attrs = _unquote_attrs(attrs_raw) if isinstance(attrs_raw, dict) else {}
                state.resources.append(IaCBlock(
                    block_type="resource",
                    type=resource_type,
                    name=resource_name,
                    address=f"{resource_type}.{resource_name}",
                    attributes=attrs,
                    raw={resource_type: {resource_name: attrs_raw}},
                ))


def _parse_provider_blocks(raw_list: list, state: IaCState) -> None:
    """Parse ``provider`` blocks.

    HCL2 format: ``[{"aws": {...attrs...}}, {"azurerm": {...attrs...}}]``
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for provider_name, attrs_raw in item.items():
            provider_name = _unquote(provider_name)
            attrs = _unquote_attrs(attrs_raw) if isinstance(attrs_raw, dict) else {}
            state.providers.append(IaCBlock(
                block_type="provider",
                type=provider_name,
                name="",
                address=f"provider.{provider_name}",
                attributes=attrs,
                raw={provider_name: attrs_raw},
            ))


def _parse_variable_blocks(raw_list: list, state: IaCState) -> None:
    """Parse ``variable`` blocks.

    HCL2 format: ``[{"my_var": {...attrs...}}, ...]``
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for var_name, attrs_raw in item.items():
            var_name = _unquote(var_name)
            attrs = _unquote_attrs(attrs_raw) if isinstance(attrs_raw, dict) else {}
            state.variables.append(IaCBlock(
                block_type="variable",
                type=var_name,
                name=var_name,
                address=f"var.{var_name}",
                attributes=attrs,
                raw={var_name: attrs_raw},
            ))

    # Also extract region variables for provider detection
    # Store them in state for use by extract_regions
    region_vars: dict[str, str] = {}
    for var in state.variables:
        # Look for variables with "region" in their name or attributes
        var_name_lower = var.name.lower()
        if "region" in var_name_lower:
            # Check for literal region default value
            default = var.attributes.get("default")
            if _is_literal_string(default):
                default_str = str(default).strip()
                # Check if this looks like a region (with provider suffix)
                # e.g., par-1-scaleway, de-fra-1-ionos, fi-hel-1-upcloud, se-sto-1-cleura
                if _region_from_zone(default_str) or _region_from_string(default_str) or re.match(r"^[a-z]{2}-[a-z]+-\d+$", default_str):
                    region_vars[var_name_lower] = default_str
    state._region_vars = region_vars


def _parse_module_blocks(raw_list: list, state: IaCState) -> None:
    """Parse ``module`` blocks.

    HCL2 format: ``[{"my_module": {...attrs...}}, ...]``
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for mod_name, attrs_raw in item.items():
            mod_name = _unquote(mod_name)
            attrs = _unquote_attrs(attrs_raw) if isinstance(attrs_raw, dict) else {}
            state.modules.append(IaCBlock(
                block_type="module",
                type=mod_name,
                name=mod_name,
                address=f"module.{mod_name}",
                attributes=attrs,
                raw={mod_name: attrs_raw},
            ))


def _parse_terraform_config_blocks(raw_list: list, state: IaCState) -> None:
    """Parse top-level ``terraform { … }`` configuration blocks.

    HCL2 format: ``[{...attrs...}]``
    """
    for item in raw_list:
        attrs = _unquote_attrs(item) if isinstance(item, dict) else {}
        state.config_blocks.append(IaCBlock(
            block_type="terraform",
            type="terraform",
            name="",
            address="terraform",
            attributes=attrs,
            raw=item if isinstance(item, dict) else {},
        ))


def _parse_hcl2_file(content: str, state: IaCState, file_path: Path) -> None:
    """Parse a single ``.tf`` file and append blocks to *state*."""
    try:
        parsed: dict = hcl2.loads(content)
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", file_path, exc)
        return

    dispatch = {
        "resource": _parse_resource_blocks,
        "provider": _parse_provider_blocks,
        "variable": _parse_variable_blocks,
        "module": _parse_module_blocks,
        "terraform": _parse_terraform_config_blocks,
    }
    for block_type, block_value in parsed.items():
        if not isinstance(block_value, list):
            continue
        handler = dispatch.get(block_type)
        if handler is None:
            continue
        try:
            handler(block_value, state)
        except Exception as exc:
            logger.warning("Error processing %s block in %s: %s", block_type, file_path, exc)


# ── Plugin class ──────────────────────────────────────────────────────────────

class TerraformPlugin:
    """IaC plugin for Terraform HCL2 (``.tf``) files."""

    name: str = "terraform"
    file_extensions: list[str] = [".tf"]

    # ── IaCPlugin interface ───────────────────────────────────────────────────

    def can_parse(self, path: Path) -> bool:
        """Return True if *path* is a ``.tf`` file or a directory containing one."""
        if path.is_file():
            return path.suffix == ".tf"
        if path.is_dir():
            return any(True for _ in path.rglob("*.tf"))
        return False

    def parse(self, path: Path) -> IaCState:
        """Parse all ``.tf`` files under *path* and return an :class:`IaCState`.

        Args:
            path: A directory (scanned recursively) or a single ``.tf`` file.

        Returns:
            :class:`IaCState` with all parsed blocks.  Parsing errors per file
            are logged as warnings; the method never raises.
        """
        state = IaCState()

        if path.is_file():
            tf_files = [path]
        elif path.is_dir():
            tf_files = sorted(path.rglob("*.tf"))
        else:
            logger.error("Path does not exist: %s", path)
            return state

        if not tf_files:
            logger.warning("No .tf files found in: %s", path)
            return state

        for tf_path in tf_files:
            try:
                content = tf_path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Cannot read %s: %s", tf_path, exc)
                continue
            _parse_hcl2_file(content, state, tf_path)

        logger.debug(
            "Terraform plugin: parsed %d resources, %d providers, %d variables, "
            "%d modules, %d config blocks from %s",
            len(state.resources),
            len(state.providers),
            len(state.variables),
            len(state.modules),
            len(state.config_blocks),
            path,
        )
        return state

    def extract_regions(self, state: IaCState) -> list[tuple[str, str, str]]:
        """Extract ``(region_name, provider, availability_zone)`` tuples from parsed Terraform state.

        The region is the base region name (without zone suffix) for grouping.
        Availability zones are included when available (e.g., de-ham-1, de-ham-2).

        Supports: AWS, Azure (azurerm/azuread/azurestack), GCP (google/google-beta),
        Alicloud, Yandex.Cloud, OCI, OVH (including infomaniak, leafcloud, tcloud,
        seeweb, exoscale, cyso, numspot, plusserver, syselev, outscale, leaseweb),
        Hetzner (including Cleura), StackIT, Scaleway, IONOS, UpCloud.
        """
        logger.debug("=== EXTRACT REGIONS DEBUG ===")
        logger.debug("Resources: %s", [(r.address, r.type, r.attributes.get("region"), r.attributes.get("location"), r.attributes.get("zone")) for r in state.resources[:5]])
        seen: set[tuple[str, str, str]] = set()  # (region, provider, az)
        result: list[tuple[str, str, str]] = []  # (region, provider, az)

        def add(region: str, provider: str, az: str | None = None) -> None:
            # Normalize region for grouping - strip numeric zone suffixes
            normalized = _normalize_region_for_zone_grouping(region, provider)
            # For display in the dashboard, include the zone in the region name
            # when a zone is present (e.g., "europe-west4-a" instead of just "europe-west4")
            # This ensures the region name can be looked up in region-data.ts
            display_region = normalized
            if az is not None:
                display_region = f"{normalized}-{az}"
            # Deduplicate by (normalized region, provider, az) to keep all unique AZs
            key = (normalized.lower(), provider, az if az is not None else None)
            if key not in seen:
                seen.add(key)
                result.append((display_region, provider, az))

        def try_literal(val: object, provider: str) -> None:
            if _is_literal_string(val):
                add(str(val).strip(), provider, None)

        def try_aws(val: object) -> None:
            if not _is_literal_string(val):
                return
            s = str(val).strip()
            # Check if s looks like region+zone (e.g., us-east-1a, eu-central-1b)
            # AWS zones are single letters at the end
            m = re.match(r"^([a-z]{2}-[a-z]+-\d+)([a-z])$", s)
            if m:
                region = m.group(1)
                zone = m.group(2)
                add(region, "aws", zone)
                return
            # Plain region without zone (e.g., us-east-1)
            if re.match(r"^[a-z]{2}-[a-z]+-\d+$", s):
                add(s, "aws", None)
                return
            region = _region_from_string(s)
            if region:
                add(region, "aws", None)

        def try_zone(val: object, provider: str) -> None:
            if not _is_literal_string(val):
                return
            s = str(val).strip()
            # Try to extract base region, fall back to full value
            base_region = _region_from_zone(s)
            # Pass just the zone part as the availability zone if base_region differs from full value
            # (i.e., if there was a zone suffix like "-a" that got stripped)
            az = s[len(base_region) + 1:] if base_region and base_region != s else None
            add(base_region or s, provider, az)

        # Build a lookup of variable references in provider blocks
        # e.g., "${var.scaleway_region}" -> "scaleway_region"
        provider_vars: dict[str, str] = {}
        for blk in state.providers:
            pname = blk.type.lower()
            varname = None
            region_attr = blk.attributes.get("region") or blk.attributes.get("location")
            if isinstance(region_attr, str) and region_attr.startswith("var."):
                # Extract variable name like "scaleway_region" from "${var.scaleway_region}"
                varname = region_attr[4:]  # strip "var."
            elif isinstance(region_attr, str) and region_attr.startswith("${") and "var." in region_attr:
                # Handle ${var.scaleway_region} format
                m = re.search(r"var\.([a-z_]+)", region_attr)
                if m:
                    varname = m.group(1)
            if varname:
                provider_vars[pname] = varname

        # Helper to resolve a region value, checking for variable references
        def resolve_region(pname: str, region_attr: object) -> str | None:
            """Resolve region value, potentially from a variable reference."""
            # Direct literal string
            if _is_literal_string(region_attr):
                return str(region_attr).strip()
            # Variable reference like "${var.scaleway_region}" or "var.scaleway_region"
            if isinstance(region_attr, str):
                if region_attr.startswith("var."):
                    varname = region_attr[4:]
                elif region_attr.startswith("${") and "var." in region_attr:
                    m = re.search(r"var\.([a-z_]+)", region_attr)
                    varname = m.group(1) if m else None
                else:
                    varname = None
                if varname and hasattr(state, "_region_vars"):
                    return state._region_vars.get(varname)
            return None

        for blk in state.providers:
            pname = blk.type.lower()
            if pname == "aws":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    try_aws(region)
            elif pname in ("azurerm", "azuread", "azurestack"):
                # Azure region from provider block
                region = resolve_region(pname, blk.attributes.get("location") or blk.attributes.get("region"))
                if region:
                    add(region, "azure", region)
                # Also check azure_region variable if no region in provider block
                elif hasattr(state, "_region_vars") and "azure_region" in state._region_vars:
                    region = state._region_vars["azure_region"]
                    if region:
                        add(region, "azure", region)
            elif pname in ("google", "google-beta"):
                region = resolve_region(pname, blk.attributes.get("region") or blk.attributes.get("location"))
                logger.debug("GCP provider block - region: %s", region)
                if region:
                    # GCP regions can include zone suffixes like europe-west1-a
                    # Extract base region and zone
                    base_region = _region_from_zone(region)
                    logger.debug("GCP _region_from_zone(%s) -> %s", region, base_region)
                    if base_region and region != base_region:
                        # region has a zone suffix, extract the zone letter
                        zone = region[len(base_region) + 1:] if len(region) > len(base_region) else None
                        add(base_region, "gcp", zone)
                    else:
                        add(region, "gcp", None)
            elif pname == "alicloud":
                region = resolve_region(pname, blk.attributes.get("region") or blk.attributes.get("zone"))
                if region:
                    try_zone(region, "alicloud")
            elif pname == "yandex":
                region = resolve_region(pname, blk.attributes.get("zone") or blk.attributes.get("region"))
                if region:
                    try_zone(region, "yandex")
            elif pname == "oci":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    add(region, "oci", region)
            elif pname == "ovh":
                region = resolve_region(pname, blk.attributes.get("region") or blk.attributes.get("location"))
                if region:
                    provider = _detect_ovh_provider_from_region(region)
                    # Format region as GRA-ovh to match region-data.ts (lowercase)
                    r = region.lower()
                    if not r.endswith("-ovh") and not r.endswith("-infomaniak") and not r.endswith("-leafcloud") and not r.endswith("-tcloud") and not r.endswith("-seeweb") and not r.endswith("-exoscale") and not r.endswith("-cyso") and not r.endswith("-numspot") and not r.endswith("-plusserver") and not r.endswith("-syselev") and not r.endswith("-outscale") and not r.endswith("-leaseweb"):
                        r = r + "-" + provider
                    add(r, provider, r)
            elif pname == "hcloud":
                region = resolve_region(pname, blk.attributes.get("region") or blk.attributes.get("location"))
                if region:
                    # Cleura regions (these have specific patterns that distinguish them from Hetzner)
                    # Cleura regions: se-sto-X, se-Gothenburg-X, fi-hel-X, de-fra-X, nl-ams-X, uk-lon-X, sto, fra
                    if re.match(r"^(se-sto|se-Gothenburg|fi-hel|de-fra|nl-ams|uk-lon|sto|fra)$", region.lower()):
                        add(region, "cleura", region)
                    elif region.startswith("se-") or region.startswith("se-Gothenburg"):
                        # Hetzner Stockholm or Gothenburg regions (without -cleura suffix)
                        add(region, "hetzner", region)
                    else:
                        add(region, "hetzner", region)
            elif pname == "openstack":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    r = str(region).strip()
                    # Detect T Cloud based on region naming (ts-, os-, hk-)
                    if r.startswith("ts-") or r.startswith("os-") or r.startswith("hk-"):
                        add(r, "tcloud", r)
                    # Detect StackIT based on region naming (ends with -stackit)
                    elif r.endswith("-stackit"):
                        add(r, "stackit", r)
                    # Detect SINA Cloud based on Germany region naming (de-*)
                    # SINA Cloud operates in Germany with datacenters in Hamburg, Düsseldorf, Frankfurt
                    elif r.startswith("de-"):
                        add(r + "-sinacloud", "sinacloud", r)
                    else:
                        add(r, "openstack", r)
            elif pname == "stackit":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    add(region, "stackit", region)
            elif pname == "scaleway":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    add(region, "scaleway", region)
            elif pname == "ionos":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    add(region, "ionos", region)
            elif pname == "upcloud":
                region = resolve_region(pname, blk.attributes.get("region"))
                if region:
                    add(region + "-upcloud", "upcloud", region)

        for blk in state.resources:
            rtype = blk.type.lower()
            if rtype.startswith("aws_"):
                for attr in ("region", "availability_zone", "service_name"):
                    try_aws(blk.attributes.get(attr))
            elif rtype.startswith("azurerm_"):
                # Azure region from location attribute
                location = blk.attributes.get("location")
                zone = blk.attributes.get("zone")
                if _is_literal_string(location):
                    region = str(location).strip()
                    # Azure zones are stored as separate "zone" attribute (e.g., "1", "2", "3")
                    # Combine region and zone for proper detection
                    if _is_literal_string(zone):
                        az = str(zone).strip()
                        add(region, "azure", az)
                    else:
                        add(region, "azure", None)
            elif rtype.startswith("google_"):
                val = blk.attributes.get("region") or blk.attributes.get("location")
                if _is_literal_string(val):
                    region = str(val).strip()
                    logger.debug("GCP resource %s - region: %s", blk.address, region)
                    # GCP regions can include zone suffixes like europe-west1-a
                    base_region = _region_from_zone(region)
                    logger.debug("GCP _region_from_zone(%s) -> %s", region, base_region)
                    if base_region and region != base_region:
                        zone = region[len(base_region) + 1:] if len(region) > len(base_region) else None
                        add(base_region, "gcp", zone)
                    else:
                        add(region, "gcp", None)
                # Also check zone attribute to extract base region from zone suffix
                zone_val = blk.attributes.get("zone")
                if _is_literal_string(zone_val):
                    zone_str = str(zone_val).strip()
                    base_from_zone = _region_from_zone(zone_str)
                    if base_from_zone:
                        add(base_from_zone, "gcp", zone_str[len(base_from_zone) + 1:] if len(zone_str) > len(base_from_zone) else None)
            elif rtype.startswith("alicloud_"):
                try_zone(
                    blk.attributes.get("region")
                    or blk.attributes.get("availability_zone")  # Alibaba uses availability_zone
                    or blk.attributes.get("zone")
                    or blk.attributes.get("zone_id"),
                    "alicloud",
                )
            elif rtype.startswith("yandex_"):
                try_zone(blk.attributes.get("zone") or blk.attributes.get("region"), "yandex")
            elif rtype.startswith("oci_"):
                try_literal(blk.attributes.get("region"), "oci")
            elif rtype.startswith("ovh_"):
                region = blk.attributes.get("region") or blk.attributes.get("location")
                if _is_literal_string(region):
                    r = str(region).strip()
                    provider = _detect_ovh_provider_from_region(r)
                    # Format region as GRA-ovh to match region-data.ts (lowercase)
                    r = r.lower()
                    if not r.endswith("-ovh") and not r.endswith("-infomaniak") and not r.endswith("-leafcloud") and not r.endswith("-tcloud") and not r.endswith("-seeweb") and not r.endswith("-exoscale") and not r.endswith("-cyso") and not r.endswith("-numspot") and not r.endswith("-plusserver") and not r.endswith("-syselev") and not r.endswith("-outscale") and not r.endswith("-leaseweb"):
                        r = r + "-" + provider
                    add(r, provider, r)
                else:
                    try_literal(region, "ovh")
            elif rtype.startswith("openstack_"):
                region = blk.attributes.get("region")
                if _is_literal_string(region):
                    r = str(region).strip()
                    # Detect T Cloud based on region naming (ts-, os-, hk-)
                    if r.startswith("ts-") or r.startswith("os-") or r.startswith("hk-"):
                        add(r, "tcloud", r)
                    # Detect StackIT based on region naming (de-fld-X-stackit, de-muc-X-stackit, etc.)
                    elif r.endswith("-stackit"):
                        add(r, "stackit", r)
                    # Detect SINA Cloud based on Germany region naming (de-*)
                    # SINA Cloud operates in Germany with datacenters in Hamburg, Düsseldorf, Frankfurt
                    elif r.startswith("de-"):
                        add(r + "-sinacloud", "sinacloud", r)
                    else:
                        add(r, "openstack", r)
                else:
                    try_literal(region, "openstack")
            elif rtype.startswith("hcloud_"):
                # Both Hetzner and Cleura use hcloud provider - differentiate by region
                # Prefer location/region over datacenter (datacenter includes suffix like -dc13)
                region = blk.attributes.get("region") or blk.attributes.get("location")
                if not _is_literal_string(region):
                    region = blk.attributes.get("datacenter")
                if isinstance(region, str):
                    r = str(region).strip()
                    # Skip if this looks like a datacenter (ends with -dcXX)
                    if re.search(r"-dc\d+$", r):
                        continue
                    # For Cleura detection, we need the full region name with suffix
                    # Check if this matches Cleura naming pattern
                    # Cleura regions: se-sto-X, se-Gothenburg-X, fi-hel-X, de-fra-X, nl-ams-X, uk-lon-X, sto, fra
                    if re.match(r"^(se-sto-\d+|se-Gothenburg-\d+|fi-hel-\d+|de-fra-\d+|nl-ams-\d+|uk-lon-\d+|sto|fra)$", r):
                        # Add with -cleura suffix so it has coordinates in the dashboard
                        r = f"{r}-cleura"
                        add(r, "cleura", r)
                    elif r.startswith("se-") or r.startswith("se-Gothenburg"):
                        # Hetzner Stockholm or Gothenburg regions (without -cleura suffix)
                        add(r, "hetzner", r)
                    else:
                        add(r, "hetzner", r)
            elif rtype.startswith("stackit_"):
                try_literal(blk.attributes.get("region"), "stackit")
            elif rtype.startswith("scaleway_"):
                region = blk.attributes.get("region") or blk.attributes.get("zone")
                if not _is_literal_string(region):
                    # Check labels/tags for region
                    # Tags can be either a dict or a string expression like ${local.tags}
                    tags = blk.attributes.get("tags")
                    if isinstance(tags, dict):
                        region = tags.get("region")
                    elif isinstance(tags, str):
                        # Parse string expression to extract region
                        # e.g., ${local.scaleway_par1_tags} or ${merge(..., region = "ams-1-scaleway")}
                        m = re.search(r'region\s*=\s*"([^"]+)"', tags)
                        if m:
                            region = m.group(1)
                    if not region:
                        labels = blk.attributes.get("labels")
                        if isinstance(labels, dict):
                            region = labels.get("region")
                        elif isinstance(labels, str):
                            m = re.search(r'region\s*=\s*"([^"]+)"', labels)
                            if m:
                                region = m.group(1)
                if region:
                    region_str = str(region).strip() if region else None
                    if region_str:
                        add(region_str, "scaleway", region_str)
            elif rtype.startswith("ionos_"):
                region = blk.attributes.get("region") or blk.attributes.get("location")
                if not _is_literal_string(region):
                    # Check labels/tags for region
                    tags = blk.attributes.get("tags")
                    if isinstance(tags, dict):
                        region = tags.get("region")
                    elif isinstance(tags, str):
                        m = re.search(r'region\s*=\s*"([^"]+)"', tags)
                        if m:
                            region = m.group(1)
                    if not region:
                        labels = blk.attributes.get("labels")
                        if isinstance(labels, dict):
                            region = labels.get("region")
                        elif isinstance(labels, str):
                            m = re.search(r'region\s*=\s*"([^"]+)"', labels)
                            if m:
                                region = m.group(1)
                if not _is_literal_string(region):
                    # IONOS uses availability_zone like ZONE_1, de-fra-1, etc.
                    az = blk.attributes.get("availability_zone")
                    if isinstance(az, str):
                        # IONOS region naming: de-fra-1, de-muc-1, etc.
                        az_str = str(az).strip()
                        if re.match(r"^[a-z]{2}-[a-z]+-\d+$", az_str):
                            region = az_str
                if region:
                    region_str = str(region).strip() if region else None
                    if region_str:
                        add(region_str, "ionos", region_str)
            elif rtype.startswith("upcloud_"):
                region = blk.attributes.get("region") or blk.attributes.get("zone")
                if region:
                    add(region + "-upcloud", "upcloud", region)

        logger.debug("extract_regions result: %s", result)
        return result


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(TerraformPlugin())


def debug_extract_regions(state):
    """Debug helper to extract and log regions."""
    result = []
    for blk in state.providers:
        pname = blk.type.lower()
        if pname in ("google", "google-beta"):
            region = blk.attributes.get("region") or blk.attributes.get("location")
            print(f"DEBUG: GCP provider block, region attribute = {region!r}")
    for blk in state.resources:
        rtype = blk.type.lower()
        if rtype.startswith("google_"):
            region = blk.attributes.get("region") or blk.attributes.get("location")
            print(f"DEBUG: GCP resource {blk.address}, region = {region!r}")
    return result
