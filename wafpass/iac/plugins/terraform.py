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


def _region_from_zone(val: str) -> str | None:
    """Return region from an Alibaba/Yandex zone string.

    Examples: ``'cn-hangzhou-b'`` → ``'cn-hangzhou'``, ``'ru-central1-a'`` → ``'ru-central1'``.
    Returns ``None`` if *val* doesn't look like a zone identifier.
    """
    parts = val.strip().split("-")
    if len(parts) >= 3 and len(parts[-1]) == 1 and parts[-1].isalpha():
        return "-".join(parts[:-1])
    return None


def _region_from_string(val: str) -> str | None:
    """Extract an AWS region embedded in an arbitrary string (e.g. service endpoint)."""
    m = _REGION_IN_STRING_RE.search(val)
    return m.group(1) if m else None


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

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        """Extract ``(region_name, provider)`` tuples from parsed Terraform state.

        Supports: AWS, Azure (azurerm/azuread/azurestack), GCP (google/google-beta),
        Alicloud, Yandex.Cloud, OCI.
        """
        seen: set[tuple[str, str]] = set()
        result: list[tuple[str, str]] = []

        def add(region: str, provider: str) -> None:
            key = (region.lower(), provider)
            if key not in seen:
                seen.add(key)
                result.append((region, provider))

        def try_literal(val: object, provider: str) -> None:
            if _is_literal_string(val):
                add(str(val).strip(), provider)

        def try_aws(val: object) -> None:
            if not _is_literal_string(val):
                return
            s = str(val).strip()
            if re.match(r"^[a-z]{2}-[a-z]+-\d+$", s):
                add(s, "aws")
                return
            region = _region_from_az(s)
            if region:
                add(region, "aws")
                return
            region = _region_from_string(s)
            if region:
                add(region, "aws")

        def try_zone(val: object, provider: str) -> None:
            if not _is_literal_string(val):
                return
            s = str(val).strip()
            add(_region_from_zone(s) or s, provider)

        for blk in state.providers:
            pname = blk.type.lower()
            if pname == "aws":
                try_literal(blk.attributes.get("region"), "aws")
            elif pname in ("azurerm", "azuread", "azurestack"):
                try_literal(blk.attributes.get("location") or blk.attributes.get("region"), "azure")
            elif pname in ("google", "google-beta"):
                try_literal(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")
            elif pname == "alicloud":
                try_zone(blk.attributes.get("region") or blk.attributes.get("zone"), "alicloud")
            elif pname == "yandex":
                try_zone(blk.attributes.get("zone") or blk.attributes.get("region"), "yandex")
            elif pname == "oci":
                try_literal(blk.attributes.get("region"), "oci")

        for blk in state.resources:
            rtype = blk.type.lower()
            if rtype.startswith("aws_"):
                for attr in ("region", "availability_zone", "service_name"):
                    try_aws(blk.attributes.get(attr))
            elif rtype.startswith("azurerm_"):
                try_literal(blk.attributes.get("location"), "azure")
            elif rtype.startswith("google_"):
                try_literal(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")
            elif rtype.startswith("alicloud_"):
                try_zone(
                    blk.attributes.get("region")
                    or blk.attributes.get("zone")
                    or blk.attributes.get("zone_id"),
                    "alicloud",
                )
            elif rtype.startswith("yandex_"):
                try_zone(blk.attributes.get("zone") or blk.attributes.get("region"), "yandex")
            elif rtype.startswith("oci_"):
                try_literal(blk.attributes.get("region"), "oci")

        return result


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(TerraformPlugin())
