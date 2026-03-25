"""Load WAF++ YAML control files and parse them into dataclasses."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from wafpass.models import Assertion, Check, Control, Scope

logger = logging.getLogger(__name__)

# Operators that skip during evaluation (not supported in automated checks)
SKIP_OPERATORS = frozenset(
    {
        "has_associated_metric_filter",
        "references_cloudtrail_bucket",
        "region_in_arn_matches",
        "in_variable",
        "not_equals_with_sibling",
        "not_all_true_with",
        "attribute_exists_on_all_providers",
        "attribute_exists_if",
        "json_not_contains_pattern",
    }
)

# Pillar prefix mapping: pillar name -> YAML id prefix
PILLAR_PREFIXES: dict[str, str] = {
    "cost": "WAF-COST-",
    "sovereign": "WAF-SOV-",
    "security": "WAF-SEC-",
    "reliability": "WAF-REL-",
    "operations": "WAF-OPS-",
    "architecture": "WAF-ARCH-",
    "governance": "WAF-GOV-",
}


def _parse_assertion(raw: dict) -> Assertion:
    """Parse a single assertion dict into an Assertion dataclass."""
    # Normalise: YAML uses 'value' (scalar) and 'values' (list); map both to 'expected'
    expected: object = None
    if "value" in raw:
        expected = raw["value"]
    elif "values" in raw:
        expected = raw["values"]

    return Assertion(
        attribute=raw.get("attribute", ""),
        op=raw.get("op", ""),
        expected=expected,
        key=raw.get("key"),
        pattern=raw.get("pattern"),
        message=raw.get("message"),
        fallback_attribute=raw.get("fallback_attribute"),
    )


def _parse_scope(raw: dict) -> Scope:
    """Parse a scope dict into a Scope dataclass."""
    return Scope(
        block_type=raw.get("block_type", "resource"),
        resource_types=raw.get("resource_types", []),
        provider_name=raw.get("provider_name"),
    )


def _parse_check(raw: dict) -> Check | None:
    """Parse a check dict. Returns None if not automated."""
    if not raw.get("automated", False):
        return None

    scope_raw = raw.get("scope", {})
    assertions_raw = raw.get("assertions", [])

    return Check(
        id=raw.get("id", ""),
        engine=raw.get("engine", ""),
        provider=raw.get("provider", ""),
        automated=raw.get("automated", False),
        severity=raw.get("severity", "medium"),
        title=raw.get("title", ""),
        scope=_parse_scope(scope_raw),
        assertions=[_parse_assertion(a) for a in assertions_raw],
        on_fail=raw.get("on_fail", "violation"),
        remediation=str(raw.get("remediation", "")).strip(),
        example=raw.get("example"),
    )


def _parse_control(raw: dict) -> Control | None:
    """Parse a control dict. Returns None if no automated checks are present."""
    checks_raw = raw.get("checks", [])
    if not checks_raw:
        return None

    checks: list[Check] = []
    for check_raw in checks_raw:
        parsed = _parse_check(check_raw)
        if parsed is not None:
            checks.append(parsed)

    if not checks:
        return None

    # Parse regulatory_mapping: list of {framework, controls} dicts
    regulatory_mapping: list[dict] = []
    for entry in raw.get("regulatory_mapping", []):
        if isinstance(entry, dict) and "framework" in entry:
            regulatory_mapping.append({
                "framework": str(entry["framework"]),
                "controls": [str(c) for c in entry.get("controls", [])],
            })

    return Control(
        id=raw.get("id", ""),
        title=raw.get("title", ""),
        pillar=raw.get("pillar", ""),
        severity=raw.get("severity", "medium"),
        category=raw.get("category", ""),
        description=str(raw.get("description", "")).strip(),
        checks=checks,
        regulatory_mapping=regulatory_mapping,
        rationale=str(raw.get("rationale", "")).strip(),
        threat=[str(t) for t in raw.get("threat", [])],
    )


def load_controls(
    controls_dir: Path,
    pillar: str | None = None,
    ids: list[str] | None = None,
) -> list[Control]:
    """Load all YAML control files from controls_dir.

    Args:
        controls_dir: Directory containing WAF-*.yml files.
        pillar: Optional pillar name to filter by (e.g. 'cost', 'sovereign').
        ids: Optional explicit list of control IDs to load.

    Returns:
        List of parsed Control objects with at least one automated check.
    """
    if not controls_dir.exists():
        logger.warning("Controls directory does not exist: %s", controls_dir)
        return []

    yml_files = sorted(controls_dir.glob("*.yml")) + sorted(controls_dir.glob("*.yaml"))

    if not yml_files:
        logger.warning("No YAML files found in: %s", controls_dir)
        return []

    # Build pillar prefix filter
    pillar_prefix: str | None = None
    if pillar:
        pillar_lower = pillar.lower()
        pillar_prefix = PILLAR_PREFIXES.get(pillar_lower)
        if pillar_prefix is None:
            # Fallback: construct prefix from pillar name
            pillar_prefix = f"WAF-{pillar_lower.upper()}-"

    controls: list[Control] = []
    for yml_path in yml_files:
        # Filter by filename prefix before loading file
        stem = yml_path.stem.upper()
        if pillar_prefix and not stem.startswith(pillar_prefix.upper()):
            continue
        if ids:
            ids_upper = [i.upper() for i in ids]
            if stem not in ids_upper:
                continue

        try:
            with yml_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            logger.error("Failed to parse YAML %s: %s", yml_path, exc)
            continue

        if not isinstance(raw, dict):
            logger.warning("Skipping non-dict YAML: %s", yml_path)
            continue

        control = _parse_control(raw)
        if control is None:
            logger.debug("Skipping control with no automated checks: %s", yml_path)
            continue

        controls.append(control)

    return controls
