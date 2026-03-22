"""Assertion evaluation engine for WAF++ PASS."""

from __future__ import annotations

import logging
import re
from typing import Any

from wafpass.iac.base import IaCBlock, IaCState
from wafpass.models import (
    Assertion,
    Check,
    CheckResult,
    Control,
    ControlResult,
    Scope,
)

# Backward-compat aliases (parser.py users may pass TerraformState/TerraformBlock,
# which are the same types — just different names).
TerraformBlock = IaCBlock
TerraformState = IaCState

logger = logging.getLogger(__name__)

# Operators that cannot be evaluated automatically (require runtime state, etc.)
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

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def get_nested(d: dict, path: str) -> tuple[bool, Any]:
    """Navigate nested dict using dot-notation path.

    Args:
        d: Dictionary to traverse.
        path: Dot-separated attribute path, e.g. 'tags.cost-center'.

    Returns:
        (found: bool, value: Any)
    """
    parts = path.split(".", 1)
    key = parts[0]

    if not isinstance(d, dict):
        return False, None
    if key not in d:
        return False, None

    value = d[key]
    if len(parts) == 1:
        return True, value

    # Recurse into nested dict
    if isinstance(value, dict):
        return get_nested(value, parts[1])

    return False, None


def _coerce_bool(value: Any) -> bool | None:
    """Coerce a value to bool (True/False/None if cannot coerce)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    return None


def _coerce_numeric(value: Any) -> float | None:
    """Coerce a value to float, or return None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate_assertion(
    assertion: Assertion, block: IaCBlock, tf: IaCState
) -> tuple[bool, str]:
    """Evaluate a single assertion against a Terraform block.

    Returns:
        (passed: bool, message: str)
        For SKIP operators, raises a special SkipAssertion exception.
    """
    op = assertion.op

    # ── Operators to skip ────────────────────────────────────────────────────
    if op in SKIP_OPERATORS:
        raise SkipAssertion(f"Operator '{op}' is not supported in automated evaluation.")

    attrs = block.attributes

    # ── block_exists ─────────────────────────────────────────────────────────
    if op == "block_exists":
        # Already matched at scope level; if we get here the block exists
        return True, "Block exists."

    # ── attribute_exists ─────────────────────────────────────────────────────
    if op == "attribute_exists":
        found, val = get_nested(attrs, assertion.attribute)
        if found and val is not None:
            return True, f"Attribute '{assertion.attribute}' exists."
        msg = assertion.message or f"Attribute '{assertion.attribute}' is missing or None."
        return False, msg

    # ── attribute_exists_or_fallback ─────────────────────────────────────────
    if op == "attribute_exists_or_fallback":
        found, val = get_nested(attrs, assertion.attribute)
        if found and val is not None:
            return True, f"Attribute '{assertion.attribute}' exists."
        if assertion.fallback_attribute:
            found2, val2 = get_nested(attrs, assertion.fallback_attribute)
            if found2 and val2 is not None:
                return True, f"Fallback attribute '{assertion.fallback_attribute}' exists."
        msg = assertion.message or (
            f"Neither '{assertion.attribute}' nor "
            f"'{assertion.fallback_attribute}' is present."
        )
        return False, msg

    # ── not_empty ─────────────────────────────────────────────────────────────
    if op == "not_empty":
        found, val = get_nested(attrs, assertion.attribute)
        if not found or val is None:
            msg = assertion.message or f"Attribute '{assertion.attribute}' is missing."
            return False, msg
        if isinstance(val, (str, list, dict)) and len(val) == 0:
            msg = assertion.message or f"Attribute '{assertion.attribute}' is empty."
            return False, msg
        return True, f"Attribute '{assertion.attribute}' is not empty."

    # ── equals ───────────────────────────────────────────────────────────────
    if op == "equals":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        if val == assertion.expected:
            return True, f"'{assertion.attribute}' == '{assertion.expected}'."
        msg = assertion.message or (
            f"'{assertion.attribute}' is '{val}', expected '{assertion.expected}'."
        )
        return False, msg

    # ── not_equals ───────────────────────────────────────────────────────────
    if op == "not_equals":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        if val != assertion.expected:
            return True, f"'{assertion.attribute}' != '{assertion.expected}'."
        msg = assertion.message or (
            f"'{assertion.attribute}' is '{val}', must not equal '{assertion.expected}'."
        )
        return False, msg

    # ── in ───────────────────────────────────────────────────────────────────
    if op == "in":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        expected_list = assertion.expected if isinstance(assertion.expected, list) else [assertion.expected]
        if val in expected_list:
            return True, f"'{assertion.attribute}' is in allowed values."
        msg = assertion.message or (
            f"'{assertion.attribute}' is '{val}', must be one of {expected_list}."
        )
        return False, msg

    # ── not_in ───────────────────────────────────────────────────────────────
    if op == "not_in":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        expected_list = assertion.expected if isinstance(assertion.expected, list) else [assertion.expected]
        if val not in expected_list:
            return True, f"'{assertion.attribute}' is not in disallowed values."
        msg = assertion.message or (
            f"'{assertion.attribute}' is '{val}', must NOT be one of {expected_list}."
        )
        return False, msg

    # ── is_true ──────────────────────────────────────────────────────────────
    if op == "is_true":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        coerced = _coerce_bool(val)
        if coerced is True:
            return True, f"'{assertion.attribute}' is true."
        msg = assertion.message or f"'{assertion.attribute}' is '{val}', expected true."
        return False, msg

    # ── is_false ─────────────────────────────────────────────────────────────
    if op == "is_false":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        coerced = _coerce_bool(val)
        if coerced is False:
            return True, f"'{assertion.attribute}' is false."
        msg = assertion.message or f"'{assertion.attribute}' is '{val}', expected false."
        return False, msg

    # ── greater_than_or_equal ────────────────────────────────────────────────
    if op == "greater_than_or_equal":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        num_val = _coerce_numeric(val)
        num_exp = _coerce_numeric(assertion.expected)
        if num_val is None or num_exp is None:
            msg = assertion.message or (
                f"Cannot compare '{assertion.attribute}' ({val!r}) with {assertion.expected!r}."
            )
            return False, msg
        if num_val >= num_exp:
            return True, f"'{assertion.attribute}' ({num_val}) >= {num_exp}."
        msg = assertion.message or (
            f"'{assertion.attribute}' is {num_val}, must be >= {num_exp}."
        )
        return False, msg

    # ── less_than_or_equal ───────────────────────────────────────────────────
    if op == "less_than_or_equal":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        num_val = _coerce_numeric(val)
        num_exp = _coerce_numeric(assertion.expected)
        if num_val is None or num_exp is None:
            msg = assertion.message or (
                f"Cannot compare '{assertion.attribute}' ({val!r}) with {assertion.expected!r}."
            )
            return False, msg
        if num_val <= num_exp:
            return True, f"'{assertion.attribute}' ({num_val}) <= {num_exp}."
        msg = assertion.message or (
            f"'{assertion.attribute}' is {num_val}, must be <= {num_exp}."
        )
        return False, msg

    # ── matches ──────────────────────────────────────────────────────────────
    if op == "matches":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        pattern = assertion.pattern or str(assertion.expected or "")
        try:
            if re.search(pattern, str(val)):
                return True, f"'{assertion.attribute}' matches pattern '{pattern}'."
            msg = assertion.message or (
                f"'{assertion.attribute}' ('{val}') does not match pattern '{pattern}'."
            )
            return False, msg
        except re.error as exc:
            return False, f"Invalid regex pattern '{pattern}': {exc}"

    # ── not_matches ──────────────────────────────────────────────────────────
    if op == "not_matches":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        pattern = assertion.pattern or str(assertion.expected or "")
        try:
            if not re.search(pattern, str(val)):
                return True, f"'{assertion.attribute}' does not match pattern '{pattern}'."
            msg = assertion.message or (
                f"'{assertion.attribute}' ('{val}') must not match pattern '{pattern}'."
            )
            return False, msg
        except re.error as exc:
            return False, f"Invalid regex pattern '{pattern}': {exc}"

    # ── key_exists ───────────────────────────────────────────────────────────
    if op == "key_exists":
        found, tag_map = get_nested(attrs, assertion.attribute)
        key = assertion.key
        if not found or not isinstance(tag_map, dict):
            msg = assertion.message or (
                f"'{assertion.attribute}' is not a map or does not exist. "
                f"Key '{key}' cannot be checked."
            )
            return False, msg
        if key in tag_map:
            return True, f"Key '{key}' found in '{assertion.attribute}'."
        msg = assertion.message or f"Key '{key}' not found in '{assertion.attribute}'."
        return False, msg

    # ── has_associated_resource ──────────────────────────────────────────────
    if op == "has_associated_resource":
        # Check whether any other resource references this block's address
        address = block.address
        for res in tf.resources:
            raw_str = str(res.raw)
            if address in raw_str or block.name in raw_str:
                if res.address != address:
                    return True, f"Associated resource found for '{address}'."
        msg = assertion.message or f"No associated resource references '{address}'."
        return False, msg

    # ── not_contains ─────────────────────────────────────────────────────────
    if op == "not_contains":
        found, val = get_nested(attrs, assertion.attribute)
        if not found:
            msg = assertion.message or f"Attribute '{assertion.attribute}' not found."
            return False, msg
        expected_str = str(assertion.expected or "")
        if expected_str not in str(val):
            return True, f"'{assertion.attribute}' does not contain '{expected_str}'."
        msg = assertion.message or (
            f"'{assertion.attribute}' must not contain '{expected_str}'."
        )
        return False, msg

    # ── Unknown operator ─────────────────────────────────────────────────────
    raise SkipAssertion(f"Unknown operator '{op}' — skipping.")


class SkipAssertion(Exception):
    """Raised when an assertion should be skipped (unsupported operator)."""


def _find_matching_blocks(scope: Scope, tf: IaCState) -> list[IaCBlock]:
    """Return Terraform blocks matching the check scope."""
    block_type = scope.block_type

    if block_type == "resource":
        if scope.resource_types:
            return [b for b in tf.resources if b.type in scope.resource_types]
        return list(tf.resources)

    if block_type == "provider":
        if scope.provider_name:
            return [b for b in tf.providers if b.type == scope.provider_name]
        return list(tf.providers)

    if block_type == "variable":
        return list(tf.variables)

    if block_type == "terraform":
        return list(tf.config_blocks)

    if block_type == "module":
        return list(tf.modules)

    logger.warning("Unknown block_type '%s' in scope.", block_type)
    return []


def _run_check(
    check: Check, control: Control, tf: IaCState
) -> list[CheckResult]:
    """Run a single check against all matching Terraform blocks."""
    results: list[CheckResult] = []
    matching_blocks = _find_matching_blocks(check.scope, tf)

    if not matching_blocks:
        results.append(
            CheckResult(
                check_id=check.id,
                check_title=check.title,
                control_id=control.id,
                severity=check.severity,
                status="SKIP",
                resource="(none)",
                message="No matching resources found in Terraform configuration.",
                remediation=check.remediation,
            )
        )
        return results

    for block in matching_blocks:
        failed_messages: list[str] = []
        skipped = False

        for assertion in check.assertions:
            try:
                passed, msg = evaluate_assertion(assertion, block, tf)
                if not passed:
                    failed_messages.append(msg)
            except SkipAssertion as exc:
                skipped = True
                logger.debug("Skipping assertion in check %s: %s", check.id, exc)

        if skipped and not check.assertions:
            status = "SKIP"
            message = "All assertions skipped (unsupported operators)."
            results.append(
                CheckResult(
                    check_id=check.id,
                    check_title=check.title,
                    control_id=control.id,
                    severity=check.severity,
                    status=status,
                    resource=block.address,
                    message=message,
                    remediation=check.remediation,
                )
            )
            continue

        if failed_messages:
            status = "FAIL"
            message = "; ".join(failed_messages)
        elif skipped and not failed_messages:
            # Some assertions were skipped but none failed → optimistically SKIP
            status = "SKIP"
            message = "Some assertions skipped (unsupported operators); no failures detected."
        else:
            status = "PASS"
            message = "All assertions passed."

        results.append(
            CheckResult(
                check_id=check.id,
                check_title=check.title,
                control_id=control.id,
                severity=check.severity,
                status=status,
                resource=block.address,
                message=message,
                remediation=check.remediation,
            )
        )

    return results


def run_controls(
    controls: list[Control],
    tf: IaCState,
    engine_name: str | None = None,
) -> list[ControlResult]:
    """Run all controls against the parsed IaC state.

    Args:
        controls: List of controls with automated checks.
        tf: Parsed IaC state (from any plugin).
        engine_name: When set, only checks whose ``engine`` field matches this
            value are evaluated.  Checks for other engines are silently skipped.
            Pass ``None`` (default) to run all checks regardless of engine.

    Returns:
        List of :class:`ControlResult` objects.
    """
    control_results: list[ControlResult] = []

    for control in controls:
        all_check_results: list[CheckResult] = []

        for check in control.checks:
            if engine_name is not None and check.engine != engine_name:
                # Skip checks that target a different IaC engine.
                continue
            check_results = _run_check(check, control, tf)
            all_check_results.extend(check_results)

        control_results.append(
            ControlResult(
                control=control,
                results=all_check_results,
            )
        )

    return control_results


def filter_by_severity(
    control_results: list[ControlResult], min_severity: str
) -> list[ControlResult]:
    """Filter control results to only include checks at or above min_severity."""
    min_level = SEVERITY_ORDER.get(min_severity.lower(), 0)
    filtered: list[ControlResult] = []

    for cr in control_results:
        filtered_results = [
            r
            for r in cr.results
            if SEVERITY_ORDER.get(r.severity.lower(), 0) >= min_level
        ]
        if filtered_results:
            filtered.append(ControlResult(control=cr.control, results=filtered_results))

    return filtered
