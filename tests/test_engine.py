"""Tests for wafpass.engine assertion evaluation."""

from __future__ import annotations

import pytest

from wafpass.engine import SkipAssertion, evaluate_assertion, get_nested
from wafpass.models import Assertion
from wafpass.parser import TerraformBlock, TerraformState


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_block(attrs: dict, block_type: str = "resource", rtype: str = "aws_s3_bucket", name: str = "example") -> TerraformBlock:
    """Create a TerraformBlock with the given attributes."""
    return TerraformBlock(
        block_type=block_type,
        type=rtype,
        name=name,
        address=f"{rtype}.{name}",
        attributes=attrs,
        raw={},
    )


def make_assertion(**kwargs) -> Assertion:
    """Create an Assertion with sensible defaults."""
    return Assertion(
        attribute=kwargs.get("attribute", "some_attr"),
        op=kwargs.get("op", "attribute_exists"),
        expected=kwargs.get("expected", None),
        key=kwargs.get("key", None),
        pattern=kwargs.get("pattern", None),
        message=kwargs.get("message", None),
        fallback_attribute=kwargs.get("fallback_attribute", None),
    )


EMPTY_STATE = TerraformState()


# ── get_nested ────────────────────────────────────────────────────────────────


class TestGetNested:
    def test_flat_key_found(self) -> None:
        found, val = get_nested({"region": "eu-central-1"}, "region")
        assert found is True
        assert val == "eu-central-1"

    def test_flat_key_missing(self) -> None:
        found, val = get_nested({}, "region")
        assert found is False
        assert val is None

    def test_nested_key_found(self) -> None:
        d = {"tags": {"cost-center": "platform", "owner": "team"}}
        found, val = get_nested(d, "tags.cost-center")
        assert found is True
        assert val == "platform"

    def test_nested_key_missing(self) -> None:
        d = {"tags": {"owner": "team"}}
        found, val = get_nested(d, "tags.cost-center")
        assert found is False

    def test_non_dict_intermediate(self) -> None:
        d = {"tags": "not-a-dict"}
        found, val = get_nested(d, "tags.cost-center")
        assert found is False


# ── attribute_exists ──────────────────────────────────────────────────────────


class TestAttributeExists:
    def test_attribute_present(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(attribute="region", op="attribute_exists")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_attribute_missing(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="region", op="attribute_exists")
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "region" in msg

    def test_attribute_none(self) -> None:
        block = make_block({"region": None})
        assertion = make_assertion(attribute="region", op="attribute_exists")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── key_exists ────────────────────────────────────────────────────────────────


class TestKeyExists:
    def test_key_present_in_tags(self) -> None:
        block = make_block({"tags": {"cost-center": "platform", "owner": "team"}})
        assertion = make_assertion(attribute="tags", op="key_exists", key="cost-center")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_key_missing_from_tags(self) -> None:
        block = make_block({"tags": {"owner": "team"}})
        assertion = make_assertion(attribute="tags", op="key_exists", key="cost-center")
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "cost-center" in msg

    def test_tags_attribute_missing(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="tags", op="key_exists", key="cost-center")
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_tags_not_a_dict(self) -> None:
        block = make_block({"tags": "not-a-map"})
        assertion = make_assertion(attribute="tags", op="key_exists", key="cost-center")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── is_true / is_false ────────────────────────────────────────────────────────


class TestIsTrue:
    def test_bool_true(self) -> None:
        block = make_block({"enabled": True})
        assertion = make_assertion(attribute="enabled", op="is_true")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_string_true(self) -> None:
        block = make_block({"enabled": "true"})
        assertion = make_assertion(attribute="enabled", op="is_true")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_bool_false_fails(self) -> None:
        block = make_block({"enabled": False})
        assertion = make_assertion(attribute="enabled", op="is_true")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_missing_attribute_fails(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="enabled", op="is_true")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


class TestIsFalse:
    def test_bool_false(self) -> None:
        block = make_block({"enabled": False})
        assertion = make_assertion(attribute="enabled", op="is_false")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_bool_true_fails(self) -> None:
        block = make_block({"enabled": True})
        assertion = make_assertion(attribute="enabled", op="is_false")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_string_false(self) -> None:
        block = make_block({"enabled": "false"})
        assertion = make_assertion(attribute="enabled", op="is_false")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True


# ── greater_than_or_equal / less_than_or_equal ────────────────────────────────


class TestNumericComparisons:
    def test_gte_passes(self) -> None:
        block = make_block({"amount": 100})
        assertion = make_assertion(attribute="amount", op="greater_than_or_equal", expected=1)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_gte_equal_passes(self) -> None:
        block = make_block({"amount": 1})
        assertion = make_assertion(attribute="amount", op="greater_than_or_equal", expected=1)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_gte_fails(self) -> None:
        block = make_block({"amount": 0})
        assertion = make_assertion(attribute="amount", op="greater_than_or_equal", expected=1)
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "0" in msg

    def test_lte_passes(self) -> None:
        block = make_block({"threshold": 80})
        assertion = make_assertion(attribute="threshold", op="less_than_or_equal", expected=100)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_lte_fails(self) -> None:
        block = make_block({"threshold": 150})
        assertion = make_assertion(attribute="threshold", op="less_than_or_equal", expected=100)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_string_number_coerced(self) -> None:
        block = make_block({"amount": "1000"})
        assertion = make_assertion(attribute="amount", op="greater_than_or_equal", expected=1)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_missing_attribute_fails(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="amount", op="greater_than_or_equal", expected=1)
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── matches / not_matches ─────────────────────────────────────────────────────


class TestMatchesOperators:
    def test_matches_passes(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(attribute="region", op="matches", pattern=r"^eu-")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_matches_fails(self) -> None:
        block = make_block({"region": "us-east-1"})
        assertion = make_assertion(attribute="region", op="matches", pattern=r"^eu-")
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "us-east-1" in msg

    def test_not_matches_passes(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(attribute="region", op="not_matches", pattern=r"^us-")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_not_matches_fails(self) -> None:
        block = make_block({"region": "us-east-1"})
        assertion = make_assertion(attribute="region", op="not_matches", pattern=r"^us-")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_matches_missing_attribute(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="region", op="matches", pattern=r"^eu-")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── equals / not_equals ───────────────────────────────────────────────────────


class TestEqualsOperators:
    def test_equals_passes(self) -> None:
        block = make_block({"budget_type": "COST"})
        assertion = make_assertion(attribute="budget_type", op="equals", expected="COST")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_equals_fails(self) -> None:
        block = make_block({"budget_type": "USAGE"})
        assertion = make_assertion(attribute="budget_type", op="equals", expected="COST")
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "USAGE" in msg

    def test_not_equals_passes(self) -> None:
        block = make_block({"budget_type": "USAGE"})
        assertion = make_assertion(attribute="budget_type", op="not_equals", expected="COST")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_not_equals_fails(self) -> None:
        block = make_block({"budget_type": "COST"})
        assertion = make_assertion(attribute="budget_type", op="not_equals", expected="COST")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── in / not_in ──────────────────────────────────────────────────────────────


class TestInOperators:
    def test_in_passes(self) -> None:
        block = make_block({"time_unit": "MONTHLY"})
        assertion = make_assertion(attribute="time_unit", op="in", expected=["MONTHLY", "QUARTERLY"])
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_in_fails(self) -> None:
        block = make_block({"time_unit": "DAILY"})
        assertion = make_assertion(attribute="time_unit", op="in", expected=["MONTHLY", "QUARTERLY"])
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "DAILY" in msg

    def test_not_in_passes(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(attribute="region", op="not_in", expected=["us-east-1", "us-west-2"])
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_not_in_fails(self) -> None:
        block = make_block({"region": "us-east-1"})
        assertion = make_assertion(attribute="region", op="not_in", expected=["us-east-1", "us-west-2"])
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── not_empty ─────────────────────────────────────────────────────────────────


class TestNotEmpty:
    def test_non_empty_string_passes(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(attribute="region", op="not_empty")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_empty_string_fails(self) -> None:
        block = make_block({"region": ""})
        assertion = make_assertion(attribute="region", op="not_empty")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_empty_list_fails(self) -> None:
        block = make_block({"emails": []})
        assertion = make_assertion(attribute="emails", op="not_empty")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False

    def test_missing_attribute_fails(self) -> None:
        block = make_block({})
        assertion = make_assertion(attribute="region", op="not_empty")
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False


# ── skip operators ────────────────────────────────────────────────────────────


class TestSkipOperators:
    def test_unsupported_operator_raises_skip(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(op="has_associated_metric_filter")
        with pytest.raises(SkipAssertion):
            evaluate_assertion(assertion, block, EMPTY_STATE)

    def test_unknown_operator_raises_skip(self) -> None:
        block = make_block({"region": "eu-central-1"})
        assertion = make_assertion(op="totally_made_up_op")
        with pytest.raises(SkipAssertion):
            evaluate_assertion(assertion, block, EMPTY_STATE)


# ── attribute_exists_or_fallback ──────────────────────────────────────────────


class TestAttributeExistsOrFallback:
    def test_primary_attribute_exists(self) -> None:
        block = make_block({"location": "europe-west3"})
        assertion = make_assertion(
            attribute="location",
            op="attribute_exists_or_fallback",
            fallback_attribute="region",
        )
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_fallback_attribute_exists(self) -> None:
        block = make_block({"region": "europe-west3"})
        assertion = make_assertion(
            attribute="location",
            op="attribute_exists_or_fallback",
            fallback_attribute="region",
        )
        passed, _ = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is True

    def test_neither_exists(self) -> None:
        block = make_block({})
        assertion = make_assertion(
            attribute="location",
            op="attribute_exists_or_fallback",
            fallback_attribute="region",
        )
        passed, msg = evaluate_assertion(assertion, block, EMPTY_STATE)
        assert passed is False
        assert "location" in msg or "region" in msg
