"""Tests for wafpass.loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from wafpass.loader import load_controls
from wafpass.models import Control


# ── Inline YAML fixtures ──────────────────────────────────────────────────────

CONTROL_COST_010 = textwrap.dedent(
    """
    id: WAF-COST-010
    title: "Cost Allocation Tagging Enforced"
    pillar: "cost"
    status: "active"
    severity: "high"
    category: "cost-allocation"
    type: [governance, configuration]
    tags: [tagging, finops]
    description: >
      All resources must carry mandatory cost tags.
    rationale: >
      Enables cost attribution.
    checks:
      - id: "waf-cost-010.tf.aws.compute-mandatory-tags"
        engine: "terraform"
        provider: "aws"
        automated: true
        severity: "high"
        title: "AWS compute resources must have mandatory tags"
        scope:
          block_type: "resource"
          resource_types:
            - "aws_instance"
            - "aws_s3_bucket"
        assertions:
          - attribute: "tags"
            op: "key_exists"
            key: "cost-center"
            message: "Resource is missing the mandatory 'cost-center' tag."
          - attribute: "tags"
            op: "key_exists"
            key: "owner"
            message: "Resource is missing the mandatory 'owner' tag."
        on_fail: "violation"
        remediation: "Add mandatory tags to all resources."
    references:
      narrative: "modules/pillar-cost/pages/controls.adoc#WAF-COST-010"
      related_controls:
        - "WAF-COST-020"
    """
)

CONTROL_COST_020 = textwrap.dedent(
    """
    id: WAF-COST-020
    title: "Cost Budgets Configured"
    pillar: "cost"
    status: "active"
    severity: "high"
    category: "budget-control"
    type: [governance]
    tags: [budget]
    description: >
      Budgets must be defined as IaC.
    checks:
      - id: "waf-cost-020.tf.aws.budgets-budget-exists"
        engine: "terraform"
        provider: "aws"
        automated: true
        severity: "high"
        title: "AWS budget must be defined as IaC resource"
        scope:
          block_type: "resource"
          resource_types:
            - "aws_budgets_budget"
        assertions:
          - attribute: "budget_type"
            op: "equals"
            value: "COST"
            message: "Budget must be of type COST."
        on_fail: "violation"
        remediation: "Add an aws_budgets_budget resource."
    """
)

CONTROL_SOV_010 = textwrap.dedent(
    """
    id: WAF-SOV-010
    title: "Data Residency Policy Defined"
    pillar: "sovereign"
    status: "active"
    severity: "high"
    category: "data-residency"
    type: [governance]
    tags: [data-residency]
    description: >
      Data residency policy must be documented.
    checks:
      - id: "waf-sov-010.tf.aws.provider-region-explicit"
        engine: "terraform"
        provider: "aws"
        automated: true
        severity: "critical"
        title: "AWS provider must have region set"
        scope:
          block_type: "provider"
          provider_name: "aws"
        assertions:
          - attribute: "region"
            op: "attribute_exists"
            message: "AWS provider is missing explicit region."
        on_fail: "violation"
        remediation: "Set region in provider block."
    """
)

CONTROL_NO_AUTOMATED = textwrap.dedent(
    """
    id: WAF-COST-099
    title: "Manual Review Only"
    pillar: "cost"
    status: "active"
    severity: "low"
    category: "governance"
    type: [governance]
    tags: []
    description: >
      This control has no automated checks.
    checks:
      - id: "waf-cost-099.manual"
        engine: "manual"
        provider: "any"
        automated: false
        severity: "low"
        title: "Manual review required"
        scope:
          block_type: "resource"
        assertions: []
        on_fail: "violation"
        remediation: "Perform manual review."
    """
)


@pytest.fixture()
def controls_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with YAML control files."""
    (tmp_path / "WAF-COST-010.yml").write_text(CONTROL_COST_010, encoding="utf-8")
    (tmp_path / "WAF-COST-020.yml").write_text(CONTROL_COST_020, encoding="utf-8")
    (tmp_path / "WAF-SOV-010.yml").write_text(CONTROL_SOV_010, encoding="utf-8")
    (tmp_path / "WAF-COST-099.yml").write_text(CONTROL_NO_AUTOMATED, encoding="utf-8")
    return tmp_path


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestLoadControls:
    def test_loads_all_automated_controls(self, controls_dir: Path) -> None:
        """Should load all controls that have at least one automated check."""
        controls = load_controls(controls_dir)
        ids = {c.id for c in controls}
        assert "WAF-COST-010" in ids
        assert "WAF-COST-020" in ids
        assert "WAF-SOV-010" in ids

    def test_skips_non_automated_controls(self, controls_dir: Path) -> None:
        """Controls with only non-automated checks should be skipped."""
        controls = load_controls(controls_dir)
        ids = {c.id for c in controls}
        assert "WAF-COST-099" not in ids

    def test_filter_by_pillar_cost(self, controls_dir: Path) -> None:
        """Filtering by 'cost' pillar should return only COST controls."""
        controls = load_controls(controls_dir, pillar="cost")
        assert all(c.pillar == "cost" for c in controls)
        ids = {c.id for c in controls}
        assert "WAF-SOV-010" not in ids

    def test_filter_by_pillar_sovereign(self, controls_dir: Path) -> None:
        """Filtering by 'sovereign' pillar should return only SOV controls."""
        controls = load_controls(controls_dir, pillar="sovereign")
        assert all(c.pillar == "sovereign" for c in controls)
        ids = {c.id for c in controls}
        assert "WAF-COST-010" not in ids

    def test_filter_by_explicit_ids(self, controls_dir: Path) -> None:
        """Filtering by explicit IDs should return only matching controls."""
        controls = load_controls(controls_dir, ids=["WAF-COST-010"])
        assert len(controls) == 1
        assert controls[0].id == "WAF-COST-010"

    def test_filter_by_multiple_ids(self, controls_dir: Path) -> None:
        """Filtering by multiple IDs should return all matching controls."""
        controls = load_controls(controls_dir, ids=["WAF-COST-010", "WAF-SOV-010"])
        ids = {c.id for c in controls}
        assert ids == {"WAF-COST-010", "WAF-SOV-010"}

    def test_empty_dir_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty controls directory should return an empty list."""
        controls = load_controls(tmp_path)
        assert controls == []

    def test_nonexistent_dir_returns_empty_list(self, tmp_path: Path) -> None:
        """A non-existent directory should return an empty list."""
        controls = load_controls(tmp_path / "nonexistent")
        assert controls == []

    def test_control_fields_parsed_correctly(self, controls_dir: Path) -> None:
        """Control fields should be correctly parsed from YAML."""
        controls = load_controls(controls_dir, ids=["WAF-COST-010"])
        assert len(controls) == 1
        ctrl = controls[0]
        assert ctrl.id == "WAF-COST-010"
        assert ctrl.title == "Cost Allocation Tagging Enforced"
        assert ctrl.pillar == "cost"
        assert ctrl.severity == "high"
        assert ctrl.category == "cost-allocation"

    def test_check_parsed_correctly(self, controls_dir: Path) -> None:
        """Check fields should be correctly parsed from YAML."""
        controls = load_controls(controls_dir, ids=["WAF-COST-010"])
        ctrl = controls[0]
        assert len(ctrl.checks) == 1
        chk = ctrl.checks[0]
        assert chk.id == "waf-cost-010.tf.aws.compute-mandatory-tags"
        assert chk.engine == "terraform"
        assert chk.provider == "aws"
        assert chk.automated is True
        assert chk.scope.block_type == "resource"
        assert "aws_instance" in chk.scope.resource_types

    def test_assertion_key_exists_parsed(self, controls_dir: Path) -> None:
        """key_exists assertions should have the 'key' field populated."""
        controls = load_controls(controls_dir, ids=["WAF-COST-010"])
        chk = controls[0].checks[0]
        assert len(chk.assertions) == 2
        first = chk.assertions[0]
        assert first.op == "key_exists"
        assert first.key == "cost-center"

    def test_assertion_equals_value_normalised(self, controls_dir: Path) -> None:
        """YAML 'value' field should be mapped to assertion.expected."""
        controls = load_controls(controls_dir, ids=["WAF-COST-020"])
        chk = controls[0].checks[0]
        first = chk.assertions[0]
        assert first.op == "equals"
        assert first.expected == "COST"

    def test_provider_scope_parsed(self, controls_dir: Path) -> None:
        """Provider scope should have provider_name populated."""
        controls = load_controls(controls_dir, ids=["WAF-SOV-010"])
        chk = controls[0].checks[0]
        assert chk.scope.block_type == "provider"
        assert chk.scope.provider_name == "aws"
