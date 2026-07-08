"""Integration tests proving cross-IaC controls work for Terraform, CDK/TS, and Pulumi/Python."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.engine import run_controls
from wafpass.iac.plugins.cdk import CdkPlugin
from wafpass.iac.plugins.pulumi import PulumiPlugin
from wafpass.iac.plugins.terraform import TerraformPlugin
from wafpass.loader import load_controls

FIXTURES = Path(__file__).parent / "fixtures"
CONTROLS_DIR = FIXTURES / "controls"


def _failing_addresses(results: list, control_id: str) -> set:
    for cr in results:
        if cr.control.id == control_id:
            return {r.resource for r in cr.results if r.status == "FAIL"}
    return set()


def test_cross_iac_controls_loaded() -> None:
    controls = load_controls(CONTROLS_DIR)
    ids = {c.id for c in controls}
    assert "WAF-CROSS-001" in ids
    assert "WAF-CROSS-002" in ids
    assert "WAF-CROSS-003" in ids


def test_terraform_adapter_evaluates_cross_iac_controls() -> None:
    plugin = TerraformPlugin()
    tf_path = FIXTURES / "fix_non_compliant" / "main.tf"
    if not tf_path.exists():
        pytest.skip("Terraform fix fixture not present")
    state = plugin.parse(tf_path)
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="terraform")
    # Smoke test: no crashes and results are populated.
    assert any(cr.results for cr in results)


def test_cdk_adapter_evaluates_cross_iac_controls() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "non_compliant.ts")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="cdk")

    assert "aws_s3_bucket.DataLakeBucket" in _failing_addresses(results, "WAF-CROSS-001")
    assert "aws_dynamodb_table.ConfigTable" in _failing_addresses(results, "WAF-CROSS-002")
    assert "aws_lambda_function.ProcessorFunction" in _failing_addresses(results, "WAF-CROSS-003")


def test_pulumi_adapter_evaluates_cross_iac_controls() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "non_compliant.py")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="pulumi")

    assert "aws_s3_bucket.data-lake-bucket" in _failing_addresses(results, "WAF-CROSS-001")
    assert "aws_dynamodb_table.config-table" in _failing_addresses(results, "WAF-CROSS-002")
    assert "aws_lambda_function.processor-function" in _failing_addresses(results, "WAF-CROSS-003")
