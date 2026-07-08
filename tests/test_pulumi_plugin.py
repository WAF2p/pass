"""Tests for the Pulumi Python source-level plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.engine import run_controls
from wafpass.iac.plugins.pulumi import PulumiPlugin
from wafpass.loader import load_controls

FIXTURES = Path(__file__).parent / "fixtures"
CONTROLS_DIR = FIXTURES / "controls"


def test_plugin_can_parse_py_directory() -> None:
    plugin = PulumiPlugin()
    assert plugin.can_parse(FIXTURES / "pulumi_py") is True


def test_plugin_parses_pulumi_resources() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "non_compliant.py")

    addresses = {r.address for r in state.resources}
    assert "aws_s3_bucket.data-lake-bucket" in addresses
    assert "aws_dynamodb_table.config-table" in addresses
    assert "aws_lambda_function.processor-function" in addresses


def test_parsed_attributes_match_terraform_shape() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "compliant.py")

    by_addr = {r.address: r.attributes for r in state.resources}
    assert by_addr["aws_s3_bucket.data-lake-bucket"]["versioning"]["enabled"] is True
    assert by_addr["aws_dynamodb_table.config-table"]["point_in_time_recovery"]["enabled"] is True
    assert (
        by_addr["aws_lambda_function.processor-function"]["environment"]["variables"][
            "AWS_XRAY_TRACING_NAME"
        ]
        == "processor-function"
    )


def test_non_compliant_pulumi_fails_cross_iac_controls() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "non_compliant.py")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="pulumi")

    failing = {(r.control_id, r.resource) for cr in results for r in cr.results if r.status == "FAIL"}
    assert ("WAF-CROSS-001", "aws_s3_bucket.data-lake-bucket") in failing
    assert ("WAF-CROSS-002", "aws_dynamodb_table.config-table") in failing
    assert ("WAF-CROSS-003", "aws_lambda_function.processor-function") in failing


def test_compliant_pulumi_passes_cross_iac_controls() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "compliant.py")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="pulumi")

    failing = {(r.control_id, r.resource) for cr in results for r in cr.results if r.status == "FAIL"}
    assert ("WAF-CROSS-001", "aws_s3_bucket.data-lake-bucket") not in failing
    assert ("WAF-CROSS-002", "aws_dynamodb_table.config-table") not in failing
    assert ("WAF-CROSS-003", "aws_lambda_function.processor-function") not in failing


def test_pulumi_extract_regions() -> None:
    plugin = PulumiPlugin()
    state = plugin.parse(FIXTURES / "pulumi_py" / "compliant.py")
    regions = plugin.extract_regions(state)
    assert isinstance(regions, list)
