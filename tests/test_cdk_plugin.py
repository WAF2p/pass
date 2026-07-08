"""Tests for the AWS CDK TypeScript source-level plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.engine import run_controls
from wafpass.iac.plugins.cdk import CdkPlugin
from wafpass.loader import load_controls

FIXTURES = Path(__file__).parent / "fixtures"
CONTROLS_DIR = FIXTURES / "controls"


def test_plugin_can_parse_ts_directory() -> None:
    plugin = CdkPlugin()
    assert plugin.can_parse(FIXTURES / "cdk_ts") is True


def test_plugin_parses_cdk_source_resources() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "non_compliant.ts")

    addresses = {r.address for r in state.resources}
    assert "aws_s3_bucket.DataLakeBucket" in addresses
    assert "aws_dynamodb_table.ConfigTable" in addresses
    assert "aws_lambda_function.ProcessorFunction" in addresses


def test_parsed_attributes_match_terraform_shape() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "compliant.ts")

    by_addr = {r.address: r.attributes for r in state.resources}
    assert by_addr["aws_s3_bucket.DataLakeBucket"]["versioning"]["enabled"] is True
    assert by_addr["aws_dynamodb_table.ConfigTable"]["point_in_time_recovery"]["enabled"] is True
    assert (
        by_addr["aws_lambda_function.ProcessorFunction"]["environment"]["variables"][
            "AWS_XRAY_TRACING_NAME"
        ]
        == "processor-function"
    )


def test_non_compliant_cdk_fails_cross_iac_controls() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "non_compliant.ts")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="cdk")

    failing = {(r.control_id, r.resource) for cr in results for r in cr.results if r.status == "FAIL"}
    assert ("WAF-CROSS-001", "aws_s3_bucket.DataLakeBucket") in failing
    assert ("WAF-CROSS-002", "aws_dynamodb_table.ConfigTable") in failing
    assert ("WAF-CROSS-003", "aws_lambda_function.ProcessorFunction") in failing


def test_compliant_cdk_passes_cross_iac_controls() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "compliant.ts")
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name="cdk")

    failing = {(r.control_id, r.resource) for cr in results for r in cr.results if r.status == "FAIL"}
    assert ("WAF-CROSS-001", "aws_s3_bucket.DataLakeBucket") not in failing
    assert ("WAF-CROSS-002", "aws_dynamodb_table.ConfigTable") not in failing
    assert ("WAF-CROSS-003", "aws_lambda_function.ProcessorFunction") not in failing


def test_cdk_extract_regions() -> None:
    plugin = CdkPlugin()
    state = plugin.parse(FIXTURES / "cdk_ts" / "compliant.ts")
    # Fixtures have no explicit region; region extraction should not crash.
    regions = plugin.extract_regions(state)
    assert isinstance(regions, list)
