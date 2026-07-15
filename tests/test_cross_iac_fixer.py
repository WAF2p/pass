"""Tests for cross-framework auto-fix (CDK/TypeScript and Pulumi/Python)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.engine import run_controls
from wafpass.fixer import (
    PatchKind,
    apply_fix_plan,
    build_fix_plan,
    make_locator,
)
from wafpass.iac.plugins.cdk import CdkPlugin
from wafpass.iac.plugins.pulumi import PulumiPlugin
from wafpass.loader import load_controls

FIXTURES = Path(__file__).parent / "fixtures"
CONTROLS_DIR = FIXTURES / "controls"


def _run_fix_pipeline(path: Path, iac: str) -> tuple:
    plugin = {"cdk": CdkPlugin(), "pulumi": PulumiPlugin()}[iac]
    state = plugin.parse(path)
    controls = load_controls(CONTROLS_DIR)
    results = run_controls(controls, state, engine_name=iac)
    locator = make_locator(iac, [path])
    plan = build_fix_plan(results, state, controls, locator, framework=iac)
    dry = apply_fix_plan(plan, locator, dry_run=True, backup=False)
    return plan, dry, state, results


def test_cdk_fix_plan_derives_three_patches() -> None:
    plan, _, _, _ = _run_fix_pipeline(FIXTURES / "cdk_ts" / "non_compliant.ts", "cdk")
    active = plan.active_patches
    assert len(active) == 3
    kinds = {(p.address, p.attribute_path, p.patch_kind) for p in active}
    assert ("aws_s3_bucket.DataLakeBucket", "versioning.enabled", PatchKind.SET_NESTED) in kinds
    assert ("aws_dynamodb_table.ConfigTable", "point_in_time_recovery.enabled", PatchKind.SET_NESTED) in kinds
    assert (
        "aws_lambda_function.ProcessorFunction",
        "environment.variables.AWS_XRAY_TRACING_NAME",
        PatchKind.SET_NESTED_MAP_KEY,
    ) in kinds


def test_cdk_fix_dry_run_injects_required_props() -> None:
    _, dry, _, _ = _run_fix_pipeline(FIXTURES / "cdk_ts" / "non_compliant.ts", "cdk")
    assert len(dry.diffs) == 1
    patched = next(iter(dry.diffs.values()))[1]
    assert "versioned: true" in patched
    assert "pointInTimeRecovery: true" in patched
    assert "environment:" in patched
    assert "AWS_XRAY_TRACING_NAME:" in patched
    # Existing expressions must be preserved.
    assert "cdk.RemovalPolicy.RETAIN" in patched
    assert "aws_dynamodb.AttributeType.STRING" in patched


def test_pulumi_fix_plan_derives_three_patches() -> None:
    plan, _, _, _ = _run_fix_pipeline(FIXTURES / "pulumi_py" / "non_compliant.py", "pulumi")
    active = plan.active_patches
    assert len(active) == 3
    kinds = {(p.address, p.attribute_path, p.patch_kind) for p in active}
    assert ("aws_s3_bucket.data-lake-bucket", "versioning.enabled", PatchKind.SET_NESTED) in kinds
    assert ("aws_dynamodb_table.config-table", "point_in_time_recovery.enabled", PatchKind.SET_NESTED) in kinds
    assert (
        "aws_lambda_function.processor-function",
        "environment.variables.AWS_XRAY_TRACING_NAME",
        PatchKind.SET_NESTED_MAP_KEY,
    ) in kinds


def test_pulumi_fix_dry_run_injects_required_kwargs() -> None:
    _, dry, _, _ = _run_fix_pipeline(FIXTURES / "pulumi_py" / "non_compliant.py", "pulumi")
    assert len(dry.diffs) == 1
    patched = next(iter(dry.diffs.values()))[1]
    assert "versioning={'enabled': True}" in patched
    assert "point_in_time_recovery={'enabled': True}" in patched
    assert "environment={'variables': {'AWS_XRAY_TRACING_NAME': 'TODO-fill-in'}}" in patched
    # The patched code must be valid Python.
    compile(patched, "patched.py", "exec")


def test_cdk_fix_improves_score_on_apply() -> None:
    from wafpass.fixer import compute_fix_delta

    path = FIXTURES / "cdk_ts" / "non_compliant.ts"
    plugin = CdkPlugin()
    state = plugin.parse(path)
    controls = load_controls(CONTROLS_DIR)
    original_results = run_controls(controls, state, engine_name="cdk")
    locator = make_locator("cdk", [path])
    plan = build_fix_plan(original_results, state, controls, locator, framework="cdk")

    apply_fix_plan(plan, locator, dry_run=True, backup=False)

    # Simulate applying by re-parsing the fixture after writing the patched text.
    dry = apply_fix_plan(plan, locator, dry_run=True, backup=False)
    patched_text = next(iter(dry.diffs.values()))[1]
    new_path = path.with_name("non_compliant_patched.ts")
    new_path.write_text(patched_text, encoding="utf-8")
    try:
        new_state = plugin.parse(new_path)
        new_results = run_controls(controls, new_state, engine_name="cdk")
        delta = compute_fix_delta(original_results, new_results)
        assert len(delta.resolved) == 3
        assert not delta.regressions
    finally:
        new_path.unlink(missing_ok=True)


def test_pulumi_fix_improves_score_on_apply() -> None:
    from wafpass.fixer import compute_fix_delta

    path = FIXTURES / "pulumi_py" / "non_compliant.py"
    plugin = PulumiPlugin()
    state = plugin.parse(path)
    controls = load_controls(CONTROLS_DIR)
    original_results = run_controls(controls, state, engine_name="pulumi")
    locator = make_locator("pulumi", [path])
    plan = build_fix_plan(original_results, state, controls, locator, framework="pulumi")

    dry = apply_fix_plan(plan, locator, dry_run=True, backup=False)
    patched_text = next(iter(dry.diffs.values()))[1]
    new_path = path.with_name("non_compliant_patched.py")
    new_path.write_text(patched_text, encoding="utf-8")
    try:
        new_state = plugin.parse(new_path)
        new_results = run_controls(controls, new_state, engine_name="pulumi")
        delta = compute_fix_delta(original_results, new_results)
        assert len(delta.resolved) == 3
        assert not delta.regressions
    finally:
        new_path.unlink(missing_ok=True)
