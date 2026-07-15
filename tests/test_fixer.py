"""Tests for the WAF++ auto-fix engine."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from wafpass.engine import run_controls
from wafpass.fixer import (
    BLOCK_DEFAULTS,
    FixApplyResult,
    FixDelta,
    FindingInput,
    FixPlan,
    Patch,
    PatchKind,
    ResourceLocation,
    ResourceLocator,
    TextPatcher,
    _count_braces,
    _derive_patch_for_assertion,
    _is_expression,
    _lookup_block_template,
    _lookup_nested_default,
    _render_flat_template,
    _render_hcl,
    _render_hcl_pairs,
    _resolve_check_for_finding,
    _unquoted_hash,
    _write_atomic,
    apply_fix_plan,
    build_fix_plan,
    classify_findings,
    compute_fix_delta,
    render_diff,
    restore_backup,
)
from wafpass.iac.base import IaCBlock, IaCState
from wafpass.iac.plugins.terraform import TerraformPlugin
from wafpass.loader import load_controls
from wafpass.models import Assertion, Check, Control, Scope

FIXTURES_DIR = Path(__file__).with_name("fixtures")
NON_COMPLIANT_FIXTURE = FIXTURES_DIR / "fix_non_compliant" / "main.tf"
EXPECTED_FIXTURE = FIXTURES_DIR / "fix_compliant_expected" / "main.tf"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_assertion(attribute: str, op: str, **kwargs) -> Assertion:
    return Assertion(attribute=attribute, op=op, **kwargs)


def _make_dummy_block(attributes: dict | None = None) -> IaCBlock:
    return IaCBlock(
        block_type="resource",
        type="aws_s3_bucket",
        name="data",
        address="aws_s3_bucket.data",
        attributes=attributes or {},
        raw={},
    )


def _run_pipeline(path: Path) -> tuple[list, IaCState, list[Control]]:
    """Parse a single Terraform file and load all controls."""
    controls = load_controls(Path("controls"), pillar=None, ids=None, server_url="")
    plugin = TerraformPlugin()
    state = plugin.parse(path)
    results = run_controls(controls, state, engine_name="terraform")
    return results, state, controls


# ── HCL rendering ─────────────────────────────────────────────────────────────


def test_render_hcl_literals() -> None:
    assert _render_hcl(True) == "true"
    assert _render_hcl(False) == "false"
    assert _render_hcl(42) == "42"
    assert _render_hcl(3.14) == "3.14"
    assert _render_hcl("hello") == '"hello"'
    assert _render_hcl("true") == "true"
    assert _render_hcl("FALSE") == "false"
    assert _render_hcl(["a", 1, True]) == '["a", 1, true]'


def test_render_hcl_pairs_includes_newlines() -> None:
    lines = _render_hcl_pairs({"a": 1, "b": "two"}, "  ")
    assert lines == ["  a = 1\n", '  b = "two"\n']


def test_render_flat_template() -> None:
    from wafpass.fixer import BlockTemplate

    template = BlockTemplate({"enabled": True, "name": "test"})
    rendered = _render_flat_template(template)
    assert rendered == '{\n  enabled = true\n  name = "test"\n}'


def test_render_flat_template_jsonencode() -> None:
    from wafpass.fixer import BlockTemplate

    template = BlockTemplate({"deadLetterTargetArn": "", "maxReceiveCount": 3}, mode="jsonencode")
    rendered = _render_flat_template(template)
    assert rendered == 'jsonencode({\n  deadLetterTargetArn = ""\n  maxReceiveCount = 3\n})'


# ── Expression detection ──────────────────────────────────────────────────────


def test_is_expression_detects_dynamic_references() -> None:
    assert _is_expression('${var.foo}')
    assert _is_expression("local.bar")
    assert _is_expression("data.aws_caller_identity.current.account_id")
    assert _is_expression("module.vpc.vpc_id")
    assert _is_expression("each.value")
    assert _is_expression("count.index")
    assert _is_expression("path.module")
    assert _is_expression("merge(a, b)")
    assert _is_expression("try(a, b)")
    assert _is_expression("var.enabled ? 1 : 0")
    assert _is_expression("aws_iam_policy.policies[*]")
    assert _is_expression("[for k in keys : k]")


def test_is_expression_allows_literals() -> None:
    assert not _is_expression("true")
    assert not _is_expression("false")
    assert not _is_expression("123")
    assert not _is_expression('"static-string"')
    assert not _is_expression("us-west-2")


# ── Block template registry ─────────────────────────────────────────────────────


def test_lookup_block_template() -> None:
    template = _lookup_block_template("aws_dynamodb_table", "point_in_time_recovery")
    assert template is not None
    assert template.defaults == {"enabled": True}


def test_lookup_block_template_missing() -> None:
    assert _lookup_block_template("unknown", "foo") is None


def test_lookup_nested_default() -> None:
    assert _lookup_nested_default("aws_bedrockagent", "guardrail_configuration.guardrail_arn") == ""
    assert (
        _lookup_nested_default("aws_bedrockagent", "human_interaction_configuration.human_interpretation_timeout")
        == 3600
    )
    assert _lookup_nested_default("aws_lambda_function", "environment.variables.AWS_XRAY_TRACING_NAME") == "TODO-fill-in"


def test_lookup_nested_default_missing() -> None:
    assert _lookup_nested_default("aws_s3_bucket", "point_in_time_recovery.enabled") is None
    assert _lookup_nested_default("aws_bedrockagent", "guardrail_configuration.unknown") is None


def test_lookup_block_template_for_new_providers() -> None:
    # OCI
    oci = _lookup_block_template("oci_objectstorage_bucket", "versioning")
    assert oci is not None
    assert oci.defaults == {"status": "Enabled"}

    # Alibaba Cloud
    ali = _lookup_block_template("alicloud_oss_bucket", "server_side_encryption_rule")
    assert ali is not None
    assert ali.defaults == {"sse_algorithm": "AES256"}

    # STACKIT
    stackit = _lookup_block_template("stackit_ske_cluster", "maintenance")
    assert stackit is not None
    assert stackit.defaults["enable_kubernetes_version_updates"] is True


def test_lookup_nested_default_for_new_providers() -> None:
    assert (
        _lookup_nested_default(
            "oci_core_instance", "agent_config.is_management_disabled"
        )
        is False
    )
    assert (
        _lookup_nested_default("alicloud_ecs_instance", "metadata_options.http_tokens")
        == "required"
    )
    assert (
        _lookup_nested_default(
            "stackit_ske_cluster",
            "maintenance.enable_machine_image_version_updates",
        )
        is True
    )


def test_provider_block_types_match_bare_provider_names() -> None:
    """Provider blocks like provider.hcloud {} should resolve to the hcloud provider."""
    from wafpass.fix_providers import fix_provider_registry

    hcloud = fix_provider_registry.find_provider("terraform", None, "hcloud")
    assert hcloud is not None
    assert hcloud.name == "terraform_hcloud"

    aws = fix_provider_registry.find_provider("terraform", None, "aws")
    assert aws is not None
    assert aws.name == "terraform_aws"

    azurerm = fix_provider_registry.find_provider("terraform", None, "azurerm")
    assert azurerm is not None
    assert azurerm.name == "terraform_azure"


def test_classify_findings_handles_provider_blocks() -> None:
    """classify_findings should derive patches for provider blocks without fs access."""
    controls = load_controls(Path("controls"), pillar=None, ids=None, server_url="")
    # Find a tag-related control that can target any resource.
    findings = [
        FindingInput(
            control_id="WAF-AGN-040",
            check_id="WAF-AGN-040-01",
            resource="hcloud_server.nbg1",
            message="resource does not have required tag owner",
        ),
    ]
    plan = classify_findings(findings, controls, framework="terraform")
    # Either a patch or a skip is acceptable; the function must not crash.
    assert isinstance(plan, FixPlan)


def test_classify_findings_deduplicates_same_attribute_from_different_checks() -> None:
    """Controls with multiple checks asserting the same attribute should yield one patch."""
    controls = load_controls(Path("controls"), pillar=None, ids=None, server_url="")
    findings = [
        FindingInput(
            control_id="WAF-AGN-040",
            check_id="waf-agn-040.tf.aws.memory-versioning-enabled",
            resource="aws_s3_bucket.main",
            message="point_in_time_recovery must be enabled",
        ),
        FindingInput(
            control_id="WAF-AGN-040",
            check_id="waf-agn-040.tf.aws.state-persistence-enabled",
            resource="aws_s3_bucket.main",
            message="point_in_time_recovery must be enabled",
        ),
    ]
    plan = classify_findings(findings, controls, framework="terraform")
    active = plan.active_patches
    assert len(active) == 1, f"expected one active patch, got {len(active)}"
    assert active[0].attribute_path == "point_in_time_recovery.enabled"
    deduplicated = [p for p in plan.patches if p.already_applied]
    assert len(deduplicated) == 1


def test_resolve_check_for_provider_block_does_not_remap_to_resource_scope() -> None:
    """A provider-block finding must not be remapped to a resource-scoped check."""
    controls = load_controls(Path("controls"), pillar=None, ids=None, server_url="")
    control = next(c for c in controls if c.id == "WAF-SUS-030")
    check_by_id = {chk.id: chk for chk in control.checks}

    # Simulate a dashboard preview where provider.azurerm was mislabeled with the GCP check.
    finding = FindingInput(
        control_id="WAF-SUS-030",
        check_id="waf-sus-030.tf.google.preferred-regions",
        resource="provider.azurerm",
        message="region has elevated carbon intensity",
    )
    resolved = _resolve_check_for_finding(finding, control, check_by_id)
    # The azurerm check in this control is resource-scoped (azurerm_resource_group.location),
    # so we must not remap to it.  Keep the original check instead.
    assert resolved is not None
    assert resolved.id == "waf-sus-030.tf.google.preferred-regions"


# ── Patch derivation ──────────────────────────────────────────────────────────


def _make_check(assertion: Assertion) -> Check:
    return Check(
        id="chk-1",
        engine="terraform",
        provider="aws",
        automated=True,
        severity="medium",
        title="t",
        scope=Scope(block_type="resource", resource_types=["aws_s3_bucket"]),
        assertions=[assertion],
        on_fail="violation",
        remediation="r",
    )


def _derive(
    attribute: str,
    op: str,
    res_type: str = "aws_s3_bucket",
    block_attrs: dict | None = None,
    **kwargs,
) -> Patch | None:
    assertion = _make_assertion(attribute, op, **kwargs)
    check = _make_check(assertion)
    control = Control(
        id="WAF-TEST-001",
        title="Test",
        pillar="security",
        severity="medium",
        category="test",
        description="d",
        checks=[check],
    )
    result = _derive_patch_for_assertion(
        assertion=assertion,
        check=check,
        control=control,
        address=f"{res_type}.x",
        file_path=Path("/tmp/test.tf"),
        block_attributes=block_attrs or {},
        res_type=res_type,
    )
    if isinstance(result, Patch):
        result.check_id = check.id
        result.control_id = control.id
    return result if isinstance(result, Patch) else None


def test_derive_is_true() -> None:
    patch = _derive("versioning.enabled", "is_true")
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_NESTED
    assert patch.hcl_value == "true"


def test_derive_is_false() -> None:
    patch = _derive("associate_public_ip_address", "is_false")
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_FLAT
    assert patch.hcl_value == "false"


def test_derive_equals() -> None:
    patch = _derive("bucket", "equals", expected="my-bucket")
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_FLAT
    assert patch.hcl_value == '"my-bucket"'


def test_derive_greater_than_or_equal() -> None:
    patch = _derive("memory_size", "greater_than_or_equal", expected=256)
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_FLAT
    assert patch.hcl_value == "256"


def test_derive_less_than_or_equal() -> None:
    patch = _derive("timeout", "less_than_or_equal", expected=10)
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_FLAT
    assert patch.hcl_value == "10"


def test_derive_in() -> None:
    patch = _derive("region", "in", expected=["us-east-1", "eu-central-1"])
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_FLAT
    assert patch.hcl_value == '"us-east-1"'


def test_derive_key_exists() -> None:
    patch = _derive("tags", "key_exists", key="owner")
    assert patch is not None
    assert patch.patch_kind == PatchKind.ADD_TAG_KEY
    assert patch.tag_key == "owner"
    assert patch.hcl_value == '"TODO-fill-in"'


def test_derive_tags_scalar_as_tag_key() -> None:
    """A scalar assertion on tags.<key> must be treated as a map-key insertion."""
    patch = _derive("tags.capacity-commitment", "equals", expected="reserved")
    assert patch is not None
    assert patch.patch_kind == PatchKind.ADD_TAG_KEY
    assert patch.tag_key == "capacity-commitment"
    assert patch.hcl_value == '"reserved"'


def test_derive_attribute_exists_with_template() -> None:
    patch = _derive("point_in_time_recovery", "attribute_exists", res_type="aws_dynamodb_table")
    assert patch is not None
    assert patch.patch_kind == PatchKind.ADD_BLOCK
    assert patch.block_defaults == {"enabled": True}


def test_derive_attribute_exists_no_template() -> None:
    patch = _derive("unknown_block", "attribute_exists")
    assert patch is None


def test_derive_not_empty_with_nested_default() -> None:
    patch = _derive(
        "environment.variables.AWS_XRAY_TRACING_NAME",
        "not_empty",
        res_type="aws_lambda_function",
    )
    assert patch is not None
    assert patch.patch_kind == PatchKind.SET_NESTED_MAP_KEY
    assert patch.map_name == "variables"
    assert patch.map_key == "AWS_XRAY_TRACING_NAME"
    assert patch.hcl_value == '"TODO-fill-in"'


def test_derive_not_empty_skips_empty_default() -> None:
    from wafpass.fixer import SkippedFix

    assertion = _make_assertion("guardrail_configuration.guardrail_arn", "not_empty")
    check = _make_check(assertion)
    check.scope = Scope(block_type="resource", resource_types=["aws_bedrockagent"])
    control = Control(
        id="WAF-TEST-001",
        title="Test",
        pillar="agentic",
        severity="high",
        category="test",
        description="d",
        checks=[check],
    )
    result = _derive_patch_for_assertion(
        assertion=assertion,
        check=check,
        control=control,
        address="aws_bedrockagent.support",
        file_path=Path("/tmp/test.tf"),
        block_attributes={},
        res_type="aws_bedrockagent",
    )
    assert isinstance(result, SkippedFix)


def test_derive_already_passing_returns_none() -> None:
    patch = _derive("versioning.enabled", "is_true", block_attrs={"versioning": {"enabled": True}})
    assert patch is None


def test_derive_unfixable_operator() -> None:
    from wafpass.fixer import SkippedFix

    assertion = _make_assertion("policy", "not_contains_pattern", pattern="Action")
    check = _make_check(assertion)
    check.scope = Scope(block_type="resource", resource_types=["aws_iam_role_policy"])
    control = Control(
        id="WAF-TEST-001",
        title="Test",
        pillar="security",
        severity="high",
        category="test",
        description="d",
        checks=[check],
    )
    result = _derive_patch_for_assertion(
        assertion=assertion,
        check=check,
        control=control,
        address="aws_iam_role_policy.x",
        file_path=Path("/tmp/test.tf"),
        block_attributes={},
        res_type="aws_iam_role_policy",
    )
    assert isinstance(result, SkippedFix)


# ── TextPatcher scalar patches ────────────────────────────────────────────────


def _make_patch(
    kind: PatchKind,
    attribute_path: str,
    hcl_value: str,
    tag_key: str | None = None,
    block_defaults: dict | None = None,
    map_name: str | None = None,
    map_key: str | None = None,
) -> Patch:
    return Patch(
        file_path=Path("/tmp/test.tf"),
        address="aws_s3_bucket.data",
        attribute_path=attribute_path,
        patch_kind=kind,
        hcl_value=hcl_value,
        tag_key=tag_key,
        check_id="chk-1",
        control_id="WAF-TEST-001",
        description="test patch",
        block_defaults=block_defaults,
        map_name=map_name,
        map_key=map_key,
    )


def _apply_to_resource(content: str, patches: list[Patch]) -> str:
    import re

    m = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', content)
    assert m, "test helper requires a resource block as the first construct"
    res_type, res_name = m.group(1), m.group(2)
    locator = ResourceLocator([])
    loc = ResourceLocation(
        file_path=Path("/tmp/test.tf"),
        address=f"{res_type}.{res_name}",
        block_type="resource",
        res_type=res_type,
        res_name=res_name,
        start_line=0,
        end_line=len(content.splitlines()) - 1,
        content=content,
    )
    patcher = TextPatcher(content)
    return patcher.apply(patches, loc)


def test_set_flat_replace() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = "old"\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_FLAT, "bucket", '"new"')])
    assert 'bucket = "new"' in patched


def test_set_flat_insert() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = "my-bucket"\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_FLAT, "acl", '"private"')])
    assert 'acl = "private"' in patched


def test_set_flat_leaves_expression() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = var.name\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_FLAT, "bucket", '"new"')])
    assert "bucket = var.name" in patched


def test_set_nested_replace() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  versioning {\n    enabled = false\n  }\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_NESTED, "versioning.enabled", "true")])
    assert "enabled = true" in patched


def test_set_nested_insert_block() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = "my-bucket"\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_NESTED, "versioning.enabled", "true")])
    assert "versioning {" in patched
    assert "enabled = true" in patched


def test_set_nested_leaves_expression() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  versioning {\n    enabled = var.flag\n  }\n}\n'
    patched = _apply_to_resource(content, [_make_patch(PatchKind.SET_NESTED, "versioning.enabled", "true")])
    assert "enabled = var.flag" in patched


# ── TextPatcher tag patches ───────────────────────────────────────────────────


def test_apply_tag_patches_creates_block() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = "my-bucket"\n}\n'
    patched = _apply_to_resource(
        content,
        [
            _make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="owner"),
            _make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="cost-center"),
        ],
    )
    assert "tags = {" in patched
    assert '"owner" = "TODO-fill-in"' in patched
    assert '"cost-center" = "TODO-fill-in"' in patched


def test_apply_tag_patches_expands_single_line() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  tags = { owner = "x" }\n}\n'
    patched = _apply_to_resource(
        content,
        [_make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="cost-center")],
    )
    assert 'owner = "x"' in patched
    assert '"cost-center" = "TODO-fill-in"' in patched


def test_apply_tag_patches_preserves_existing_key() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  tags = {\n    "owner" = "x"\n  }\n}\n'
    patched = _apply_to_resource(
        content,
        [
            _make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="owner"),
            _make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="cost-center"),
        ],
    )
    # Duplicate insertion is allowed at the patcher level; dedup happens in build_fix_plan.
    assert patched.count('"owner"') == 2


def test_apply_tag_patches_leaves_dynamic_expression() -> None:
    content = 'resource "aws_s3_bucket" "data" {\n  tags = merge(local.common, { owner = "x" })\n}\n'
    patched = _apply_to_resource(
        content,
        [_make_patch(PatchKind.ADD_TAG_KEY, "tags", '"TODO-fill-in"', tag_key="cost-center")],
    )
    assert "tags = merge" in patched


def test_apply_tag_patches_scalar_value() -> None:
    """tags.<key> scalar assertions carry the exact HCL value."""
    content = 'resource "aws_s3_bucket" "data" {\n  bucket = "my-bucket"\n}\n'
    patched = _apply_to_resource(
        content,
        [_make_patch(PatchKind.ADD_TAG_KEY, "tags.capacity-commitment", '"reserved"', tag_key="capacity-commitment")],
    )
    assert '"capacity-commitment" = "reserved"' in patched


# ── TextPatcher block patches ─────────────────────────────────────────────────


def test_add_block() -> None:
    content = 'resource "aws_dynamodb_table" "agent_memory" {\n  name = "agent-memory"\n}\n'
    patched = _apply_to_resource(
        content,
        [_make_patch(PatchKind.ADD_BLOCK, "point_in_time_recovery", "", block_defaults={"enabled": True})],
    )
    assert "point_in_time_recovery {" in patched
    assert "enabled = true" in patched


def test_add_block_already_exists() -> None:
    content = 'resource "aws_dynamodb_table" "agent_memory" {\n  point_in_time_recovery {\n    enabled = true\n  }\n}\n'
    patched = _apply_to_resource(
        content,
        [_make_patch(PatchKind.ADD_BLOCK, "point_in_time_recovery", "", block_defaults={"enabled": True})],
    )
    assert patched.count("point_in_time_recovery {") == 1


def test_set_nested_map_key_creates_full_path() -> None:
    content = 'resource "aws_lambda_function" "agent_handler" {\n  function_name = "agent-handler"\n}\n'
    patched = _apply_to_resource(
        content,
        [
            _make_patch(
                PatchKind.SET_NESTED_MAP_KEY,
                "environment.variables.AWS_XRAY_TRACING_NAME",
                '"TODO-fill-in"',
                map_name="variables",
                map_key="AWS_XRAY_TRACING_NAME",
            ),
        ],
    )
    assert "environment {" in patched
    assert "variables = {" in patched
    assert "AWS_XRAY_TRACING_NAME = \"TODO-fill-in\"" in patched


def test_set_nested_map_key_updates_existing_map() -> None:
    content = 'resource "aws_lambda_function" "agent_handler" {\n  environment {\n    variables = {\n      FOO = "bar"\n    }\n  }\n}\n'
    patched = _apply_to_resource(
        content,
        [
            _make_patch(
                PatchKind.SET_NESTED_MAP_KEY,
                "environment.variables.AWS_XRAY_TRACING_NAME",
                '"TODO-fill-in"',
                map_name="variables",
                map_key="AWS_XRAY_TRACING_NAME",
            ),
        ],
    )
    assert "AWS_XRAY_TRACING_NAME = \"TODO-fill-in\"" in patched
    assert "FOO = \"bar\"" in patched


def test_set_nested_map_key_expands_single_line_map() -> None:
    content = 'resource "aws_lambda_function" "agent_handler" {\n  environment {\n    variables = { FOO = "bar" }\n  }\n}\n'
    patched = _apply_to_resource(
        content,
        [
            _make_patch(
                PatchKind.SET_NESTED_MAP_KEY,
                "environment.variables.AWS_XRAY_TRACING_NAME",
                '"TODO-fill-in"',
                map_name="variables",
                map_key="AWS_XRAY_TRACING_NAME",
            ),
        ],
    )
    assert "FOO = \"bar\"" in patched
    assert "AWS_XRAY_TRACING_NAME = \"TODO-fill-in\"" in patched


# ── ResourceLocator ───────────────────────────────────────────────────────────


def test_scan_file_clean_handles_nested_blocks() -> None:
    content = '''resource "aws_instance" "web" {
  ami = "ami-12345678"
  root_block_device {
    delete_on_termination = true
  }
}
'''
    locs = ResourceLocator._scan_file_clean(Path("/tmp/test.tf"), content, content.splitlines(keepends=True))
    assert len(locs) == 1
    loc = locs[0]
    assert loc.address == "aws_instance.web"
    assert loc.start_line == 0
    assert loc.end_line == 5


def test_scan_file_clean_skips_heredoc_braces() -> None:
    content = '''resource "aws_instance" "web" {
  user_data = <<EOF
{
  "key": "value"
}
EOF
}
'''
    locs = ResourceLocator._scan_file_clean(Path("/tmp/test.tf"), content, content.splitlines(keepends=True))
    assert len(locs) == 1
    loc = locs[0]
    assert loc.end_line == 6


def test_count_braces_respects_strings() -> None:
    assert _count_braces('name = "foo{bar}"', "{") == 0
    assert _count_braces('a = "x}"', "}") == 0
    assert _count_braces('a = "x" {', "{") == 1


def test_unquoted_hash() -> None:
    assert _unquoted_hash('a = "b" # comment') == 8
    assert _unquoted_hash('a = "#not-a-comment"') == -1


# ── Fix-plan builder ──────────────────────────────────────────────────────────


def test_build_fix_plan_deduplicates_tag_keys() -> None:
    path = NON_COMPLIANT_FIXTURE
    results, state, controls = _run_pipeline(path)
    locator = ResourceLocator([path]).build()
    plan = build_fix_plan(results, state, controls, locator)

    tags_for_instance = [
        p for p in plan.patches
        if p.address == "aws_instance.web" and p.patch_kind == PatchKind.ADD_TAG_KEY and p.tag_key == "capacity-commitment"
    ]
    # key_exists and equals both target the same tag key; only one patch should be active.
    active = [p for p in tags_for_instance if not p.already_applied]
    assert len(active) == 1


def test_build_fix_plan_suppresses_add_block_when_nested_patch_exists() -> None:
    """If a SET_NESTED patch creates the parent block, a separate ADD_BLOCK is redundant."""
    path = NON_COMPLIANT_FIXTURE
    results, state, controls = _run_pipeline(path)
    locator = ResourceLocator([path]).build()
    plan = build_fix_plan(results, state, controls, locator)

    # DynamoDB has both a SET_NESTED point_in_time_recovery.enabled patch and no ADD_BLOCK
    # because the SET_NESTED already creates the parent block.
    pitr_patches = [p for p in plan.patches if p.address == "aws_dynamodb_table.agent_memory" and "point_in_time_recovery" in p.attribute_path]
    kinds = {p.patch_kind for p in pitr_patches if not p.already_applied}
    assert PatchKind.ADD_BLOCK not in kinds


# ── End-to-end fixture test ───────────────────────────────────────────────────


def _terraform_fmt(path: Path) -> bool:
    binary = shutil.which("terraform") or shutil.which("tofu")
    if not binary:
        pytest.skip("terraform/tofu not available")
    proc = subprocess.run([binary, "fmt", "-check", str(path)], capture_output=True, text=True)
    return proc.returncode == 0


def test_fixer_end_to_end_on_fixture(tmp_path: Path) -> None:
    """Apply the fix plan to the non-compliant fixture and assert the result."""
    if not _terraform_fmt(NON_COMPLIANT_FIXTURE):
        pytest.skip("fixture is not pre-formatted (terraform fmt would change it)")

    copy_path = tmp_path / "main.tf"
    shutil.copy(NON_COMPLIANT_FIXTURE, copy_path)

    results, state, controls = _run_pipeline(copy_path)
    locator = ResourceLocator([copy_path]).build()
    plan = build_fix_plan(results, state, controls, locator)

    assert plan.active_patches, "expected at least one patch"

    apply_result = apply_fix_plan(plan, locator, dry_run=False, backup=False)
    assert isinstance(apply_result, FixApplyResult)
    assert not apply_result.warnings or all(
        "terraform/tofu not found" not in w for w in apply_result.warnings
    )

    # The patched file must be valid HCL.
    assert _terraform_fmt(copy_path), "patched file is not valid Terraform"

    # Re-run controls and verify the score improved.
    new_results, _, _ = _run_pipeline(copy_path)
    orig_fail = sum(1 for cr in results for r in cr.results if r.status == "FAIL")
    new_fail = sum(1 for cr in new_results for r in cr.results if r.status == "FAIL")
    assert new_fail < orig_fail, f"score did not improve ({orig_fail} -> {new_fail})"

    # Compare with the expected fixture (both should be fmt-clean).
    expected = EXPECTED_FIXTURE.read_text()
    actual = copy_path.read_text()
    assert actual == expected


# ── Rollback ──────────────────────────────────────────────────────────────────


def test_restore_backup(tmp_path: Path) -> None:
    original = "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"orig\"\n}\n"
    file = tmp_path / "main.tf"
    file.write_text(original)

    apply_result = _write_atomic(file, "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"changed\"\n}\n")
    assert not apply_result
    assert file.read_text() != original

    assert restore_backup(file)
    assert file.read_text() == original
    assert not (file.with_suffix(file.suffix + ".bak")).exists()


def test_restore_backup_missing(tmp_path: Path) -> None:
    file = tmp_path / "main.tf"
    file.write_text("x")
    assert not restore_backup(file)


# ── Diff / delta helpers ───────────────────────────────────────────────────────


def test_compute_fix_delta() -> None:
    from wafpass.models import CheckResult, ControlResult

    control = Control(
        id="WAF-TEST-001",
        title="t",
        pillar="security",
        severity="medium",
        category="test",
        description="d",
        checks=[],
    )

    def _result(check_id: str, resource: str, status: str):
        return ControlResult(
            control=control,
            results=[CheckResult(
                check_id=check_id,
                check_title="t",
                control_id=control.id,
                severity=control.severity,
                status=status,
                resource=resource,
                message="m",
                remediation="r",
            )],
        )

    original = [_result("c1", "r1", "FAIL"), _result("c2", "r2", "FAIL")]
    new = [_result("c1", "r1", "PASS"), _result("c2", "r2", "FAIL")]
    delta = compute_fix_delta(original, new)
    assert delta.resolved == [("c1", "r1")]
    assert delta.still_failing == [("c2", "r2")]
    assert delta.regressions == []


def test_render_diff() -> None:
    diff = render_diff("a\nb\n", "a\nc\n", Path("/tmp/main.tf"))
    assert any("--- a/main.tf" in line for line in diff)
    assert any("+++ b/main.tf" in line for line in diff)
    assert any(line.startswith("-b") for line in diff)
    assert any(line.startswith("+c") for line in diff)
