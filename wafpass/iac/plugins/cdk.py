"""AWS CDK IaC plugin for WAF++ PASS.

Parses synthesised CDK output — CloudFormation JSON templates inside
``cdk.out/`` — and maps them onto :class:`~wafpass.iac.base.IaCState` so
that WAF++ controls with ``engine: cdk`` can be evaluated.

Parsing strategy
----------------
1. Locate template files (``*.template.json``) in the ``cdk.out/`` directory
   produced by ``cdk synth``, or accept individual template files directly.
2. For every ``Resources`` entry in a template, create an
   :class:`~wafpass.iac.base.IaCBlock` with:

   * ``block_type = "resource"``
   * ``type`` = CloudFormation resource type (e.g. ``"AWS::S3::Bucket"``)
   * ``name`` = CloudFormation logical ID (e.g. ``"DataLakeBucket"``)
   * ``address`` = ``"<Type>.<LogicalId>"``
   * ``attributes`` = normalised ``Properties`` dict (see below)

3. ``Parameters`` → ``block_type="variable"``
4. ``manifest.json`` (written by CDK CLI next to the templates) is read for
   the deployment region and stored as a ``block_type="manifest"`` config
   block so that :meth:`extract_regions` can use it.

Attribute normalisation
-----------------------
CloudFormation uses PascalCase property names and an array-of-objects tag
format.  The following transformations are applied so that WAF++ assertions
work uniformly:

* **Tags** ``[{"Key": "k", "Value": "v"}, …]``
  → ``{"k": "v", …}`` (same format as Terraform)

* **S3 Buckets** (``AWS::S3::Bucket``) — derived helpers added at top level:

  * ``_EncryptionAlgorithm`` — ``str`` pulled from the first
    ``ServerSideEncryptionByDefault.SSEAlgorithm`` entry, or ``None``
  * ``_EncryptionKeyId`` — ``str | None`` from ``KMSMasterKeyID``
  * ``_VersioningStatus`` — ``"Enabled"`` / ``"Suspended"`` / ``None``
  * ``_HasLifecycleRules`` — ``bool``, True when ``LifecycleConfiguration.Rules``
    is non-empty

* **IAM Roles / Policies** — derived helpers:

  * ``_HasWildcardActions`` — ``bool``, True when any ``Allow`` statement
    contains ``"*"`` or ``"<service>:*"`` in its ``Action``
  * ``_HasWildcardResources`` — ``bool``, True when any ``Allow`` statement
    has ``"*"`` in its ``Resource``

All native PascalCase properties (``MultiAZ``, ``StorageEncrypted``,
``BackupRetentionPeriod``, ``EnableKeyRotation``, …) are kept as-is so
that CDK controls can reference them directly.

Region extraction
-----------------
``cdk.out/manifest.json`` contains per-stack ``environment`` strings in
``"aws://ACCOUNT/REGION"`` format.  The plugin reads these and returns
``(region, "aws")`` tuples from :meth:`extract_regions`.

The plugin self-registers with the global registry when this module is
imported.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from wafpass.iac.base import IaCBlock, IaCState
from wafpass.iac.registry import registry

logger = logging.getLogger(__name__)

_REGION_RE = re.compile(
    r"\b([a-z]{2}-(?:central|west|east|north|south|southeast|northeast|northwest|southwest|"
    r"northeast|northeast|ap-southeast|ap-northeast|ap-south|ap-east|ca-central|me-south|"
    r"af-south)-\d+|us-(?:east|west)-\d+|eu-(?:central|west|north|south)-\d+|"
    r"ap-(?:southeast|northeast|south|east|northeast)-\d+|"
    r"sa-east-\d+|ca-central-\d+|me-south-\d+|af-south-\d+)\b"
)


# ── Tag normalisation ─────────────────────────────────────────────────────────

def _tags_to_dict(tags_raw: object) -> dict:
    """Convert CloudFormation Tags array to a plain ``{key: value}`` dict.

    CloudFormation format: ``[{"Key": "cost-center", "Value": "data-platform"}, …]``
    Normalized:            ``{"cost-center": "data-platform", …}``

    Also accepts an already-normalised dict (pass-through).
    """
    if isinstance(tags_raw, list):
        return {
            item["Key"]: item["Value"]
            for item in tags_raw
            if isinstance(item, dict) and "Key" in item and "Value" in item
        }
    if isinstance(tags_raw, dict):
        return tags_raw
    return {}


# ── Per-resource-type normalisers ─────────────────────────────────────────────

def _normalise_s3_bucket(props: dict) -> dict:
    """Add ``_Encryption*``, ``_VersioningStatus``, ``_HasLifecycleRules`` helpers."""
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))

    # Encryption
    enc_algo: str | None = None
    enc_key: str | None = None
    sse_cfgs = (
        props.get("BucketEncryption", {})
        .get("ServerSideEncryptionConfiguration", [])
    )
    if isinstance(sse_cfgs, list) and sse_cfgs:
        ssd = sse_cfgs[0].get("ServerSideEncryptionByDefault", {})
        enc_algo = ssd.get("SSEAlgorithm")
        enc_key = ssd.get("KMSMasterKeyID")
    result["_EncryptionAlgorithm"] = enc_algo
    result["_EncryptionKeyId"] = enc_key

    # Versioning
    result["_VersioningStatus"] = (
        props.get("VersioningConfiguration", {}).get("Status")
    )

    # Lifecycle
    rules = props.get("LifecycleConfiguration", {}).get("Rules", [])
    result["_HasLifecycleRules"] = isinstance(rules, list) and len(rules) > 0

    return result


def _normalise_kms_key(props: dict) -> dict:
    """Normalise ``AWS::KMS::Key`` — tags + expose ``PendingWindowInDays``."""
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    # Alias for controls that use Terraform's deletion_window_in_days name
    if "PendingWindowInDays" in props:
        result["deletion_window_in_days"] = props["PendingWindowInDays"]
    return result


def _has_wildcard_in_statements(statements: list[dict]) -> tuple[bool, bool]:
    """Return (has_wildcard_actions, has_wildcard_resources) for Allow statements."""
    wildcard_actions = False
    wildcard_resources = False
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        # Actions
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, str) and ("*" in action):
                    wildcard_actions = True
        # Resources
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if isinstance(resources, list):
            for resource in resources:
                if resource == "*":
                    wildcard_resources = True
    return wildcard_actions, wildcard_resources


def _normalise_iam_role(props: dict) -> dict:
    """Normalise ``AWS::IAM::Role`` — tags + wildcard policy analysis."""
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))

    all_statements: list[dict] = []

    # Inline policies
    for policy in props.get("Policies", []):
        if isinstance(policy, dict):
            doc = policy.get("PolicyDocument", {})
            all_statements.extend(doc.get("Statement", []))

    # AssumeRolePolicyDocument (usually sts:AssumeRole — not interesting for wildcard check,
    # but included for completeness)
    assume_doc = props.get("AssumeRolePolicyDocument", {})
    all_statements.extend(assume_doc.get("Statement", []))

    wild_act, wild_res = _has_wildcard_in_statements(all_statements)
    result["_HasWildcardActions"] = wild_act
    result["_HasWildcardResources"] = wild_res
    return result


def _normalise_iam_policy(props: dict) -> dict:
    """Normalise ``AWS::IAM::ManagedPolicy`` / ``AWS::IAM::Policy``."""
    result = dict(props)
    doc = props.get("PolicyDocument", {})
    statements = doc.get("Statement", [])
    wild_act, wild_res = _has_wildcard_in_statements(statements)
    result["_HasWildcardActions"] = wild_act
    result["_HasWildcardResources"] = wild_res
    return result


def _normalise_rds(props: dict) -> dict:
    """Normalise ``AWS::RDS::DBInstance`` / ``AWS::RDS::DBCluster`` — tags only."""
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    return result


def _normalise_generic(props: dict) -> dict:
    """Default normalisation: only convert Tags."""
    result = dict(props)
    if "Tags" in props:
        result["Tags"] = _tags_to_dict(props["Tags"])
    return result


# Dispatch table: CloudFormation type prefix → normaliser function
_NORMALISERS: dict[str, Any] = {
    "AWS::S3::Bucket": _normalise_s3_bucket,
    "AWS::KMS::Key": _normalise_kms_key,
    "AWS::IAM::Role": _normalise_iam_role,
    "AWS::IAM::ManagedPolicy": _normalise_iam_policy,
    "AWS::IAM::Policy": _normalise_iam_policy,
    "AWS::RDS::DBInstance": _normalise_rds,
    "AWS::RDS::DBCluster": _normalise_rds,
}


def _normalise_properties(cfn_type: str, props: object) -> dict:
    """Apply the appropriate normaliser for *cfn_type* to *props*."""
    if not isinstance(props, dict):
        return {}
    normaliser = _NORMALISERS.get(cfn_type, _normalise_generic)
    return normaliser(props)


# ── Template parser ───────────────────────────────────────────────────────────

def _parse_template(data: dict, state: IaCState, template_path: Path) -> None:
    """Parse a single CloudFormation template dict and append blocks to *state*."""

    # ── Resources ─────────────────────────────────────────────────────────────
    resources = data.get("Resources", {})
    if isinstance(resources, dict):
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            cfn_type = resource_def.get("Type", "")
            props = resource_def.get("Properties", {})
            attrs = _normalise_properties(cfn_type, props)

            # Expose top-level resource attributes (DeletionPolicy etc.)
            for key in ("DeletionPolicy", "UpdateReplacePolicy", "DependsOn", "Condition"):
                if key in resource_def:
                    attrs[key] = resource_def[key]

            state.resources.append(IaCBlock(
                block_type="resource",
                type=cfn_type,
                name=logical_id,
                address=f"{cfn_type}.{logical_id}",
                attributes=attrs,
                raw=resource_def,
            ))

    # ── Parameters → variables ────────────────────────────────────────────────
    parameters = data.get("Parameters", {})
    if isinstance(parameters, dict):
        for param_name, param_def in parameters.items():
            if not isinstance(param_def, dict):
                continue
            state.variables.append(IaCBlock(
                block_type="variable",
                type=param_def.get("Type", "String"),
                name=param_name,
                address=f"param.{param_name}",
                attributes=param_def,
                raw=param_def,
            ))

    # ── Template metadata → config_blocks ─────────────────────────────────────
    meta: dict = {}
    for key in ("Description", "Metadata", "Conditions", "Mappings", "Outputs", "Transform"):
        if key in data:
            meta[key] = data[key]
    if meta:
        state.config_blocks.append(IaCBlock(
            block_type="config",
            type="cloudformation:template",
            name=template_path.stem,
            address=f"template.{template_path.stem}",
            attributes=meta,
            raw=meta,
        ))

    logger.debug(
        "CDK plugin: parsed template %s — %d resources, %d parameters",
        template_path.name,
        len(resources) if isinstance(resources, dict) else 0,
        len(parameters) if isinstance(parameters, dict) else 0,
    )


def _read_json(path: Path) -> dict | None:
    """Read and parse a JSON file; return None on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("CDK plugin: could not read %s: %s", path, exc)
        return None


# ── Region extraction helpers ─────────────────────────────────────────────────

def _region_from_env_string(env: str) -> str | None:
    """Extract region from a CDK environment string like ``aws://123456789/eu-central-1``."""
    # Format: aws://ACCOUNT/REGION
    parts = env.split("/")
    if len(parts) >= 2:
        region = parts[-1].strip()
        if region and region != "unknown-region" and re.match(r"^[a-z]{2}-", region):
            return region
    return None


# ── Plugin class ──────────────────────────────────────────────────────────────

class CdkPlugin:
    """IaC plugin for AWS CDK synthesised CloudFormation output.

    Parses ``*.template.json`` files from a ``cdk.out/`` directory (or any
    directory / individual file you point it at) and converts them into a
    generic :class:`~wafpass.iac.base.IaCState` for assertion evaluation.
    """

    name: str = "cdk"
    file_extensions: list[str] = [".json"]

    # ── IaCPlugin interface ───────────────────────────────────────────────────

    def can_parse(self, path: Path) -> bool:
        """Return True if *path* looks like CDK output."""
        if path.is_file():
            name = path.name
            return name.endswith(".template.json") or name.endswith(".template.yaml")
        if path.is_dir():
            if (path / "cdk.out").is_dir():
                return True
            return any(path.rglob("*.template.json"))
        return False

    def parse(self, path: Path) -> IaCState:
        """Parse CDK synthesised CloudFormation templates under *path*.

        Looks for:
        1. ``<path>/cdk.out/*.template.json`` (standard ``cdk synth`` output)
        2. ``<path>/*.template.json``          (non-standard / flattened layout)
        3. ``<path>`` itself, if it is a single ``.template.json`` file

        Also reads ``manifest.json`` (if present) for deployment region info.

        Returns:
            :class:`~wafpass.iac.base.IaCState` populated with all parsed blocks.
        """
        state = IaCState()

        if not path.exists():
            logger.error("CDK plugin: path does not exist: %s", path)
            return state

        # ── Locate template files ──────────────────────────────────────────
        if path.is_file():
            template_files = [path]
            manifest_path: Path | None = None
        else:
            cdk_out = path / "cdk.out" if (path / "cdk.out").is_dir() else path
            template_files = sorted(cdk_out.glob("*.template.json"))
            if not template_files:
                template_files = sorted(cdk_out.rglob("*.template.json"))
            manifest_path = cdk_out / "manifest.json"
            if not manifest_path.exists():
                manifest_path = None

        if not template_files:
            logger.warning(
                "CDK plugin: no *.template.json files found under %s", path
            )
            return state

        # ── Parse manifest for region metadata ────────────────────────────
        if manifest_path:
            manifest_data = _read_json(manifest_path)
            if manifest_data:
                state.config_blocks.append(IaCBlock(
                    block_type="manifest",
                    type="cdk:manifest",
                    name="manifest",
                    address="cdk.manifest",
                    attributes=manifest_data,
                    raw=manifest_data,
                ))

        # ── Parse templates ────────────────────────────────────────────────
        for tmpl_path in template_files:
            data = _read_json(tmpl_path)
            if data is None:
                continue
            _parse_template(data, state, tmpl_path)

        logger.debug(
            "CDK plugin: finished — %d resources, %d variables, %d config blocks",
            len(state.resources),
            len(state.variables),
            len(state.config_blocks),
        )
        return state

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        """Extract ``(region_name, provider)`` tuples from the parsed CDK state.

        Primary source: ``manifest.json`` artifact ``environment`` strings
        (``aws://ACCOUNT/REGION``).

        Fallback: scan string attribute values in all resources for embedded
        AWS region names.
        """
        seen: set[str] = set()
        result: list[tuple[str, str]] = []

        def add(region: str, provider: str = "aws") -> None:
            key = f"{region}|{provider}"
            if key not in seen:
                seen.add(key)
                result.append((region, provider))

        # ── Primary: manifest.json ─────────────────────────────────────────
        for blk in state.config_blocks:
            if blk.type != "cdk:manifest":
                continue
            artifacts = blk.attributes.get("artifacts", {})
            if not isinstance(artifacts, dict):
                continue
            for artifact in artifacts.values():
                if not isinstance(artifact, dict):
                    continue
                if artifact.get("type") != "aws:cloudformation:stack":
                    continue
                env_str = artifact.get("environment", "")
                region = _region_from_env_string(env_str)
                if region:
                    add(region)

        # ── Fallback: scan resource string attributes ──────────────────────
        if not result:
            for blk in state.resources:
                self._scan_attrs_for_region(blk.attributes, add)

        return result

    @staticmethod
    def _scan_attrs_for_region(attrs: dict, add_fn: Any) -> None:
        """Recursively scan string values in *attrs* for AWS region names."""
        for val in attrs.values():
            if isinstance(val, str):
                for m in _REGION_RE.finditer(val):
                    add_fn(m.group(1))
            elif isinstance(val, dict):
                CdkPlugin._scan_attrs_for_region(val, add_fn)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        CdkPlugin._scan_attrs_for_region(item, add_fn)


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(CdkPlugin())
