"""AWS CDK IaC plugin for WAF++ PASS.

Parses both synthesised CloudFormation JSON templates (``cdk.out/*.template.json``)
and AWS CDK TypeScript source files (``*.ts``).  The source-level parser is the
preferred path when TypeScript construct files are available; it produces
Terraform-like resource addresses and attributes so the same controls and
auto-fix providers can be reused across IaC frameworks.

Source-level parsing
--------------------
Detects common AWS construct instantiations:

* ``new aws_s3.Bucket(scope, id, props)`` → ``aws_s3_bucket.<id>``
* ``new aws_dynamodb.Table(scope, id, props)`` → ``aws_dynamodb_table.<id>``
* ``new aws_lambda.Function(scope, id, props)`` → ``aws_lambda_function.<id>``
* ``new aws_bedrock.Agent(scope, id, props)`` → ``aws_bedrockagent.<id>``
* ``new aws_sqs.Queue(scope, id, props)`` → ``aws_sqs_queue.<id>``

CDK camelCase props are normalised to snake_case and, where needed, to the same
nested shape Terraform uses (e.g. ``versioned`` → ``versioning.enabled``,
``pointInTimeRecovery`` → ``point_in_time_recovery.enabled``,
``environment`` → ``environment.variables``).

Synthesised-template parsing
----------------------------
When only ``cdk.out/*.template.json`` is available, the plugin falls back to the
original CloudFormation-based parser.  This preserves compatibility with existing
``engine: cdk`` controls that reference CloudFormation resource types.

Region extraction
-----------------
Reads ``aws://ACCOUNT/REGION`` environment strings from ``manifest.json`` when
available, otherwise scans string attributes for AWS region names.

The plugin self-registers with the global registry when this module is imported.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
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


# ── Construct type mapping ───────────────────────────────────────────────────

# CDK class name → canonical Terraform-like resource type used by WAF++ controls.
_CDK_CONSTRUCT_TYPES: dict[str, str] = {
    "Bucket": "aws_s3_bucket",
    "Table": "aws_dynamodb_table",
    "Function": "aws_lambda_function",
    "Agent": "aws_bedrockagent",
    "Queue": "aws_sqs_queue",
}

# CDK camelCase property → normalised snake_case attribute path.
_CDK_PROP_ALIASES: dict[str, str | dict[str, Any]] = {
    # S3
    "versioned": {"target": "versioning.enabled", "when_true": True},
    "versioning": {"target": "versioning", "passthrough": True},
    # DynamoDB
    "pointInTimeRecovery": {"target": "point_in_time_recovery.enabled", "when_true": True},
    "pointInTimeRecoverySpecification": {"target": "point_in_time_recovery", "passthrough": True},
    # Lambda
    "environment": {"target": "environment.variables", "passthrough": True},
    "tracing": {"target": "tracing_config.mode", "value_map": {"Active": "Active", "PassThrough": "PassThrough"}},
    "tracingConfig": {"target": "tracing_config", "passthrough": True},
    # Bedrock
    "guardrailConfiguration": {"target": "guardrail_configuration", "passthrough": True},
    "humanInteractionConfiguration": {"target": "human_interaction_configuration", "passthrough": True},
    # SQS
    "redrivePolicy": {"target": "redrive_policy", "passthrough": True},
    "deadLetterQueue": {"target": "redrive_policy", "when_set": True},
    # DynamoDB TTL
    "timeToLiveAttribute": {"target": "ttl.attribute_name", "when_set": True},
    "ttl": {"target": "ttl", "passthrough": True},
}


def _snake_case(name: str) -> str:
    """Convert a camelCase/PascalCase identifier to snake_case."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _extract_string_literal(text: str, pos: int) -> tuple[str | None, int]:
    """Extract a single- or double-quoted string literal starting at *pos*.

    Returns the unescaped string and the index of the closing quote, or
    ``(None, -1)`` if the text at *pos* is not a valid string literal.
    """
    if pos >= len(text) or text[pos] not in ('"', "'"):
        return None, -1
    quote = text[pos]
    i = pos + 1
    out: list[str] = []
    while i < len(text):
        ch = text[i]
        if ch == quote and text[i - 1] != '\\':
            return "".join(out), i
        if ch == '\\' and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return None, -1


def _parse_object_literal(text: str, start: int) -> tuple[dict[str, Any], int] | None:
    """Parse a simple JS/TS object literal ``{ key: value, ... }``.

    This is a lightweight brace-balanced parser that handles string literals,
    numbers, booleans, null, nested object literals, and array literals.  It
    deliberately does **not** support arbitrary expressions on the right-hand
    side — those are stored as raw strings.

    Returns ``(dict, end_index)`` where *end_index* is the position of the
    matching closing brace, or ``None`` if parsing fails.
    """
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text) or text[i] != '{':
        return None
    i += 1
    result: dict[str, Any] = {}

    while i < len(text):
        # Skip whitespace and commas
        while i < len(text) and (text[i].isspace() or text[i] == ','):
            i += 1
        if i >= len(text):
            return None
        if text[i] == '}':
            return result, i

        # Key: identifier or string literal
        if text[i] == '"':
            key, end = _extract_string_literal(text, i)
            if key is None:
                return None
            i = end + 1
        elif text[i].isidentifier() or text[i] == '$':
            key_start = i
            while i < len(text) and (text[i].isalnum() or text[i] == '_' or text[i] == '$'):
                i += 1
            key = text[key_start:i]
        else:
            return None

        # Colon
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != ':':
            return None
        i += 1

        # Value
        value, i = _parse_value(text, i)
        if value is ...:
            return None
        result[key] = value

        # Optional comma / closing brace
        while i < len(text) and text[i].isspace():
            i += 1
        if i < len(text) and text[i] == ',':
            i += 1

    return None


def _parse_array_literal(text: str, start: int) -> tuple[list[Any], int] | None:
    """Parse a simple JS/TS array literal ``[ value, ... ]``."""
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text) or text[i] != '[':
        return None
    i += 1
    result: list[Any] = []
    while i < len(text):
        while i < len(text) and (text[i].isspace() or text[i] == ','):
            i += 1
        if i >= len(text):
            return None
        if text[i] == ']':
            return result, i
        value, i = _parse_value(text, i)
        if value is ...:
            return None
        result.append(value)
        while i < len(text) and text[i].isspace():
            i += 1
        if i < len(text) and text[i] == ',':
            i += 1
    return None


def _parse_value(text: str, start: int) -> tuple[Any, int]:
    """Parse a single JS/TS literal value starting at *start*.

    Returns ``(value, next_index)``.  The sentinel ``...`` means "could not
    parse".
    """
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        return ..., i

    ch = text[i]

    if ch in ('"', "'"):
        s, end = _extract_string_literal(text, i)
        if s is None:
            return ..., i
        return s, end + 1

    if ch == '{':
        parsed = _parse_object_literal(text, i)
        if parsed is None:
            return ..., i
        return parsed[0], parsed[1] + 1

    if ch == '[':
        parsed = _parse_array_literal(text, i)
        if parsed is None:
            return ..., i
        return parsed[0], parsed[1] + 1

    # Boolean / null / number
    if text.startswith("true", i):
        return True, i + 4
    if text.startswith("false", i):
        return False, i + 5
    if text.startswith("null", i):
        return None, i + 4
    if ch == '-' or ch.isdigit():
        num_start = i
        if ch == '-':
            i += 1
        while i < len(text) and (text[i].isdigit() or text[i] == '.'):
            i += 1
        num_str = text[num_start:i]
        try:
            if '.' in num_str:
                return float(num_str), i
            return int(num_str), i
        except ValueError:
            return ..., i

    # Identifier or call expression (e.g. aws_lambda.Code.fromAsset('lambda'))
    # Keep as a raw string; consume any balanced parentheses/brackets that follow.
    if ch.isalpha() or ch == '_' or ch == '$':
        expr_start = i
        while i < len(text) and (text[i].isalnum() or text[i] in '_.$'):
            i += 1
        # Consume trailing calls / subscripts while balanced.
        while i < len(text) and text[i] in '([':
            close = ')' if text[i] == '(' else ']'
            end = _find_matching_paren(text, i, open_ch=text[i], close_ch=close)
            if end == -1:
                break
            i = end + 1
            while i < len(text) and (text[i].isalnum() or text[i] in '_.$'):
                i += 1
        return text[expr_start:i].strip(), i

    # Unknown / expression — skip until comma or closing brace/bracket
    expr_start = i
    depth = 0
    while i < len(text):
        c = text[i]
        if c in '({[':
            depth += 1
        elif c in ')}]':
            if depth == 0:
                break
            depth -= 1
        elif c == ',' and depth == 0:
            break
        elif c in ('"', "'"):
            # skip string literal
            _, end = _extract_string_literal(text, i)
            if end == -1:
                i = len(text)
                break
            i = end + 1
            continue
        i += 1
    return text[expr_start:i].strip(), i


def _find_matching_paren(text: str, open_pos: int, open_ch: str = '(', close_ch: str = ')') -> int:
    """Return the index of the matching closing paren/brace/bracket."""
    if text[open_pos] != open_ch:
        return -1
    depth = 1
    i = open_pos + 1
    in_str: str | None = None
    escape = False
    while i < len(text):
        c = text[i]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c in ('"', "'") and in_str is None:
            in_str = c
        elif c == in_str:
            in_str = None
        elif in_str is None:
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _find_call_args(text: str, new_pos: int) -> tuple[str | None, str | None, str | None, int]:
    """Given the position of ``new`` in ``new aws_s3.Bucket(scope, id, props)``,
    extract scope, id, and props argument source strings.

    Returns ``(scope_src, id_src, props_src, close_paren_pos)``.  Any of the
    sources may be ``None`` if not present.
    """
    # Find the opening paren of the constructor call
    paren = text.find('(', new_pos)
    if paren == -1:
        return None, None, None, -1
    close = _find_matching_paren(text, paren)
    if close == -1:
        return None, None, None, -1
    args_str = text[paren + 1:close]

    # Split top-level commas
    parts: list[str] = []
    depth = 0
    in_str: str | None = None
    escape = False
    cur_start = 0
    for idx, c in enumerate(args_str):
        if escape:
            escape = False
            continue
        if c == '\\':
            escape = True
            continue
        if c in ('"', "'") and depth == 0:
            if in_str is None:
                in_str = c
            elif in_str == c:
                in_str = None
            continue
        if in_str is not None:
            continue
        if c in '({[':
            depth += 1
        elif c in ')}]':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(args_str[cur_start:idx].strip())
            cur_start = idx + 1
    parts.append(args_str[cur_start:].strip())

    scope_src = parts[0] if len(parts) > 0 else None
    id_src = parts[1] if len(parts) > 1 else None
    props_src = parts[2] if len(parts) > 2 else None
    return scope_src, id_src, props_src, close


def _normalise_cdk_prop(key: str, value: Any) -> dict[str, Any]:
    """Map a single CDK camelCase property to Terraform-like attributes."""
    alias = _CDK_PROP_ALIASES.get(key)
    if alias is None:
        # Default: snake_case the key and store the value as-is.
        return {_snake_case(key): value}

    if isinstance(alias, str):
        return {alias: value}

    target: str = alias.get("target", _snake_case(key))
    passthrough = alias.get("passthrough", False)

    def _nest(value_to_nest: Any) -> dict[str, Any]:
        parts = target.split(".")
        d: Any = value_to_nest
        for p in reversed(parts):
            d = {p: d}
        return d

    if passthrough:
        return _nest(value)

    when_true = alias.get("when_true")
    if when_true is not None and value is True:
        return _nest(when_true)

    when_set = alias.get("when_set")
    if when_set is not None and value:
        return _nest(when_set)

    value_map = alias.get("value_map")
    if value_map is not None:
        return _nest(value_map.get(value, value))

    return _nest(value)


def _merge_nested(base: dict[str, Any], update: dict[str, Any]) -> None:
    """Deep-merge *update* into *base*."""
    for k, v in update.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge_nested(base[k], v)
        else:
            base[k] = v


def _normalise_cdk_props(props: dict[str, Any]) -> dict[str, Any]:
    """Convert a CDK props dict to Terraform-like attributes."""
    result: dict[str, Any] = {}
    for key, value in props.items():
        mapped = _normalise_cdk_prop(key, value)
        _merge_nested(result, mapped)
    return result


def _extract_logical_id(id_src: str | None) -> str:
    """Best-effort extraction of a logical id from the second constructor argument."""
    if not id_src:
        return "unknown"
    id_src = id_src.strip()
    if len(id_src) > 1 and id_src[0] == id_src[-1] and id_src[0] in ('"', "'"):
        return id_src[1:-1]
    # Fallback: use the raw expression as the id (sanitised)
    return re.sub(r"[^a-zA-Z0-9_-]", "_", id_src) or "unknown"


# ── Source-level TypeScript scanner ────────────────────────────────────────────

# Pattern: new aws_s3.Bucket(scope, id, { ... })
_NEW_EXPR_RE = re.compile(
    r"\bnew\s+"
    r"(?:((?:aws(?:_[a-z0-9]+)?)\.)?"
    r"([A-Z][a-zA-Z0-9_]*))"
    r"\s*\("
)


def _parse_ts_source(path: Path, state: IaCState) -> None:
    """Parse a single ``*.ts`` CDK source file and append blocks to *state*."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("CDK plugin: could not read %s: %s", path, exc)
        return

    for match in _NEW_EXPR_RE.finditer(content):
        class_name = match.group(2)
        res_type = _CDK_CONSTRUCT_TYPES.get(class_name)
        if res_type is None:
            continue

        new_pos = match.start()
        scope_src, id_src, props_src, close = _find_call_args(content, new_pos)
        if close == -1:
            continue

        logical_id = _extract_logical_id(id_src)

        props: dict[str, Any] = {}
        if props_src:
            # Locate the props literal in the original source and parse it
            props_start = content.find(props_src, new_pos)
            if props_start != -1 and props_src.strip().startswith('{'):
                parsed = _parse_object_literal(content, props_start + props_src.index('{'))
                if parsed is not None:
                    props = parsed[0]

        attrs = _normalise_cdk_props(props)
        attrs["_cdk_class"] = class_name
        attrs["_cdk_scope"] = scope_src
        attrs["_source_path"] = str(path)

        state.resources.append(IaCBlock(
            block_type="resource",
            type=res_type,
            name=logical_id,
            address=f"{res_type}.{logical_id}",
            attributes=attrs,
            raw={
                "class": class_name,
                "scope": scope_src,
                "id": id_src,
                "props": props,
                "source_path": str(path),
            },
        ))


# ── Synthesised CloudFormation template parser (legacy) ────────────────────────


def _tags_to_dict(tags_raw: object) -> dict:
    """Convert CloudFormation Tags array to a plain ``{key: value}`` dict."""
    if isinstance(tags_raw, list):
        return {
            item["Key"]: item["Value"]
            for item in tags_raw
            if isinstance(item, dict) and "Key" in item and "Value" in item
        }
    if isinstance(tags_raw, dict):
        return tags_raw
    return {}


def _normalise_s3_bucket(props: dict) -> dict:
    """Add S3 helper attributes for CloudFormation-based parsing."""
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    sse_cfgs = (
        props.get("BucketEncryption", {})
        .get("ServerSideEncryptionConfiguration", [])
    )
    enc_algo: str | None = None
    enc_key: str | None = None
    if isinstance(sse_cfgs, list) and sse_cfgs:
        ssd = sse_cfgs[0].get("ServerSideEncryptionByDefault", {})
        enc_algo = ssd.get("SSEAlgorithm")
        enc_key = ssd.get("KMSMasterKeyID")
    result["_EncryptionAlgorithm"] = enc_algo
    result["_EncryptionKeyId"] = enc_key
    result["_VersioningStatus"] = (
        props.get("VersioningConfiguration", {}).get("Status")
    )
    rules = props.get("LifecycleConfiguration", {}).get("Rules", [])
    result["_HasLifecycleRules"] = isinstance(rules, list) and len(rules) > 0
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
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, str) and ("*" in action):
                    wildcard_actions = True
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if isinstance(resources, list):
            for resource in resources:
                if resource == "*":
                    wildcard_resources = True
    return wildcard_actions, wildcard_resources


def _normalise_iam_role(props: dict) -> dict:
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    all_statements: list[dict] = []
    for policy in props.get("Policies", []):
        if isinstance(policy, dict):
            doc = policy.get("PolicyDocument", {})
            all_statements.extend(doc.get("Statement", []))
    assume_doc = props.get("AssumeRolePolicyDocument", {})
    all_statements.extend(assume_doc.get("Statement", []))
    wild_act, wild_res = _has_wildcard_in_statements(all_statements)
    result["_HasWildcardActions"] = wild_act
    result["_HasWildcardResources"] = wild_res
    return result


def _normalise_iam_policy(props: dict) -> dict:
    result = dict(props)
    doc = props.get("PolicyDocument", {})
    statements = doc.get("Statement", [])
    wild_act, wild_res = _has_wildcard_in_statements(statements)
    result["_HasWildcardActions"] = wild_act
    result["_HasWildcardResources"] = wild_res
    return result


def _normalise_kms_key(props: dict) -> dict:
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    if "PendingWindowInDays" in props:
        result["deletion_window_in_days"] = props["PendingWindowInDays"]
    return result


def _normalise_rds(props: dict) -> dict:
    result = dict(props)
    result["Tags"] = _tags_to_dict(props.get("Tags", []))
    return result


def _normalise_generic(props: dict) -> dict:
    result = dict(props)
    if "Tags" in props:
        result["Tags"] = _tags_to_dict(props["Tags"])
    return result


_NORMALISERS: dict[str, Any] = {
    "AWS::S3::Bucket": _normalise_s3_bucket,
    "AWS::KMS::Key": _normalise_kms_key,
    "AWS::IAM::Role": _normalise_iam_role,
    "AWS::IAM::ManagedPolicy": _normalise_iam_policy,
    "AWS::IAM::Policy": _normalise_iam_policy,
    "AWS::RDS::DBInstance": _normalise_rds,
    "AWS::RDS::DBCluster": _normalise_rds,
}


def _normalise_cfn_properties(cfn_type: str, props: object) -> dict:
    """Apply the appropriate normaliser for *cfn_type* to *props*."""
    if not isinstance(props, dict):
        return {}
    normaliser = _NORMALISERS.get(cfn_type, _normalise_generic)
    return normaliser(props)


def _parse_cfn_template(data: dict, state: IaCState, template_path: Path) -> None:
    """Parse a single CloudFormation template dict and append blocks to *state*."""
    resources = data.get("Resources", {})
    if isinstance(resources, dict):
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            cfn_type = resource_def.get("Type", "")
            props = resource_def.get("Properties", {})
            attrs = _normalise_cfn_properties(cfn_type, props)
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


def _read_json(path: Path) -> dict | None:
    """Read and parse a JSON file; return None on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("CDK plugin: could not read %s: %s", path, exc)
        return None


def _region_from_env_string(env: str) -> str | None:
    """Extract region from a CDK environment string like ``aws://123456789/eu-central-1``."""
    parts = env.split("/")
    if len(parts) >= 2:
        region = parts[-1].strip()
        if region and region != "unknown-region" and re.match(r"^[a-z]{2}-", region):
            return region
    return None


def _scan_attrs_for_region(attrs: dict, add_fn: Any) -> None:
    """Recursively scan string values in *attrs* for AWS region names."""
    for val in attrs.values():
        if isinstance(val, str):
            for m in _REGION_RE.finditer(val):
                add_fn(m.group(1))
        elif isinstance(val, dict):
            _scan_attrs_for_region(val, add_fn)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _scan_attrs_for_region(item, add_fn)


# ── Plugin class ──────────────────────────────────────────────────────────────

class CdkPlugin:
    """IaC plugin for AWS CDK — parses TypeScript source and synthesised templates."""

    name: str = "cdk"
    file_extensions: list[str] = [".ts", ".json"]

    def can_parse(self, path: Path) -> bool:
        """Return True if *path* contains CDK source or synthesised output."""
        if path.is_file():
            name = path.name
            return (
                name.endswith(".ts")
                or name.endswith(".template.json")
                or name.endswith(".template.yaml")
            )
        if path.is_dir():
            if (path / "cdk.out").is_dir():
                return True
            return any(path.rglob("*.ts")) or any(path.rglob("*.template.json"))
        return False

    def parse(self, path: Path) -> IaCState:
        """Parse CDK TypeScript source and/or synthesised CloudFormation templates."""
        state = IaCState()

        if not path.exists():
            logger.error("CDK plugin: path does not exist: %s", path)
            return state

        # ── Source-level TypeScript files ─────────────────────────────────────
        if path.is_file() and path.suffix == ".ts":
            _parse_ts_source(path, state)
            return state

        if path.is_dir():
            ts_files = sorted(path.rglob("*.ts"))
            for ts_path in ts_files:
                _parse_ts_source(ts_path, state)

            # ── Synthesised templates (fallback / complementary) ─────────────
            cdk_out = path / "cdk.out" if (path / "cdk.out").is_dir() else path
            template_files = sorted(cdk_out.glob("*.template.json"))
            if not template_files:
                template_files = sorted(cdk_out.rglob("*.template.json"))
            manifest_path: Path | None = cdk_out / "manifest.json"
            if not manifest_path.exists():
                manifest_path = None

            if template_files or manifest_path:
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
                for tmpl_path in template_files:
                    data = _read_json(tmpl_path)
                    if data is not None:
                        _parse_cfn_template(data, state, tmpl_path)

        logger.debug(
            "CDK plugin: finished — %d resources, %d variables, %d config blocks",
            len(state.resources),
            len(state.variables),
            len(state.config_blocks),
        )
        return state

    def extract_regions(self, state: IaCState) -> list[tuple[str, str, str]]:
        """Extract ``(region_name, provider, availability_zone)`` tuples."""
        seen: set[str] = set()
        result: list[tuple[str, str, str]] = []

        def add(region: str, provider: str = "aws", az: str = "") -> None:
            key = f"{region}|{provider}|{az}"
            if key not in seen:
                seen.add(key)
                result.append((region, provider, az))

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

        if not result:
            for blk in state.resources:
                _scan_attrs_for_region(blk.attributes, lambda r, p="aws": add(r, p))

        return result


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(CdkPlugin())
