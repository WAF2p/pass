"""Pulumi IaC plugin for WAF++ PASS.

Parses Pulumi Python programs (``*.py``) using the standard ``ast`` module and
maps AWS resource declarations onto :class:`~wafpass.iac.base.IaCState` so that
WAF++ controls with ``engine: pulumi`` can be evaluated.

Supported resource constructors
-------------------------------
* ``aws.s3.BucketV2`` / ``aws.s3.Bucket`` → ``aws_s3_bucket.<name>``
* ``aws.dynamodb.Table`` → ``aws_dynamodb_table.<name>``
* ``aws.lambda_.Function`` → ``aws_lambda_function.<name>``
* ``aws.bedrock.Agent`` → ``aws_bedrockagent.<name>``
* ``aws.sqs.Queue`` → ``aws_sqs_queue.<name>``

Attribute normalisation
-----------------------
Constructor keyword arguments are normalised to Terraform-style snake_case
attribute paths:

* ``versioning={"enabled": True}`` → ``versioning.enabled = True``
* ``point_in_time_recovery={"enabled": True}`` → ``point_in_time_recovery.enabled = True``
* ``environment={"variables": {"X": ...}}`` → ``environment.variables.X = ...``
* ``tracing_config={"mode": "Active"}`` → ``tracing_config.mode = "Active"``

Region extraction
-----------------
The plugin scans string attribute values for AWS region names and optionally
reads ``Pulumi.<stack>.yaml`` for the ``aws:region`` config value.

The plugin self-registers with the global registry when this module is imported.
"""

from __future__ import annotations

import ast
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


# ── Construct type mapping ───────────────────────────────────────────────────

_PULUMI_CLASS_TYPES: dict[str, str] = {
    "BucketV2": "aws_s3_bucket",
    "Bucket": "aws_s3_bucket",
    "Table": "aws_dynamodb_table",
    "Function": "aws_lambda_function",
    "Agent": "aws_bedrockagent",
    "Queue": "aws_sqs_queue",
}

# kwarg → normalised attribute path (or passthrough dict)
_PULUMI_KWARG_ALIASES: dict[str, str | dict[str, Any]] = {
    "versioning": {"target": "versioning", "passthrough": True},
    "point_in_time_recovery": {"target": "point_in_time_recovery", "passthrough": True},
    "environment": {"target": "environment", "passthrough": True},
    "tracing_config": {"target": "tracing_config", "passthrough": True},
    "guardrail_configuration": {"target": "guardrail_configuration", "passthrough": True},
    "human_interaction_configuration": {"target": "human_interaction_configuration", "passthrough": True},
    "redrive_policy": {"target": "redrive_policy", "passthrough": True},
    "ttl": {"target": "ttl", "passthrough": True},
}


def _to_python_value(node: ast.AST | None) -> Any:
    """Convert a simple AST expression node to a Python value.

    Returns the sentinel ``...`` for expressions that cannot be evaluated
    statically (e.g. variable references, function calls).
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_to_python_value(elt) for elt in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_to_python_value(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        result: dict[Any, Any] = {}
        for k, v in zip(node.keys, node.values):
            key = _to_python_value(k)
            if key is ... or key is None:
                key = str(ast.unparse(k))
            result[key] = _to_python_value(v)
        return result
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _to_python_value(node.operand)
        if isinstance(inner, (int, float)):
            return -inner
    # Expression we can't statically evaluate
    return ...


def _snake_case(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _normalise_kwarg(key: str, value: Any) -> dict[str, Any]:
    """Map a single Pulumi Python kwarg to Terraform-like attributes."""
    alias = _PULUMI_KWARG_ALIASES.get(key)
    if alias is None:
        return {_snake_case(key): value}
    if isinstance(alias, str):
        return {alias: value}
    if alias.get("passthrough"):
        return {alias["target"]: value}
    return {_snake_case(key): value}


def _merge_nested(base: dict[str, Any], update: dict[str, Any]) -> None:
    for k, v in update.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge_nested(base[k], v)
        else:
            base[k] = v


def _normalise_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Convert Pulumi kwargs to Terraform-like attributes."""
    result: dict[str, Any] = {}
    for key, value in kwargs.items():
        mapped = _normalise_kwarg(key, value)
        _merge_nested(result, mapped)
    return result


def _resolve_resource_call(func: ast.expr) -> tuple[str | None, str | None]:
    """Resolve a Pulumi constructor call like ``aws.s3.BucketV2``.

    Returns ``(module_path, class_name)``.  ``module_path`` is something like
    ``aws.s3`` and ``class_name`` is ``BucketV2``.
    """
    parts: list[str] = []
    node: ast.AST = func
    class_name: str | None = None
    while isinstance(node, ast.Attribute):
        if class_name is None:
            class_name = node.attr
        else:
            parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return None, None
    parts.reverse()
    return ".".join(parts[:-1]) if len(parts) > 1 else parts[0], class_name


def _is_aws_resource_call(func: ast.expr) -> tuple[str | None, str]:
    """Return ``(resource_type, class_name)`` if *func* is an AWS resource constructor."""
    module_path, class_name = _resolve_resource_call(func)
    if module_path is None or class_name is None:
        return None, ""
    if not module_path.startswith("aws"):
        return None, ""
    res_type = _PULUMI_CLASS_TYPES.get(class_name)
    if res_type is None:
        return None, ""
    return res_type, class_name


def _extract_name(node: ast.expr | None) -> str:
    """Extract the first positional string argument as the logical name."""
    if node is None:
        return "unknown"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    return "unknown"


def _extract_kwargs(call: ast.Call) -> dict[str, Any]:
    """Extract keyword arguments from a Pulumi resource call."""
    kwargs: dict[str, Any] = {}
    for kw in call.keywords:
        if kw.arg is None:
            continue
        kwargs[kw.arg] = _to_python_value(kw.value)
    return kwargs


def _parse_py_source(path: Path, state: IaCState) -> None:
    """Parse a single ``*.py`` Pulumi source file and append blocks to *state*."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Pulumi plugin: could not read %s: %s", path, exc)
        return

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        logger.warning("Pulumi plugin: could not parse %s: %s", path, exc)
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        res_type, class_name = _is_aws_resource_call(node.func)
        if res_type is None:
            continue

        logical_id = _extract_name(node.args[0] if node.args else None)
        kwargs = _extract_kwargs(node)
        attrs = _normalise_kwargs(kwargs)
        attrs["_pulumi_class"] = class_name
        attrs["_source_path"] = str(path)

        state.resources.append(IaCBlock(
            block_type="resource",
            type=res_type,
            name=logical_id,
            address=f"{res_type}.{logical_id}",
            attributes=attrs,
            raw={
                "class": class_name,
                "kwargs": kwargs,
                "source_path": str(path),
            },
        ))


def _read_yaml_stack_config(path: Path) -> dict[str, Any]:
    """Read a Pulumi stack config YAML file if available."""
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _scan_attrs_for_region(attrs: dict, add_fn: Any) -> None:
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


class PulumiPlugin:
    """IaC plugin for Pulumi Python programs."""

    name: str = "pulumi"
    file_extensions: list[str] = [".py"]

    def can_parse(self, path: Path) -> bool:
        """Return True if *path* is a Pulumi Python file or a directory containing one."""
        if path.is_file():
            return path.suffix == ".py"
        if path.is_dir():
            return any(path.rglob("*.py")) or (path / "Pulumi.yaml").exists()
        return False

    def parse(self, path: Path) -> IaCState:
        """Parse Pulumi Python source files under *path*."""
        state = IaCState()

        if not path.exists():
            logger.error("Pulumi plugin: path does not exist: %s", path)
            return state

        if path.is_file() and path.suffix == ".py":
            _parse_py_source(path, state)
            return state

        if path.is_dir():
            for py_path in sorted(path.rglob("*.py")):
                # Skip virtualenvs / __pycache__
                if "__pycache__" in py_path.parts or ".venv" in py_path.parts:
                    continue
                _parse_py_source(py_path, state)

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

        for blk in state.resources:
            _scan_attrs_for_region(blk.attributes, lambda r, p="aws": add(r, p))

        return result


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(PulumiPlugin())
