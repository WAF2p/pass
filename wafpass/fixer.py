"""Auto-fix engine for WAF++ PASS.

Derives and applies surgical text patches to IaC source files (Terraform `.tf`,
CDK TypeScript `.ts`, Pulumi Python `.py`, etc.) based on failing WAF++ check
results.  The engine is deliberately conservative:

- It only patches assertions whose desired value can be derived unambiguously
  from the control definition (is_true → true, equals → <expected>, …).
- It guards against overwriting dynamic expressions (var., local., ${ … }).
- Dry-run is the default; ``--apply`` must be passed explicitly in the CLI.
- One patch per (file, address, attribute) — duplicates are deduplicated.
- Tags-map insertions are batched so the tags block is only rewritten once
  even when multiple tag keys are missing from the same resource.
"""

from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from wafpass.engine import SkipAssertion, evaluate_assertion
from wafpass.fix_providers import fix_provider_registry
from wafpass.iac.base import IaCBlock, IaCState
from wafpass.iac.plugins.cdk import (
    _CDK_CONSTRUCT_TYPES as _CDK_TYPES,
    _CDK_PROP_ALIASES as _CDK_PROP_ALIASES,
    _extract_logical_id as _cdk_extract_logical_id,
    _extract_string_literal as _cdk_extract_string_literal,
    _find_call_args as _cdk_find_call_args,
    _find_matching_paren as _cdk_find_matching_paren,
    _NEW_EXPR_RE as _CDK_NEW_RE,
)
from wafpass.iac.plugins.pulumi import (
    _extract_name as _pulumi_extract_name,
    _is_aws_resource_call as _pulumi_is_aws_resource_call,
)
from wafpass.models import Assertion, Check, Control, ControlResult


# ── Operator classification ────────────────────────────────────────────────────

# Operators we can map to a concrete HCL value
_FIXABLE_OPS: frozenset[str] = frozenset({
    "is_true",
    "is_false",
    "equals",
    "greater_than_or_equal",
    "less_than_or_equal",
    "in",
    "key_exists",
})

# Operators we explicitly cannot fix (with reasons)
_UNFIXABLE_REASONS: dict[str, str] = {
    "block_exists":                 "requires adding an entirely new resource block",
    "not_empty":                    "cannot auto-generate a meaningful non-empty value",
    "matches":                      "cannot auto-generate a string matching the pattern",
    "not_matches":                  "negation — cannot determine a safe replacement",
    "not_in":                       "negation — cannot determine a safe replacement",
    "not_equals":                   "negation — cannot determine a safe replacement",
    "not_contains":                 "negation — cannot determine a safe replacement",
    "has_associated_resource":      "requires creating a separate resource block",
    # skip operators are also not fixable
    "has_associated_metric_filter": "runtime-state operator — not auto-fixable",
    "references_cloudtrail_bucket": "runtime-state operator — not auto-fixable",
    "region_in_arn_matches":        "runtime-state operator — not auto-fixable",
    "in_variable":                  "runtime-state operator — not auto-fixable",
    "not_equals_with_sibling":      "runtime-state operator — not auto-fixable",
    "not_all_true_with":            "runtime-state operator — not auto-fixable",
    "attribute_exists_on_all_providers": "runtime-state operator — not auto-fixable",
    "attribute_exists_if":          "conditional operator — not auto-fixable",
    "json_not_contains_pattern":    "runtime-state operator — not auto-fixable",
}


@dataclass
class BlockTemplate:
    """Default contents and rendering mode for a missing Terraform block/attribute."""

    defaults: dict[str, Any]
    mode: str = "block"  # "block" | "jsonencode" | "map"


# Legacy in-module block defaults.  Provider/framework-specific defaults are
# now loaded from ``fix_provider_registry`` (see ``wafpass/fix_providers/``).
# This dict remains as a fallback/override hook for callers that still import
# it directly; in normal operation it is empty.
BLOCK_DEFAULTS: dict[tuple[str, str], BlockTemplate] = {}


# Expression pattern: Terraform dynamic references that we must not overwrite
_EXPR_RE = re.compile(
    r'\$\{'                     # interpolation  ${...}
    r'|\bvar\.'                 # variable ref   var.foo
    r'|\blocal\.'               # local ref      local.foo
    r'|\bdata\.'                # data ref       data.foo
    r'|\bmodule\.'              # module ref     module.foo
    r'|\beach\.'                # each ref       each.value
    r'|\bcount\.'               # count ref      count.index
    r'|\bpath\.'                # path ref       path.module
    r'|\bmerge\s*\('            # function call  merge(...)
    r'|\bconcat\s*\('           # function call  concat(...)
    r'|\btoset\s*\('            # function call  toset(...)
    r'|\btomap\s*\('            # function call  tomap(...)
    r'|\btry\s*\('              # function call  try(...)
    r'|\blookup\s*\('           # function call  lookup(...)
    r'|\bone\s*\('              # function call  one(...)
    r'|\bcoalesce\s*\('          # function call  coalesce(...)
    r'|\bjsondecode\s*\('        # function call  jsondecode(...)
    r'|\bformat\s*\('           # function call  format(...)
    r'|\btimestamp\s*\('        # function call  timestamp(...)
    r'|\blength\s*\('            # function call  length(...)
    r'|\bflatten\s*\('          # function call  flatten(...)
    r'|\bdistinct\s*\('          # function call  distinct(...)
    r'|\?'                      # ternary operator
    r'|:'                       # ternary operator
    r'|\[\*\]'                   # splat expression [*]
    r'|\bfor\b'                 # for expression
)


# ── Data structures ────────────────────────────────────────────────────────────

class PatchKind(Enum):
    SET_FLAT          = auto()   # replace / insert  attr = value  at resource scope
    SET_NESTED        = auto()   # replace / insert  outer { inner = value }
    ADD_TAG_KEY       = auto()   # add "key" = "TODO-fill-in" inside tags = { }
    ADD_BLOCK         = auto()   # insert a missing nested block from a default template
    SET_NESTED_MAP_KEY = auto()  # set outer { map_name = { map_key = value } }


@dataclass
class ResourceLocation:
    """Where a resource or provider block lives inside a .tf file."""
    file_path: Path
    address: str        # e.g. "aws_s3_bucket.my_bucket" or "provider.aws"
    block_type: str     # "resource" | "provider"
    res_type: str       # e.g. "aws_s3_bucket" or "aws"
    res_name: str       # e.g. "my_bucket" or "" for providers
    start_line: int     # 0-based, inclusive — opening `resource "..." "..." {` line
    end_line: int       # 0-based, inclusive — line with the matching closing `}`
    content: str        # full text of the file at scan time


@dataclass
class Patch:
    """A single, atomic text change to an IaC source file."""
    file_path: Path
    address: str            # resource address
    attribute_path: str     # dotted attribute path, e.g. "tags" or "versioning.enabled"
    patch_kind: PatchKind
    hcl_value: str          # rendered literal to write (target-language literal)
    tag_key: str | None     # only for ADD_TAG_KEY
    check_id: str
    control_id: str
    description: str
    framework: str = "terraform"  # target language: terraform, cdk, pulumi
    already_applied: bool = False  # True if deduplicated away
    block_defaults: dict[str, Any] | None = None  # only for ADD_BLOCK
    map_name: str | None = None   # only for SET_NESTED_MAP_KEY
    map_key: str | None = None    # only for SET_NESTED_MAP_KEY


@dataclass
class SkippedFix:
    """A failing assertion that cannot (or need not) be auto-fixed."""
    check_id: str
    control_id: str
    address: str
    attribute: str
    op: str
    reason: str


@dataclass
class FixPlan:
    """Complete plan derived from a set of failing control results."""
    patches: list[Patch] = field(default_factory=list)
    skipped: list[SkippedFix] = field(default_factory=list)

    @property
    def active_patches(self) -> list[Patch]:
        return [p for p in self.patches if not p.already_applied]

    @property
    def files_affected(self) -> list[Path]:
        seen: list[Path] = []
        for p in self.active_patches:
            if p.file_path not in seen:
                seen.append(p.file_path)
        return seen


@dataclass
class FixDelta:
    """Improvement delta after applying a fix plan."""
    resolved: list[tuple[str, str]]          # (check_id, address)  FAIL → PASS
    still_failing: list[tuple[str, str]]     # (check_id, address)  still FAIL
    regressions: list[tuple[str, str]]       # (check_id, address)  PASS → FAIL  ← should never happen


@dataclass
class FixApplyResult:
    """Result of applying (or dry-running) a fix plan."""
    diffs: dict[Path, tuple[str, str]]
    warnings: list[str]


# ── Multi-language value renderer ─────────────────────────────────────────────

def _render_hcl(value: Any) -> str:
    """Render a Python value as a Terraform HCL literal string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value == int(value) else str(value)
    if isinstance(value, str):
        # If it already looks like an HCL literal (true/false/number), keep it raw
        if value.lower() in ("true", "false"):
            return value.lower()
        try:
            float(value)
            return value
        except ValueError:
            pass
        return f'"{value}"'
    if isinstance(value, list):
        return "[" + ", ".join(_render_hcl(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_render_hcl(k)} = {_render_hcl(v)}" for k, v in value.items()) + "}"
    return f'"{value}"'


def _render_ts(value: Any) -> str:
    """Render a Python value as a TypeScript literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value == int(value) else str(value)
    if isinstance(value, str):
        if value.lower() in ("true", "false"):
            return value.lower()
        try:
            float(value)
            return value
        except ValueError:
            pass
        # Use single quotes to match common CDK style; escape single quotes in value.
        escaped = value.replace("'", "\\'")
        return f"'{escaped}'"
    if isinstance(value, list):
        return "[" + ", ".join(_render_ts(v) for v in value) + "]"
    if isinstance(value, dict):
        pairs = ", ".join(f"{_ts_prop_key(k)}: {_render_ts(v)}" for k, v in value.items())
        return "{" + pairs + "}"
    return f"'{value}'"


def _ts_prop_key(key: Any) -> str:
    """Render a TypeScript object key; quote if not a simple identifier."""
    s = str(key)
    if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", s):
        return s
    escaped = s.replace("'", "\\'")
    return f"'{escaped}'"


def _render_python(value: Any) -> str:
    """Render a Python value as a Python literal."""
    if isinstance(value, bool):
        return "True" if value else "False"
    if value is None:
        return "None"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value == int(value) else str(value)
    if isinstance(value, str):
        if value.lower() in ("true", "false"):
            return value.capitalize()
        try:
            float(value)
            return value
        except ValueError:
            pass
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list):
        return "[" + ", ".join(_render_python(v) for v in value) + "]"
    if isinstance(value, dict):
        pairs = ", ".join(f"{_render_python(k)}: {_render_python(v)}" for k, v in value.items())
        return "{" + pairs + "}"
    return f'"{value}"'


def _render_value(value: Any, framework: str = "terraform") -> str:
    """Render a Python value as a literal in the target IaC language."""
    if framework == "cdk":
        return _render_ts(value)
    if framework == "pulumi":
        return _render_python(value)
    return _render_hcl(value)


def _is_expression(text: str) -> bool:
    """Return True if text contains a Terraform dynamic reference."""
    return bool(_EXPR_RE.search(text))


def _render_hcl_pairs(defaults: dict[str, Any], indent: str) -> list[str]:
    """Render a Python dict as HCL assignment lines with the given indentation.

    Each returned line includes a trailing newline so callers can insert it
    directly into a line list.
    """
    lines: list[str] = []
    for key, value in defaults.items():
        if isinstance(value, dict):
            nested = _render_hcl_pairs(value, indent + "  ")
            if nested:
                lines.append(f"{indent}{key} = {{\n")
                lines.extend(nested)
                lines.append(f"{indent}}}\n")
            else:
                lines.append(f"{indent}{key} = {{}}\n")
        else:
            lines.append(f"{indent}{key} = {_render_hcl(value)}\n")
    return lines


def _render_flat_template(template: BlockTemplate, base_indent: str = "", framework: str = "terraform") -> str:
    """Render a BlockTemplate as the right-hand side of a flat attribute assignment."""
    if not isinstance(template.defaults, dict):
        return _render_value(template.defaults, framework)
    if framework in ("cdk", "pulumi"):
        return _render_value(template.defaults, framework)
    body_lines = _render_hcl_pairs(template.defaults, base_indent + "  ")
    if not body_lines:
        return "jsonencode({})" if template.mode == "jsonencode" else "{}"
    if template.mode == "jsonencode":
        return "jsonencode({\n" + "".join(body_lines) + f"{base_indent}}})"
    return "{\n" + "".join(body_lines) + f"{base_indent}}}"


def _lookup_block_template(
    res_type: str,
    attribute: str,
    framework: str = "terraform",
    provider_name: str | None = None,
) -> BlockTemplate | None:
    """Return a default template for a missing block/attribute, if one is known.

    Looks up provider/framework-specific defaults from ``fix_provider_registry``
    first, then falls back to the legacy ``BLOCK_DEFAULTS`` dict.

    The actual resource type (``res_type``) is preferred over the control's declared
    provider, because multi-provider controls (e.g. sovereignty checks with
    ``provider: any`` or ``provider: aws`` that target ``provider.hcloud`` blocks)
    must resolve to the provider the address belongs to.
    """
    for name in (None, provider_name):
        provider = fix_provider_registry.find_provider(framework, name, res_type)
        if provider is not None:
            defaults = provider.lookup_block_template(res_type, attribute)
            if defaults is not None:
                mode = provider.block_modes.get((res_type, attribute), "block")
                return BlockTemplate(defaults=defaults, mode=mode)
    return BLOCK_DEFAULTS.get((res_type, attribute))


def _lookup_nested_default(
    res_type: str,
    attribute_path: str,
    framework: str = "terraform",
    provider_name: str | None = None,
) -> Any | None:
    """Look up a default value for a dotted attribute path.

    Supports paths like ``guardrail_configuration.guardrail_arn`` or
    ``environment.variables.AWS_XRAY_TRACING_NAME`` by descending into
    the registered default dict/map.
    """
    parts = attribute_path.split(".")
    # First part must match a registered template for this resource type.
    template = _lookup_block_template(res_type, parts[0], framework, provider_name)
    if template is None:
        return None
    value: Any = template.defaults
    for part in parts[1:]:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


# ── ResourceLocator ────────────────────────────────────────────────────────────

# Matches the opening line of a resource or provider block
_RES_OPEN_RE  = re.compile(
    r'^\s*resource\s+"(?P<rtype>[^"]+)"\s+"(?P<rname>[^"]+)"\s*\{'
)
_PROV_OPEN_RE = re.compile(
    r'^\s*provider\s+"(?P<pname>[^"]+)"\s*\{'
)
# Heredoc start: anything that ends with << or <<-
_HEREDOC_RE   = re.compile(r'<<-?\s*(\w+)\s*$')


class ResourceLocator:
    """Scans Terraform `.tf` files to build an index of resource and provider block positions."""

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths
        self._index: dict[str, ResourceLocation] = {}

    def build(self) -> "ResourceLocator":
        tf_files: list[Path] = []
        for p in self._paths:
            if p.is_file() and p.suffix == ".tf":
                tf_files.append(p)
            elif p.is_dir():
                tf_files.extend(sorted(p.rglob("*.tf")))

        for tf_file in tf_files:
            try:
                content = tf_file.read_text(encoding="utf-8")
            except OSError:
                continue
            for loc in self._scan_file(tf_file, content):
                # First occurrence wins (Terraform would reject duplicates anyway)
                if loc.address not in self._index:
                    self._index[loc.address] = loc
        return self

    def get(self, address: str) -> ResourceLocation | None:
        return self._index.get(address)

    @property
    def all_locations(self) -> list[ResourceLocation]:
        return list(self._index.values())

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _scan_file(file_path: Path, content: str) -> list[ResourceLocation]:
        """Detect all resource/provider block positions via brace-counting."""
        locations: list[ResourceLocation] = []
        lines = content.splitlines(keepends=True)

        # Stack: each frame is (address, block_type, res_type, res_name, start_line, depth)
        stack: list[tuple[str, str, str, str, int]] = []
        in_heredoc: str | None = None  # heredoc terminator we are waiting for

        for i, raw_line in enumerate(lines):
            line = raw_line

            # ── heredoc handling ──────────────────────────────────────────────
            if in_heredoc is not None:
                if raw_line.strip() == in_heredoc:
                    in_heredoc = None
                continue

            hm = _HEREDOC_RE.search(line)
            if hm:
                in_heredoc = hm.group(1)
                # still count braces on this line before the heredoc token
                line = line[: line.index("<<")]

            # ── block open detection (only at top level, i.e. stack empty) ──
            if not stack:
                m = _RES_OPEN_RE.match(raw_line)
                if m:
                    address = f"{m.group('rtype')}.{m.group('rname')}"
                    stack.append((address, "resource", m.group("rtype"), m.group("rname"), i))
                    continue
                m2 = _PROV_OPEN_RE.match(raw_line)
                if m2:
                    address = f"provider.{m2.group('pname')}"
                    stack.append((address, "provider", m2.group("pname"), "", i))
                    continue

            # ── brace counting ────────────────────────────────────────────────
            if stack:
                open_count  = _count_braces(line, "{")
                close_count = _count_braces(line, "}")
                addr, btype, rtype, rname, start = stack[-1]

                # Update depth stored as the length of sub-frames we push:
                # We track depth via a secondary count rather than extra stack frames.
                # Use a mutable holder by rewriting the top frame.
                stack.pop()
                # Depth is tracked by re-reading from separate counter dict
                # Simpler: attach depth as a 6th element
                # Restart with depth tracking
                ...

        # ── Restart with proper depth tracking ─────────────────────────────
        # The above was a false start — implement cleanly below.
        return ResourceLocator._scan_file_clean(file_path, content, lines)

    @staticmethod
    def _scan_file_clean(
        file_path: Path, content: str, lines: list[str]
    ) -> list[ResourceLocation]:
        locations: list[ResourceLocation] = []
        # Each frame: [address, block_type, res_type, res_name, start_line, depth]
        stack: list[list] = []
        in_heredoc: str | None = None

        for i, raw_line in enumerate(lines):
            # ── heredoc ──────────────────────────────────────────────────────
            if in_heredoc is not None:
                if raw_line.strip() == in_heredoc:
                    in_heredoc = None
                continue

            stripped = raw_line.rstrip()
            hm = _HEREDOC_RE.search(stripped)
            effective_line = stripped
            if hm:
                in_heredoc = hm.group(1)
                effective_line = stripped[: stripped.index("<<")]

            open_count  = _count_braces(effective_line, "{")
            close_count = _count_braces(effective_line, "}")

            if not stack:
                # Look for a new top-level block
                m = _RES_OPEN_RE.match(raw_line)
                if m:
                    stack.append([
                        f"{m.group('rtype')}.{m.group('rname')}",
                        "resource",
                        m.group("rtype"),
                        m.group("rname"),
                        i,
                        1,  # depth starts at 1 because the opening { is on this line
                    ])
                    continue
                m2 = _PROV_OPEN_RE.match(raw_line)
                if m2:
                    stack.append([
                        f"provider.{m2.group('pname')}",
                        "provider",
                        m2.group("pname"),
                        "",
                        i,
                        1,
                    ])
                    continue
                # Not a block header we care about; brace counting still needed
                # if nested inside a block we're tracking — but stack is empty so skip
                continue

            # We are inside a tracked block
            frame = stack[-1]
            # Adjust depth: this line's open braces were already counted if it's
            # the header line (depth starts at 1). For subsequent lines, update.
            # Header line is handled above with depth=1; here we handle body lines.
            frame[5] += open_count - close_count

            if frame[5] <= 0:
                # Block closed
                stack.pop()
                addr, btype, rtype, rname, start, _ = frame
                locations.append(ResourceLocation(
                    file_path=file_path,
                    address=addr,
                    block_type=btype,
                    res_type=rtype,
                    res_name=rname,
                    start_line=start,
                    end_line=i,
                    content=content,
                ))

        return locations


def _count_braces(line: str, brace: str) -> int:
    """Count unquoted occurrences of `brace` ('{' or '}') in a line."""
    count = 0
    in_str = False
    escape = False
    for ch in line:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"' and not escape:
            in_str = not in_str
            continue
        if not in_str and ch == brace:
            count += 1
    return count


# ── Framework-specific resource locators ───────────────────────────────────────

class CdkTsResourceLocator:
    """Scans CDK/TypeScript source files for AWS construct calls."""

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths
        self._index: dict[str, ResourceLocation] = {}

    def build(self) -> "CdkTsResourceLocator":
        ts_files: list[Path] = []
        for p in self._paths:
            if p.is_file() and p.suffix == ".ts":
                ts_files.append(p)
            elif p.is_dir():
                ts_files.extend(sorted(p.rglob("*.ts")))

        for ts_file in ts_files:
            try:
                content = ts_file.read_text(encoding="utf-8")
            except OSError:
                continue
            for loc in self._scan_file(ts_file, content):
                if loc.address not in self._index:
                    self._index[loc.address] = loc
        return self

    def get(self, address: str) -> ResourceLocation | None:
        return self._index.get(address)

    @property
    def all_locations(self) -> list[ResourceLocation]:
        return list(self._index.values())

    @staticmethod
    def _scan_file(file_path: Path, content: str) -> list[ResourceLocation]:
        locations: list[ResourceLocation] = []
        for match in _CDK_NEW_RE.finditer(content):
            class_name = match.group(2)
            res_type = _CDK_TYPES.get(class_name)
            if res_type is None:
                continue
            new_pos = match.start()
            _, id_src, _, close = _cdk_find_call_args(content, new_pos)
            if close == -1:
                continue
            logical_id = _cdk_extract_logical_id(id_src)
            address = f"{res_type}.{logical_id}"
            start_line = content[:new_pos].count("\n")
            end_line = content[:close].count("\n")
            locations.append(ResourceLocation(
                file_path=file_path,
                address=address,
                block_type="resource",
                res_type=res_type,
                res_name=logical_id,
                start_line=start_line,
                end_line=end_line,
                content=content,
            ))
        return locations


class PulumiPyResourceLocator:
    """Scans Pulumi Python source files for AWS resource constructor calls."""

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths
        self._index: dict[str, ResourceLocation] = {}

    def build(self) -> "PulumiPyResourceLocator":
        py_files: list[Path] = []
        for p in self._paths:
            if p.is_file() and p.suffix == ".py":
                py_files.append(p)
            elif p.is_dir():
                py_files.extend(sorted(p.rglob("*.py")))

        for py_file in py_files:
            try:
                content = py_file.read_text(encoding="utf-8")
            except OSError:
                continue
            for loc in self._scan_file(py_file, content):
                if loc.address not in self._index:
                    self._index[loc.address] = loc
        return self

    def get(self, address: str) -> ResourceLocation | None:
        return self._index.get(address)

    @property
    def all_locations(self) -> list[ResourceLocation]:
        return list(self._index.values())

    @staticmethod
    def _scan_file(file_path: Path, content: str) -> list[ResourceLocation]:
        import ast as _ast
        locations: list[ResourceLocation] = []
        try:
            tree = _ast.parse(content)
        except SyntaxError:
            return locations

        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            res_type, _ = _pulumi_is_aws_resource_call(node.func)
            if res_type is None:
                continue
            logical_id = _pulumi_extract_name(node.args[0] if node.args else None)
            address = f"{res_type}.{logical_id}"
            start_line = (node.lineno or 1) - 1
            end_line = (node.end_lineno or node.lineno or 1) - 1
            locations.append(ResourceLocation(
                file_path=file_path,
                address=address,
                block_type="resource",
                res_type=res_type,
                res_name=logical_id,
                start_line=start_line,
                end_line=end_line,
                content=content,
            ))
        return locations


def make_locator(framework: str, paths: list[Path]) -> ResourceLocator | CdkTsResourceLocator | PulumiPyResourceLocator:
    """Return a resource locator appropriate for the requested framework."""
    if framework == "cdk":
        return CdkTsResourceLocator(paths).build()
    if framework == "pulumi":
        return PulumiPyResourceLocator(paths).build()
    return ResourceLocator(paths).build()


# ── Indent detection ──────────────────────────────────────────────────────────

def _detect_indent(lines: list[str], start: int, end: int) -> str:
    """Detect the indentation used by direct children of a block."""
    for i in range(start + 1, end):
        s = lines[i].rstrip()
        if not s or s.lstrip().startswith("#"):
            continue
        indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
        if indent:
            return indent
    return "  "


# ── Patch derivation ───────────────────────────────────────────────────────────

def _derive_patch_for_assertion(
    assertion: Assertion,
    check: Check,
    control: Control,
    address: str,
    file_path: Path,
    block_attributes: dict,
    res_type: str,
    framework: str = "terraform",
) -> Patch | SkippedFix | None:
    """Derive a Patch for one assertion, or SkippedFix if not auto-fixable.

    Returns None when the assertion is already passing (no fix needed).
    """
    op = assertion.op
    attr_parts = assertion.attribute.split(".")

    # ── Already passing? ──────────────────────────────────────────────────────
    # Re-evaluate against the live block attributes to skip unnecessary patches.
    _dummy_state = IaCState()
    _dummy_block = IaCBlock(
        block_type="resource", type="", name="", address=address,
        attributes=block_attributes, raw={},
    )
    try:
        passed, _ = evaluate_assertion(assertion, _dummy_block, _dummy_state)
        if passed:
            return None  # no fix needed
    except SkipAssertion:
        pass  # unsupported operator — still try to derive a patch below

    # ── Structural defaults (attribute_exists) ────────────────────────────────
    if op in ("attribute_exists", "attribute_exists_or_fallback"):
        template = _lookup_block_template(
            res_type, assertion.attribute, framework, check.provider
        )
        if template is None:
            # No exact template for the full dotted path; try descending into a
            # registered parent template (e.g. environment -> environment.variables.X).
            default_value = _lookup_nested_default(
                res_type, assertion.attribute, framework, check.provider
            )
            if default_value is None:
                return SkippedFix(
                    check_id=check.id, control_id=control.id, address=address,
                    attribute=assertion.attribute, op=op,
                    reason="no unambiguous default value can be derived",
                )
            if len(attr_parts) == 1:
                kind = PatchKind.SET_FLAT
            elif len(attr_parts) == 2:
                kind = PatchKind.SET_NESTED
            elif len(attr_parts) == 3:
                kind = PatchKind.SET_NESTED_MAP_KEY
            else:
                return SkippedFix(
                    check_id=check.id, control_id=control.id, address=address,
                    attribute=assertion.attribute, op=op,
                    reason="nested attribute depth > 3 is not supported by the auto-fixer",
                )
            return Patch(
                file_path=file_path,
                address=address,
                attribute_path=assertion.attribute,
                patch_kind=kind,
                hcl_value=_render_value(default_value, framework),
                tag_key=None,
                map_name=attr_parts[1] if kind == PatchKind.SET_NESTED_MAP_KEY else None,
                map_key=attr_parts[2] if kind == PatchKind.SET_NESTED_MAP_KEY else None,
                check_id=check.id,
                control_id=control.id,
                description=f"Set {address}.{assertion.attribute} from default template",
                framework=framework,
            )
        # Block templates with dict defaults render as nested blocks; scalar or
        # non-block-mode templates render as flat attribute assignments.
        if isinstance(template.defaults, dict) and template.mode == "block":
            return Patch(
                file_path=file_path,
                address=address,
                attribute_path=assertion.attribute,
                patch_kind=PatchKind.ADD_BLOCK,
                hcl_value="",
                tag_key=None,
                check_id=check.id,
                control_id=control.id,
                description=f"Add {assertion.attribute} block to {address}",
                framework=framework,
                block_defaults=template.defaults,
            )
        return Patch(
            file_path=file_path,
            address=address,
            attribute_path=assertion.attribute,
            patch_kind=PatchKind.SET_FLAT,
            hcl_value=_render_flat_template(template, framework=framework),
            tag_key=None,
            check_id=check.id,
            control_id=control.id,
            description=f"Set {address}.{assertion.attribute} from default template",
            framework=framework,
        )

    # ── not_empty on registry-known nested keys ────────────────────────────────
    if op == "not_empty":
        default_value = _lookup_nested_default(
            res_type, assertion.attribute, framework, check.provider
        )
        if default_value is None or (
            isinstance(default_value, (str, list, dict)) and len(default_value) == 0
        ):
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="cannot auto-generate a meaningful non-empty value",
            )
        hcl_value = _render_value(default_value, framework)
        if len(attr_parts) == 1:
            kind = PatchKind.SET_FLAT
        elif len(attr_parts) == 2:
            kind = PatchKind.SET_NESTED
        elif len(attr_parts) == 3:
            kind = PatchKind.SET_NESTED_MAP_KEY
        else:
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="nested attribute depth > 3 is not supported by the auto-fixer",
            )
        return Patch(
            file_path=file_path,
            address=address,
            attribute_path=assertion.attribute,
            patch_kind=kind,
            hcl_value=hcl_value,
            tag_key=None,
            map_name=attr_parts[1] if kind == PatchKind.SET_NESTED_MAP_KEY else None,
            map_key=attr_parts[2] if kind == PatchKind.SET_NESTED_MAP_KEY else None,
            check_id=check.id,
            control_id=control.id,
            description=f"Set {address}.{assertion.attribute} from default template",
            framework=framework,
        )

    # ── Unfixable operators ───────────────────────────────────────────────────
    if op in _UNFIXABLE_REASONS:
        return SkippedFix(
            check_id=check.id,
            control_id=control.id,
            address=address,
            attribute=assertion.attribute,
            op=op,
            reason=_UNFIXABLE_REASONS[op],
        )

    if op not in _FIXABLE_OPS:
        return SkippedFix(
            check_id=check.id,
            control_id=control.id,
            address=address,
            attribute=assertion.attribute,
            op=op,
            reason=f"operator '{op}' is not handled by the auto-fixer",
        )

    # ── key_exists → ADD_TAG_KEY ──────────────────────────────────────────────
    if op == "key_exists":
        tag_key = assertion.key
        if not tag_key:
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="key_exists assertion has no 'key' field",
            )
        return Patch(
            file_path=file_path,
            address=address,
            attribute_path=assertion.attribute,
            patch_kind=PatchKind.ADD_TAG_KEY,
            hcl_value='"TODO-fill-in"',
            tag_key=tag_key,
            check_id=check.id,
            control_id=control.id,
            description=f"Add tag '{tag_key}' to {address}",
            framework=framework,
        )

    # ── Derive hcl_value for scalar operators ─────────────────────────────────
    hcl_value: str | None = None

    if op == "is_true":
        hcl_value = _render_value(True, framework)
    elif op == "is_false":
        hcl_value = _render_value(False, framework)
    elif op in ("equals", "greater_than_or_equal", "less_than_or_equal"):
        if assertion.expected is None:
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="assertion has no 'expected' value defined",
            )
        hcl_value = _render_value(assertion.expected, framework)
    elif op == "in":
        expected_list = (
            assertion.expected if isinstance(assertion.expected, list)
            else ([assertion.expected] if assertion.expected is not None else [])
        )
        if not expected_list:
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="'in' operator has empty allowed-values list",
            )
        # For provider-level region/location assertions where the expected list belongs
        # to a different provider than the resource address, prefer the provider's own
        # registered default if one exists. This prevents e.g. OCI or OVH from being
        # patched with us-west-2 just because the failing check was the AWS one.
        chosen_value: Any = expected_list[0]
        if address.startswith("provider.") and assertion.attribute in ("region", "location", "zone"):
            provider_default = _lookup_block_template(
                res_type, assertion.attribute, framework, check.provider
            )
            if provider_default is not None and provider_default.defaults not in (None, ""):
                chosen_value = provider_default.defaults
        hcl_value = _render_value(chosen_value, framework)

    if hcl_value is None:
        return SkippedFix(
            check_id=check.id, control_id=control.id, address=address,
            attribute=assertion.attribute, op=op,
            reason=f"could not derive a value from the assertion for framework '{framework}'",
        )

    # ── tags.<key> scalar assertions are map-key insertions ─────────────────────
    if len(attr_parts) == 2 and attr_parts[0] == "tags":
        return Patch(
            file_path=file_path,
            address=address,
            attribute_path=assertion.attribute,
            patch_kind=PatchKind.ADD_TAG_KEY,
            hcl_value=hcl_value,
            tag_key=attr_parts[1],
            check_id=check.id,
            control_id=control.id,
            description=f"Add tag '{attr_parts[1]}' to {address}",
            framework=framework,
        )

    # ── Determine patch kind from attribute path depth ────────────────────────
    if len(attr_parts) == 1:
        kind = PatchKind.SET_FLAT
    elif len(attr_parts) == 2:
        kind = PatchKind.SET_NESTED
    else:
        return SkippedFix(
            check_id=check.id, control_id=control.id, address=address,
            attribute=assertion.attribute, op=op,
            reason="nested attribute depth > 2 is not supported by the auto-fixer",
        )

    return Patch(
        file_path=file_path,
        address=address,
        attribute_path=assertion.attribute,
        patch_kind=kind,
        hcl_value=hcl_value,
        tag_key=None,
        check_id=check.id,
        control_id=control.id,
        framework=framework,
        description=(
            f"Set {address}.{assertion.attribute} = {hcl_value}"
            f"  [{control.id}]"
        ),
    )


# ── Fix-plan builder ──────────────────────────────────────────────────────────

def build_fix_plan(
    control_results: list[ControlResult],
    merged_state: IaCState,
    controls: list[Control],
    locator: ResourceLocator,
    framework: str = "terraform",
) -> FixPlan:
    """Derive the complete set of patches needed to remediate all FAIL results.

    The plan is fully computed (including deduplication) but nothing is written
    to disk here.
    """
    plan = FixPlan()

    # Build lookup tables
    check_by_id: dict[str, Check] = {}
    control_by_check: dict[str, Control] = {}
    for ctrl in controls:
        for chk in ctrl.checks:
            check_by_id[chk.id] = chk
            control_by_check[chk.id] = ctrl

    block_by_address: dict[str, IaCBlock] = {
        b.address: b
        for b in (merged_state.resources + merged_state.providers)
    }

    # Track (file, address, attribute_path) to deduplicate patches
    seen_patch_keys: set[tuple[Path, str, str]] = set()

    for cr in control_results:
        if cr.status != "FAIL":
            continue

        for check_result in cr.results:
            if check_result.status != "FAIL":
                continue

            check = check_by_id.get(check_result.check_id)
            if check is None:
                continue

            control = control_by_check.get(check_result.check_id, cr.control)
            address = check_result.resource

            if address in ("(none)", ""):
                plan.skipped.append(SkippedFix(
                    check_id=check_result.check_id,
                    control_id=control.id,
                    address=address,
                    attribute="(all)",
                    op="(n/a)",
                    reason="no matching resource found in IaC state",
                ))
                continue

            loc = locator.get(address)
            if loc is None:
                plan.skipped.append(SkippedFix(
                    check_id=check_result.check_id,
                    control_id=control.id,
                    address=address,
                    attribute="(all)",
                    op="(n/a)",
                    reason=(
                        f"resource not found in scanned source files "
                        f"for {framework} (may be in a module or dynamically generated)"
                    ),
                ))
                continue

            block = block_by_address.get(address)
            block_attrs = block.attributes if block else {}

            for assertion in check.assertions:
                result = _derive_patch_for_assertion(
                    assertion=assertion,
                    check=check,
                    control=control,
                    address=address,
                    file_path=loc.file_path,
                    block_attributes=block_attrs,
                    res_type=loc.res_type,
                    framework=framework,
                )

                if result is None:
                    continue  # already passing

                if isinstance(result, SkippedFix):
                    plan.skipped.append(result)
                    continue

                # Deduplication key. Tag-key patches are normalized to
                # ``tags:<key>`` so a ``key_exists`` assertion and a
                # ``tags.<key> == value`` assertion do not produce duplicates.
                if result.patch_kind == PatchKind.ADD_TAG_KEY:
                    dedup_attr = f"tags:{result.tag_key}"
                else:
                    dedup_attr = result.attribute_path
                key = (result.file_path, address, dedup_attr)
                if key in seen_patch_keys:
                    result.already_applied = True
                else:
                    seen_patch_keys.add(key)

                plan.patches.append(result)

    # Suppress ADD_BLOCK patches whose parent block will already be created by a
    # deeper SET_NESTED / SET_NESTED_MAP_KEY patch.
    parent_attrs = {
        p.attribute_path.split(".")[0]
        for p in plan.patches
        if not p.already_applied and p.patch_kind in (
            PatchKind.SET_NESTED,
            PatchKind.SET_NESTED_MAP_KEY,
        )
    }
    for p in plan.patches:
        if (
            not p.already_applied
            and p.patch_kind == PatchKind.ADD_BLOCK
            and p.attribute_path in parent_attrs
        ):
            p.already_applied = True

    return plan


@dataclass
class FindingInput:
    """Minimal finding data used by :func:`classify_findings`."""

    control_id: str
    check_id: str
    resource: str | None = None
    message: str | None = None


def _address_to_res_type(address: str) -> str:
    """Infer the Terraform block type from a resource/provider address."""
    if address.startswith("provider."):
        return address.split(".", 1)[1]
    if address == "terraform":
        return "terraform"
    return address.split(".", 1)[0]


def _provider_from_address(address: str) -> str | None:
    """Return the Terraform provider name inferred from a resource/provider address."""
    if address.startswith("provider."):
        return address.split(".", 1)[1]
    if "." in address:
        res_type = address.split(".", 1)[0]
        # Resource types like aws_s3_bucket -> aws, azurerm_resource_group -> azurerm.
        # Find the registered provider whose prefix matches.
        lower_res = res_type.lower()
        for provider in fix_provider_registry.all():
            for prefix in provider.resource_type_prefixes:
                if lower_res.startswith(prefix.lower()):
                    return provider.providers[0]
            for block_type in provider.provider_block_types:
                if lower_res == block_type.lower():
                    return provider.providers[0]
        # Fallback: use the first underscore-delimited segment.
        if "_" in res_type:
            return res_type.split("_", 1)[0]
    return None


def _check_covers_provider_block(check: Check, provider_name: str) -> bool:
    """Return True if ``check`` is scoped to a provider block of the given name."""
    return check.scope.block_type == "provider" and provider_name in check.scope.resource_types


def _resolve_check_for_finding(
    finding: FindingInput,
    control: Control,
    check_by_id: dict[str, Check],
) -> Check | None:
    """Return the check that should be used to classify a finding.

    Dashboard local previews sometimes carry the wrong ``check_id`` for multi-provider
    controls (e.g. every provider block ends up with the AWS region check). When the
    finding targets a provider block whose provider does not match the check's declared
    provider, we try to find another check in the same control whose declared provider
    matches the resource provider **and** whose scope actually covers provider blocks.

    Remapping a provider-block finding to a resource-scoped check (e.g. the Azure
    ``azurerm_resource_group`` check in WAF-SUS-030) would patch the wrong attribute on
    the provider block, so we only swap to provider-scoped checks.
    """
    check = check_by_id.get(finding.check_id)
    if check is None:
        return None

    address = finding.resource or ""
    if not address.startswith("provider."):
        # Only provider blocks have this ambiguity; resource blocks already carry a
        # concrete resource type and the fixer resolves provider from that.
        return check

    res_provider = _provider_from_address(address)
    if res_provider is None:
        return check

    # If the declared check already targets this provider block, keep it.
    if (
        check.provider.lower() == res_provider.lower()
        and _check_covers_provider_block(check, res_provider)
    ):
        return check

    # If the check does not match the provider block, look for a provider-scoped check
    # that does.  We must verify the target scope; otherwise a resource-scoped check
    # (e.g. azurerm_resource_group) would be applied to the provider block.
    if not _check_covers_provider_block(check, res_provider):
        for chk in control.checks:
            if (
                chk.provider.lower() == res_provider.lower()
                and _check_covers_provider_block(chk, res_provider)
            ):
                return chk

    return check


def classify_findings(
    findings: list[FindingInput],
    controls: list[Control],
    framework: str = "terraform",
) -> FixPlan:
    """Classify stored findings as fixable or manual without filesystem access.

    This lets a dashboard local preview use the same provider registry and
    assertion logic as the real :func:`build_fix_plan` path.  Diffs are not
    produced (no source files are read), but the returned patches/skipped list
    accurately reflects what the auto-fixer would attempt.
    """
    plan = FixPlan()
    check_by_id: dict[str, Check] = {}
    control_by_check: dict[str, Control] = {}
    for ctrl in controls:
        for chk in ctrl.checks:
            check_by_id[chk.id] = chk
            control_by_check[chk.id] = ctrl

    # Deduplicate by (address, attribute_path) — not by check_id.  Multi-provider
    # controls such as WAF-AGN-040 contain several checks asserting the same nested
    # attribute; collapsing them avoids duplicate rows in the dashboard preview.
    seen: set[tuple[str, str]] = set()

    for f in findings:
        control = next((c for c in controls if c.id == f.control_id), None)
        if control is None:
            continue
        check = _resolve_check_for_finding(f, control, check_by_id)
        if check is None:
            continue

        address = f.resource or ""
        res_type = _address_to_res_type(address)

        for assertion in check.assertions:
            result = _derive_patch_for_assertion(
                assertion=assertion,
                check=check,
                control=control,
                address=address,
                file_path=Path("unknown"),
                block_attributes={},
                res_type=res_type,
                framework=framework,
            )
            if result is None:
                continue
            if isinstance(result, Patch):
                if result.patch_kind == PatchKind.ADD_TAG_KEY:
                    dedup_attr = f"tags:{result.tag_key}"
                else:
                    dedup_attr = result.attribute_path
                dedup = (address, dedup_attr)
                if dedup in seen:
                    result.already_applied = True
                else:
                    seen.add(dedup)
                plan.patches.append(result)
            else:
                plan.skipped.append(result)

    # Suppress ADD_BLOCK patches whose parent block will already be created by a
    # deeper SET_NESTED / SET_NESTED_MAP_KEY patch.
    parent_attrs = {
        p.attribute_path.split(".")[0]
        for p in plan.patches
        if not p.already_applied and p.patch_kind in (
            PatchKind.SET_NESTED,
            PatchKind.SET_NESTED_MAP_KEY,
        )
    }
    for p in plan.patches:
        if (
            not p.already_applied
            and p.patch_kind == PatchKind.ADD_BLOCK
            and p.attribute_path in parent_attrs
        ):
            p.already_applied = True

    return plan


# ── TextPatcher ────────────────────────────────────────────────────────────────

class TextPatcher:
    """Applies a list of Patches to a single Terraform `.tf` file's text content."""

    def __init__(self, content: str) -> None:
        self._content = content

    def apply(self, patches: list[Patch], location: ResourceLocation) -> str:
        """Apply all patches for the given resource location.

        Returns the full modified file content.
        """
        lines = self._content.splitlines(keepends=True)

        # The location was captured from the original file. Previous patches to
        # other resources may have shifted line numbers, so relocate this block
        # before touching it.
        start, end = self._relocate_block(lines, location, location.start_line)

        # Separate tag-key patches from scalar patches
        tag_patches   = [p for p in patches if p.patch_kind == PatchKind.ADD_TAG_KEY]
        other_patches = [p for p in patches if p.patch_kind != PatchKind.ADD_TAG_KEY]

        # Apply scalar patches.  Sort by attribute path for determinism; line
        # indices will shift after each insertion, so we recalculate `start`/`end`
        # by re-scanning after every patch.
        for patch in other_patches:
            lines = self._apply_scalar_patch(lines, patch, start, end)
            # Recalculate block boundary after potential line insertions
            start, end = self._relocate_block(lines, location, start)

        # Apply all tag-key additions in one pass (to the same tags block)
        if tag_patches:
            # Tag patches may also shift the block end, so use the latest range.
            lines = self._apply_tag_patches(lines, tag_patches, start, end)

        return "".join(lines)

    # ── scalar patches ─────────────────────────────────────────────────────────

    def _apply_scalar_patch(
        self,
        lines: list[str],
        patch: Patch,
        start: int,
        end: int,
    ) -> list[str]:
        indent = _detect_indent(lines, start, end)

        if patch.patch_kind == PatchKind.SET_FLAT:
            return self._set_flat(lines, patch.attribute_path, patch.hcl_value, indent, start, end)

        if patch.patch_kind == PatchKind.SET_NESTED:
            outer, inner = patch.attribute_path.split(".", 1)
            return self._set_nested(lines, outer, inner, patch.hcl_value, indent, start, end)

        if patch.patch_kind == PatchKind.SET_NESTED_MAP_KEY:
            outer = patch.attribute_path.split(".", 1)[0]
            return self._set_nested_map_key(
                lines,
                outer,
                patch.map_name or "",
                patch.map_key or "",
                patch.hcl_value,
                indent,
                start,
                end,
            )

        if patch.patch_kind == PatchKind.ADD_BLOCK:
            return self._add_block(
                lines,
                patch.attribute_path,
                patch.block_defaults or {},
                indent,
                start,
                end,
            )

        return lines

    def _set_flat(
        self,
        lines: list[str],
        attr: str,
        hcl_value: str,
        indent: str,
        start: int,
        end: int,
    ) -> list[str]:
        """Replace or insert a flat attribute within a block."""
        attr_pat = re.compile(r'^(\s*)' + re.escape(attr) + r'\s*=\s*(.*)')
        for i in range(start + 1, end):
            m = attr_pat.match(lines[i])
            if m:
                existing_val = m.group(2).rstrip("\n\r")
                if _is_expression(existing_val):
                    return lines  # leave Terraform expressions untouched
                # Preserve trailing comment if any
                comment = ""
                if "#" in existing_val:
                    # crude: only strip comment if the # is outside quotes
                    hash_idx = _unquoted_hash(existing_val)
                    if hash_idx != -1:
                        comment = "  " + existing_val[hash_idx:]
                        existing_val = existing_val[:hash_idx].rstrip()
                new_line = f"{m.group(1)}{attr} = {hcl_value}{comment}\n"
                lines = list(lines)
                lines[i] = new_line
                return lines

        # Attribute not found — insert before the closing brace
        lines = list(lines)
        lines.insert(end, f"{indent}{attr} = {hcl_value}\n")
        return lines

    def _set_nested(
        self,
        lines: list[str],
        outer: str,
        inner: str,
        hcl_value: str,
        indent: str,
        start: int,
        end: int,
    ) -> list[str]:
        """Replace or insert `outer { inner = value }` within a block."""
        nested_indent = indent + "  "
        inner_block = self._find_inner_block(lines, outer, start, end)

        if inner_block is not None:
            o_start, o_end = inner_block
            # Look for inner attribute
            inner_pat = re.compile(r'^(\s*)' + re.escape(inner) + r'\s*=\s*(.*)')
            for i in range(o_start + 1, o_end):
                m = inner_pat.match(lines[i])
                if m:
                    existing_val = m.group(2).rstrip("\n\r")
                    if _is_expression(existing_val):
                        return lines
                    lines = list(lines)
                    lines[i] = f"{m.group(1)}{inner} = {hcl_value}\n"
                    return lines
            # Inner attribute not present; insert before outer's closing brace
            lines = list(lines)
            lines.insert(o_end, f"{nested_indent}{inner} = {hcl_value}\n")
            return lines

        # Outer block doesn't exist at all; insert a new one before closing brace
        lines = list(lines)
        new_block = (
            f"{indent}{outer} {{\n"
            f"{nested_indent}{inner} = {hcl_value}\n"
            f"{indent}}}\n"
        )
        for line in reversed(new_block.splitlines(keepends=True)):
            lines.insert(end, line)
        return lines

    def _add_block(
        self,
        lines: list[str],
        block_name: str,
        defaults: dict[str, Any],
        indent: str,
        start: int,
        end: int,
    ) -> list[str]:
        """Insert a missing nested block from a default template."""
        if self._find_inner_block(lines, block_name, start, end) is not None:
            return lines  # block already exists

        nested_indent = indent + "  "
        body_lines = _render_hcl_pairs(defaults, nested_indent)

        new_block_lines = [f"{indent}{block_name} {{\n"]
        new_block_lines.extend(body_lines)
        new_block_lines.append(f"{indent}}}\n")

        lines = list(lines)
        for line in reversed(new_block_lines):
            lines.insert(end, line)
        return lines

    def _set_nested_map_key(
        self,
        lines: list[str],
        outer: str,
        map_name: str,
        map_key: str,
        hcl_value: str,
        indent: str,
        start: int,
        end: int,
    ) -> list[str]:
        """Insert/update ``outer { map_name = { map_key = value } }``."""
        nested_indent = indent + "  "
        map_indent = nested_indent + "  "
        key_indent = map_indent + "  "

        outer_block = self._find_inner_block(lines, outer, start, end)

        if outer_block is None:
            # Create the whole outer block with the map and key.
            inner_lines = [f"{key_indent}{map_key} = {hcl_value}\n"]
            map_lines = [
                f"{nested_indent}{map_name} = {{\n",
                *inner_lines,
                f"{nested_indent}}}\n",
            ]
            block_lines = [f"{indent}{outer} {{\n", *map_lines, f"{indent}}}\n"]
            lines = list(lines)
            for line in reversed(block_lines):
                lines.insert(end, line)
            return lines

        o_start, o_end = outer_block

        # Find the map attribute inside the outer block.
        map_range = self._find_map_block(lines, map_name, o_start, o_end)
        if map_range is None:
            # Insert a new map attribute before the outer block closes.
            inner_lines = [f"{key_indent}{map_key} = {hcl_value}\n"]
            map_lines = [
                f"{nested_indent}{map_name} = {{\n",
                *inner_lines,
                f"{nested_indent}}}\n",
            ]
            lines = list(lines)
            for line in reversed(map_lines):
                lines.insert(o_end, line)
            return lines

        m_start, m_end = map_range
        if m_start == m_end:
            # Single-line map: expand to multi-line first.
            lines = self._expand_single_line_map(lines, m_start, nested_indent, map_name)
            map_range = self._find_map_block(lines, map_name, o_start, o_end)
            if map_range is None:
                map_range = (m_start, m_start + 2)
            m_start, m_end = map_range

        map_line = lines[m_start].rstrip()
        rhs = map_line.split("=", 1)[1].strip() if "=" in map_line else ""
        if _is_expression(rhs):
            return lines  # dynamic map — leave it alone

        # Insert key before the closing brace of the map.
        new_line = f"{key_indent}{map_key} = {hcl_value}\n"
        lines = list(lines)
        lines.insert(m_end, new_line)
        return lines

    @staticmethod
    def _find_map_block(
        lines: list[str],
        map_name: str,
        start: int,
        end: int,
    ) -> tuple[int, int] | None:
        """Find ``map_name = { ... }`` within lines[start:end]."""
        ml_pat = re.compile(r'^\s*' + re.escape(map_name) + r'\s*=\s*\{')
        sl_pat = re.compile(r'^\s*' + re.escape(map_name) + r'\s*=\s*\{[^}]*\}')

        for i in range(start + 1, min(end, len(lines))):
            line = lines[i]
            if sl_pat.match(line):
                return (i, i)
            if ml_pat.match(line):
                depth = _count_braces(line, "{") - _count_braces(line, "}")
                for j in range(i + 1, min(end + 1, len(lines))):
                    depth += _count_braces(lines[j], "{") - _count_braces(lines[j], "}")
                    if depth <= 0:
                        return (i, j)
        return None

    @staticmethod
    def _expand_single_line_map(
        lines: list[str],
        line_idx: int,
        indent: str,
        map_name: str,
    ) -> list[str]:
        """Convert ``map_name = { K = v }`` to a multi-line form."""
        line = lines[line_idx]
        pat = re.compile(r'^(\s*' + re.escape(map_name) + r'\s*=\s*)\{(.*)\}\s*$')
        m = pat.match(line.rstrip())
        if not m:
            return lines
        inner = m.group(2).strip()
        lines = list(lines)
        if inner:
            new_lines = [
                f"{indent}{map_name} = {{\n",
                f"{indent}  {inner}\n",
                f"{indent}}}\n",
            ]
        else:
            new_lines = [f"{indent}{map_name} = {{\n", f"{indent}}}\n"]
        lines[line_idx : line_idx + 1] = new_lines
        return lines

    # ── tag patches ────────────────────────────────────────────────────────────

    def _apply_tag_patches(
        self,
        lines: list[str],
        patches: list[Patch],
        start: int,
        end: int,
    ) -> list[str]:
        """Insert all missing tag keys into the tags block (or create it)."""
        indent = _detect_indent(lines, start, end)
        nested_indent = indent + "  "
        tag_keys = [p.tag_key for p in patches if p.tag_key]

        # Check for existing tags = { ... } (possibly single-line)
        tags_range = self._find_tags_block(lines, start, end)

        if tags_range is not None:
            t_start, t_end = tags_range
            # Check if it's a single-line `tags = { Key = "val" }`
            if t_start == t_end:
                lines = self._expand_single_line_tags(lines, t_start, indent)
                # Recalculate after expansion (tags block now spans multiple lines)
                tags_range = self._find_tags_block(lines, start, end + len(tag_keys) + 2)
                if tags_range is None:
                    tags_range = (t_start, t_start + 2)
                t_start, t_end = tags_range

            # Check for dynamic expression on the tags = line
            tags_line = lines[t_start].rstrip()
            rhs = tags_line.split("=", 1)[1].strip() if "=" in tags_line else ""
            if _is_expression(rhs):
                # Cannot patch into dynamic tag expression
                return lines

            # Insert all missing keys before the closing } of tags
            new_tag_lines = [
                f'{nested_indent}"{p.tag_key}" = {p.hcl_value}\n'
                for p in patches
            ]
            lines = list(lines)
            for tl in reversed(new_tag_lines):
                lines.insert(t_end, tl)
            return lines

        # No tags block at all — check if tags exists as a bare reference
        bare_tags_re = re.compile(r'^\s*tags\s*=\s*(.+)')
        for i in range(start + 1, end):
            m = bare_tags_re.match(lines[i])
            if m:
                rhs = m.group(1).rstrip()
                if _is_expression(rhs):
                    return lines  # dynamic tag expression — leave it
                break

        # Insert a new tags block before the resource's closing brace
        new_block_lines = [f"{indent}tags = {{\n"]
        for p in patches:
            new_block_lines.append(f'{nested_indent}"{p.tag_key}" = {p.hcl_value}\n')
        new_block_lines.append(f"{indent}}}\n")

        lines = list(lines)
        for nl in reversed(new_block_lines):
            lines.insert(end, nl)
        return lines

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _relocate_block(
        lines: list[str], loc: ResourceLocation, hint_start: int
    ) -> tuple[int, int]:
        """Re-locate a resource block after line insertions may have shifted its end."""
        if loc.block_type == "resource":
            result = _find_block_range(
                lines, loc.res_type, loc.res_name, hint_start
            )
        else:
            result = _find_provider_range(lines, loc.res_type, hint_start)
        if result is None:
            # Fallback: use the hint (shouldn't happen)
            return hint_start, hint_start + 1
        return result

    @staticmethod
    def _find_inner_block(
        lines: list[str], block_name: str, start: int, end: int
    ) -> tuple[int, int] | None:
        """Find `block_name { … }` within lines[start:end]."""
        pat = re.compile(r'^\s*' + re.escape(block_name) + r'\s*\{')
        depth = 0
        inner_start: int | None = None
        for i in range(start + 1, end):
            if pat.match(lines[i]) and inner_start is None:
                inner_start = i
                depth = _count_braces(lines[i], "{") - _count_braces(lines[i], "}")
                continue
            if inner_start is not None:
                depth += _count_braces(lines[i], "{") - _count_braces(lines[i], "}")
                if depth <= 0:
                    return (inner_start, i)
        return None

    @staticmethod
    def _find_tags_block(
        lines: list[str], start: int, end: int
    ) -> tuple[int, int] | None:
        """Find the `tags = { … }` block.  Returns (start, end) line indices."""
        # Multi-line: tags = {
        ml_pat = re.compile(r'^\s*tags\s*=\s*\{')
        # Single-line: tags = { ... }
        sl_pat = re.compile(r'^\s*tags\s*=\s*\{[^}]*\}')

        for i in range(start + 1, min(end, len(lines))):
            line = lines[i]
            if sl_pat.match(line):
                return (i, i)
            if ml_pat.match(line):
                depth = _count_braces(line, "{") - _count_braces(line, "}")
                for j in range(i + 1, min(end + 1, len(lines))):
                    depth += _count_braces(lines[j], "{") - _count_braces(lines[j], "}")
                    if depth <= 0:
                        return (i, j)
        return None

    @staticmethod
    def _expand_single_line_tags(
        lines: list[str], line_idx: int, indent: str
    ) -> list[str]:
        """Convert `tags = { K = "v" }` to a multi-line form."""
        nested_indent = indent + "  "
        line = lines[line_idx]
        # Extract content between the outer braces
        m = re.match(r'^(\s*tags\s*=\s*)\{(.*)\}\s*$', line.rstrip())
        if not m:
            return lines  # can't expand safely
        inner = m.group(2).strip()
        lines = list(lines)
        if inner:
            new_lines = [
                f"{indent}tags = {{\n",
                f"{nested_indent}{inner}\n",
                f"{indent}}}\n",
            ]
        else:
            new_lines = [f"{indent}tags = {{\n", f"{indent}}}\n"]
        lines[line_idx : line_idx + 1] = new_lines
        return lines


# ── Native attribute-path mapping for non-Terraform frameworks ────────────────

_CDK_REVERSE_ALIASES: dict[tuple[str, str], list[str]] = {
    # S3
    ("aws_s3_bucket", "versioning.enabled"): ["versioned"],
    # Lambda
    ("aws_lambda_function", "tracing_config.mode"): ["tracing"],
}


def _snake_case_to_camel_case(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _native_attribute_path(res_type: str, attribute_path: str, framework: str) -> list[str]:
    """Map a normalized snake_case attribute path to the native prop/argument path."""
    parts = attribute_path.split(".")
    if framework == "cdk":
        special = _CDK_REVERSE_ALIASES.get((res_type, attribute_path))
        if special:
            return special
        # Only the top-level CDK prop name is camelCase; nested map keys are preserved.
        if parts:
            return [_snake_case_to_camel_case(parts[0]), *parts[1:]]
    return parts


# ── TypeScript/CDK source patcher ─────────────────────────────────────────────

class _TsExpr:
    """Wraps a raw TypeScript expression so the renderer emits it verbatim."""

    def __init__(self, text: str) -> None:
        self.text = text


def _parse_ts_props_object(text: str, start: int) -> tuple[dict[str, Any], int] | None:
    """Parse a JS/TS object literal, preserving raw expressions as ``_TsExpr``."""
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text) or text[i] != '{':
        return None
    i += 1
    result: dict[str, Any] = {}

    while i < len(text):
        while i < len(text) and (text[i].isspace() or text[i] == ','):
            i += 1
        if i >= len(text):
            return None
        if text[i] == '}':
            return result, i

        # Key
        if text[i] in ('"', "'"):
            key, end = _cdk_extract_string_literal(text, i)
            if key is None:
                return None
            i = end + 1
        elif text[i].isidentifier() or text[i] == '$':
            key_start = i
            while i < len(text) and (text[i].isalnum() or text[i] in '_$'):
                i += 1
            key = text[key_start:i]
        else:
            return None

        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != ':':
            return None
        i += 1

        value, i = _parse_ts_value(text, i)
        if value is ...:
            return None
        result[key] = value

        while i < len(text) and text[i].isspace():
            i += 1
        if i < len(text) and text[i] == ',':
            i += 1

    return None


def _parse_ts_array(text: str, start: int) -> tuple[list[Any], int] | None:
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
        value, i = _parse_ts_value(text, i)
        if value is ...:
            return None
        result.append(value)
        while i < len(text) and text[i].isspace():
            i += 1
        if i < len(text) and text[i] == ',':
            i += 1
    return None


def _parse_ts_value(text: str, start: int) -> tuple[Any, int]:
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        return ..., i

    ch = text[i]
    if ch in ('"', "'"):
        s, end = _cdk_extract_string_literal(text, i)
        if s is None:
            return ..., i
        return s, end + 1
    if ch == '{':
        parsed = _parse_ts_props_object(text, i)
        if parsed is None:
            return ..., i
        return parsed[0], parsed[1] + 1
    if ch == '[':
        parsed = _parse_ts_array(text, i)
        if parsed is None:
            return ..., i
        return parsed[0], parsed[1] + 1
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

    # Raw expression (identifier, member access, call, …)
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
            _, end = _cdk_extract_string_literal(text, i)
            if end == -1:
                i = len(text)
                break
            i = end + 1
            continue
        i += 1
    raw = text[expr_start:i].strip()
    return _TsExpr(raw), i


class TsTextPatcher:
    """Applies Patches to a CDK TypeScript construct call's props object."""

    def __init__(self, content: str) -> None:
        self._content = content

    def apply(self, patches: list[Patch], location: ResourceLocation) -> str:
        content = self._content
        expected_address = location.address
        for match in _CDK_NEW_RE.finditer(content):
            class_name = match.group(2)
            res_type = _CDK_TYPES.get(class_name)
            if res_type is None:
                continue
            new_pos = match.start()
            _, id_src, props_src, close = _cdk_find_call_args(content, new_pos)
            if close == -1:
                continue
            logical_id = _cdk_extract_logical_id(id_src)
            if f"{res_type}.{logical_id}" != expected_address:
                continue

            if not props_src or not props_src.strip().startswith("{"):
                return content

            props_start = content.find(props_src, new_pos)
            if props_start == -1:
                return content
            brace_open = props_start + props_src.index("{")
            brace_close = _cdk_find_matching_paren(content, brace_open, "{", "}")
            if brace_close == -1:
                return content

            parsed = _parse_ts_props_object(content, brace_open)
            if parsed is None:
                return content
            props = parsed[0]

            for p in patches:
                _apply_patch_to_ts_props(props, p, res_type)

            base_indent = self._base_indent(content, new_pos)
            new_props = _render_ts_object(props, base_indent + "  ", base_indent)
            return content[:brace_open] + new_props + content[brace_close + 1 :]
        return content

    @staticmethod
    def _base_indent(content: str, pos: int) -> str:
        line_start = content.rfind("\n", 0, pos) + 1
        indent_end = pos
        while indent_end < len(content) and content[indent_end].isspace() and content[indent_end] != "\n":
            indent_end += 1
        return content[line_start:indent_end]


def _apply_patch_to_ts_props(props: dict[str, Any], patch: Patch, res_type: str) -> None:
    if patch.patch_kind == PatchKind.ADD_TAG_KEY:
        path = ["tags", patch.tag_key or "unknown"]
        value: Any = _ts_value_from_literal(patch.hcl_value)
    elif patch.patch_kind == PatchKind.ADD_BLOCK:
        path, value = _cdk_reverse_path_and_value(
            res_type, patch.attribute_path, patch.block_defaults or {}
        )
    else:
        path, value = _cdk_reverse_path_and_value(
            res_type, patch.attribute_path, _ts_value_from_literal(patch.hcl_value)
        )
    _set_nested_dict(props, path, value)


def _cdk_reverse_path_and_value(
    res_type: str, attribute_path: str, value: Any
) -> tuple[list[str], Any]:
    """Reverse-map a normalized attribute path back to a CDK prop path and value."""
    for cdk_prop, alias in _CDK_PROP_ALIASES.items():
        if isinstance(alias, str):
            target = alias
            passthrough = False
            when_true = None
        else:
            target = alias.get("target", "")
            passthrough = alias.get("passthrough", False)
            when_true = alias.get("when_true")

        if attribute_path == target:
            if when_true is not None:
                return [cdk_prop], True
            return [cdk_prop], value

        if passthrough and attribute_path.startswith(target + "."):
            remainder = attribute_path[len(target) + 1 :]
            return [cdk_prop, *remainder.split(".")], value

    # Fallback: camelCase the first segment only.
    parts = attribute_path.split(".")
    return [_snake_case_to_camel_case(parts[0]), *parts[1:]], value


def _set_nested_dict(obj: dict[str, Any], path: list[str], value: Any) -> None:
    for key in path[:-1]:
        if key not in obj or not isinstance(obj[key], dict):
            obj[key] = {}
        obj = obj[key]
    obj[path[-1]] = value


def _ts_value_from_literal(literal: str) -> Any:
    """Best-effort parse of a rendered TypeScript literal string back to a Python value."""
    s = literal.strip()
    if s == "true":
        return True
    if s == "false":
        return False
    if s == "null":
        return None
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("\\'", "'")
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        pass
    return s


def _render_ts_object(obj: dict[str, Any], indent: str, base_indent: str) -> str:
    if not obj:
        return "{}"
    lines = [f"{{\n"]
    for k, v in obj.items():
        key = _ts_prop_key(k)
        lines.append(f"{indent}{key}: {_render_ts_value(v, indent + '  ')},\n")
    lines.append(f"{base_indent}}}")
    return "".join(lines)


def _render_ts_value(value: Any, indent: str) -> str:
    if isinstance(value, _TsExpr):
        return value.text
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("'", "\\'")
        return f"'{escaped}'"
    if isinstance(value, dict):
        return _render_ts_object(value, indent + "  ", indent)
    if isinstance(value, list):
        return "[" + ", ".join(_render_ts_value(v, indent) for v in value) + "]"
    escaped = str(value).replace("'", "\\'")
    return f"'{escaped}'"


# ── Python/Pulumi source patcher ────────────────────────────────────────────────

class PythonTextPatcher:
    """Applies Patches to a Pulumi Python resource constructor call."""

    def __init__(self, content: str) -> None:
        self._content = content

    def apply(self, patches: list[Patch], location: ResourceLocation) -> str:
        import ast as _ast

        tree = _ast.parse(self._content)

        # Build a parent map so we can replace the enclosing statement.
        parents: dict[_ast.AST, _ast.AST] = {}

        def _visit(parent: _ast.AST | None, node: _ast.AST) -> None:
            if parent is not None:
                parents[node] = parent
            for child in _ast.iter_child_nodes(node):
                _visit(node, child)

        _visit(None, tree)

        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            res_type, _ = _pulumi_is_aws_resource_call(node.func)
            if res_type is None:
                continue
            logical_id = _pulumi_extract_name(node.args[0] if node.args else None)
            if f"{res_type}.{logical_id}" != location.address:
                continue

            for p in patches:
                _apply_patch_to_pulumi_call(node, p, res_type)

            parent = parents.get(node)
            if parent is None:
                return self._content

            new_stmt_src = _ast.unparse(parent)
            start_line = (parent.lineno or 1) - 1
            end_line = (parent.end_lineno or parent.lineno or 1) - 1
            lines = self._content.splitlines(keepends=True)

            prefix = "".join(lines[:start_line])
            suffix = "".join(lines[end_line + 1 :])
            original_first = lines[start_line]
            base_indent = original_first[: len(original_first) - len(original_first.lstrip())]
            rendered = _indent_python_source(new_stmt_src, base_indent)
            return prefix + rendered + suffix
        return self._content


def _indent_python_source(source: str, base_indent: str) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    first = lines[0]
    # Strip leading whitespace from the first line and prepend base_indent.
    result = [base_indent + first.lstrip()]
    for line in lines[1:]:
        result.append(base_indent + line)
    return "\n".join(result)


def _apply_patch_to_pulumi_call(node: ast.Call, patch: Patch, res_type: str) -> None:
    if patch.patch_kind == PatchKind.ADD_TAG_KEY:
        path = ["tags", patch.tag_key or "unknown"]
        value = _python_value_from_literal(patch.hcl_value)
    elif patch.patch_kind == PatchKind.ADD_BLOCK:
        path = _native_attribute_path(res_type, patch.attribute_path, "pulumi")
        value = patch.block_defaults or {}
    else:
        path = _native_attribute_path(res_type, patch.attribute_path, "pulumi")
        value = _python_value_from_literal(patch.hcl_value)

    kwargs_by_name = {kw.arg: kw for kw in node.keywords}
    first_key = path[0]
    if first_key in kwargs_by_name:
        kw = kwargs_by_name[first_key]
        if len(path) == 1:
            kw.value = _python_ast_value(value)
        else:
            kw.value = _set_or_merge_python_dict(kw.value, path[1:], value)
    else:
        if len(path) == 1:
            new_value = _python_ast_value(value)
        else:
            new_value = _build_nested_python_dict(path[1:], value)
        node.keywords.append(ast.keyword(arg=first_key, value=new_value))


def _python_value_from_literal(literal: str) -> Any:
    s = literal.strip()
    if s == "True":
        return True
    if s == "False":
        return False
    if s == "None":
        return None
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("\\'", "'")
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        pass
    return s


def _python_ast_value(value: Any) -> ast.expr:
    if isinstance(value, bool):
        return ast.Constant(value=value)
    if value is None:
        return ast.Constant(value=None)
    if isinstance(value, (int, float, str)):
        return ast.Constant(value=value)
    if isinstance(value, list):
        return ast.List(elts=[_python_ast_value(v) for v in value], ctx=ast.Load())
    if isinstance(value, dict):
        return ast.Dict(
            keys=[ast.Constant(value=k) for k in value.keys()],
            values=[_python_ast_value(v) for v in value.values()],
        )
    return ast.Constant(value=str(value))


def _build_nested_python_dict(path: list[str], value: Any) -> ast.expr:
    if not path:
        return _python_ast_value(value)
    inner = _build_nested_python_dict(path[1:], value)
    return ast.Dict(keys=[ast.Constant(value=path[0])], values=[inner])


def _set_or_merge_python_dict(node: ast.expr, path: list[str], value: Any) -> ast.expr:
    if not isinstance(node, ast.Dict):
        return _build_nested_python_dict(path, value)
    if not path:
        return _python_ast_value(value)
    key = path[0]
    keys = [k.value if isinstance(k, ast.Constant) else None for k in node.keys]
    if key in keys:
        idx = keys.index(key)
        node.values[idx] = _set_or_merge_python_dict(node.values[idx], path[1:], value)
    else:
        node.keys.append(ast.Constant(value=key))
        node.values.append(_build_nested_python_dict(path[1:], value))
    return node


# ── Block range finders (file-level helpers) ──────────────────────────────────

def _find_block_range(
    lines: list[str], res_type: str, res_name: str, hint: int = 0
) -> tuple[int, int] | None:
    """Find the line range of `resource "TYPE" "NAME" { … }`."""
    pat = re.compile(
        r'^\s*resource\s+"' + re.escape(res_type)
        + r'"\s+"' + re.escape(res_name) + r'"\s*\{'
    )
    for i in range(hint, len(lines)):
        if pat.match(lines[i]):
            depth = _count_braces(lines[i], "{") - _count_braces(lines[i], "}")
            for j in range(i + 1, len(lines)):
                depth += _count_braces(lines[j], "{") - _count_braces(lines[j], "}")
                if depth <= 0:
                    return (i, j)
    return None


def _find_provider_range(
    lines: list[str], provider_name: str, hint: int = 0
) -> tuple[int, int] | None:
    """Find the line range of `provider "NAME" { … }`."""
    pat = re.compile(r'^\s*provider\s+"' + re.escape(provider_name) + r'"\s*\{')
    for i in range(hint, len(lines)):
        if pat.match(lines[i]):
            depth = _count_braces(lines[i], "{") - _count_braces(lines[i], "}")
            for j in range(i + 1, len(lines)):
                depth += _count_braces(lines[j], "{") - _count_braces(lines[j], "}")
                if depth <= 0:
                    return (i, j)
    return None


def _unquoted_hash(s: str) -> int:
    """Return the index of the first '#' outside quotes, or -1."""
    in_str = False
    for i, ch in enumerate(s):
        if ch == '"':
            in_str = not in_str
        elif ch == "#" and not in_str:
            return i
    return -1


# ── Atomic write helpers ──────────────────────────────────────────────────────

def _run_terraform_fmt(path: Path) -> list[str]:
    """Run ``terraform fmt`` or ``tofu fmt`` on ``path`` if a binary is available.

    Returns a list of warning messages (empty on success).
    """
    binary: str | None = None
    for candidate in ("terraform", "tofu"):
        if shutil.which(candidate):
            binary = candidate
            break
    if binary is None:
        return ["terraform/tofu not found — skipped formatting."]

    try:
        subprocess.run(
            [binary, "fmt", "-write", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        return [f"{binary} fmt failed: {exc.stderr.strip() or exc.stdout.strip() or 'unknown error'}"]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"{binary} fmt could not run: {exc}"]
    return []


def _run_prettier(path: Path) -> list[str]:
    binary = shutil.which("prettier")
    if binary is None:
        return ["prettier not found — skipped TypeScript formatting."]
    try:
        subprocess.run(
            [binary, "--write", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        return [f"prettier failed: {exc.stderr.strip() or exc.stdout.strip() or 'unknown error'}"]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"prettier could not run: {exc}"]
    return []


def _run_black(path: Path) -> list[str]:
    binary = shutil.which("black")
    if binary is None:
        return ["black not found — skipped Python formatting."]
    try:
        subprocess.run(
            [binary, str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        return [f"black failed: {exc.stderr.strip() or exc.stdout.strip() or 'unknown error'}"]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"black could not run: {exc}"]
    return []


def _run_formatter(path: Path, framework: str) -> list[str]:
    if framework == "cdk":
        return _run_prettier(path)
    if framework == "pulumi":
        return _run_black(path)
    return _run_terraform_fmt(path)


def _write_atomic(
    file_path: Path,
    content: str,
    backup: bool = True,
    framework: str = "terraform",
) -> list[str]:
    """Write ``content`` to ``file_path`` atomically with optional backup.

    1. Write to a temp file next to the target.
    2. Run a framework-specific formatter on the temp file (warnings collected, never fatal).
    3. Copy the original to ``file_path.bak`` if ``backup`` is true.
    4. Atomically replace the target with the temp file.

    Returns a list of warning strings.
    """
    warnings: list[str] = []
    tmp_path = file_path.with_name(f"{file_path.stem}.tmp.{os.getpid()}{file_path.suffix}")

    try:
        tmp_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        warnings.append(f"Could not write temp file {tmp_path}: {exc}")
        return warnings

    fmt_warnings = _run_formatter(tmp_path, framework)
    warnings.extend(fmt_warnings)

    if backup:
        try:
            bak_path = file_path.with_suffix(file_path.suffix + ".bak")
            shutil.copy2(file_path, bak_path)
        except OSError as exc:
            warnings.append(f"Could not create backup {bak_path}: {exc}")

    try:
        os.replace(tmp_path, file_path)
    except OSError as exc:
        warnings.append(f"Atomic replace failed for {file_path}: {exc}")
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    return warnings


def restore_backup(file_path: Path) -> bool:
    """Restore ``file_path`` from its ``.bak`` backup if it exists.

    Returns ``True`` if a backup was restored.
    """
    bak_path = file_path.with_suffix(file_path.suffix + ".bak")
    if not bak_path.exists():
        return False
    try:
        shutil.copy2(bak_path, file_path)
        bak_path.unlink()
        return True
    except OSError:
        return False


# ── Apply plan ────────────────────────────────────────────────────────────────

def apply_fix_plan(
    plan: FixPlan,
    locator: ResourceLocator,
    dry_run: bool = True,
    backup: bool = True,
) -> FixApplyResult:
    """Apply a FixPlan to disk (or just compute diffs in dry-run mode).

    Returns a :class:`FixApplyResult` containing the diff map and any warnings.
    """
    diffs: dict[Path, tuple[str, str]] = {}
    warnings: list[str] = []

    # Group active patches by file
    patches_by_file: dict[Path, list[Patch]] = {}
    for p in plan.active_patches:
        patches_by_file.setdefault(p.file_path, []).append(p)

    for file_path, patches in patches_by_file.items():
        try:
            original = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.append(f"Could not read {file_path}: {exc}")
            continue

        patcher = TextPatcher(original)

        # Group patches further by address
        by_address: dict[str, list[Patch]] = {}
        for p in patches:
            by_address.setdefault(p.address, []).append(p)

        patched = original
        for address, addr_patches in by_address.items():
            loc = locator.get(address)
            if loc is None:
                continue
            framework = addr_patches[0].framework if addr_patches else "terraform"
            # Re-instantiate patcher with the current (possibly already patched) content
            if framework == "cdk":
                patcher2 = TsTextPatcher(patched)
            elif framework == "pulumi":
                patcher2 = PythonTextPatcher(patched)
            else:
                patcher2 = TextPatcher(patched)
            patched = patcher2.apply(addr_patches, loc)

        if patched == original:
            continue  # no net change

        diffs[file_path] = (original, patched)

        if not dry_run:
            framework = next((p.framework for p in patches), "terraform")
            write_warnings = _write_atomic(file_path, patched, backup=backup, framework=framework)
            warnings.extend(write_warnings)

    return FixApplyResult(diffs=diffs, warnings=warnings)


# ── Post-apply delta ──────────────────────────────────────────────────────────

def compute_fix_delta(
    original_results: list[ControlResult],
    new_results: list[ControlResult],
) -> FixDelta:
    """Compare two check run outcomes and report improvements/regressions."""
    def _fail_set(results: list[ControlResult]) -> set[tuple[str, str]]:
        s: set[tuple[str, str]] = set()
        for cr in results:
            for r in cr.results:
                if r.status == "FAIL":
                    s.add((r.check_id, r.resource))
        return s

    def _pass_set(results: list[ControlResult]) -> set[tuple[str, str]]:
        s: set[tuple[str, str]] = set()
        for cr in results:
            for r in cr.results:
                if r.status == "PASS":
                    s.add((r.check_id, r.resource))
        return s

    orig_fail = _fail_set(original_results)
    new_fail  = _fail_set(new_results)
    orig_pass = _pass_set(original_results)
    new_pass  = _pass_set(new_results)

    resolved       = sorted(orig_fail - new_fail)
    still_failing  = sorted(orig_fail & new_fail)
    regressions    = sorted(new_fail - orig_fail - (orig_fail | new_fail - orig_pass))

    return FixDelta(
        resolved=resolved,
        still_failing=still_failing,
        regressions=regressions,
    )


# ── Diff rendering helpers (used by CLI) ──────────────────────────────────────

def render_diff(original: str, patched: str, file_path: Path) -> list[str]:
    """Return unified diff lines for a patched source file.

    The returned strings are prefix-coloured for CLI rendering:
    ``+`` additions in green, ``-`` deletions in red, context in dim white.
    """
    return list(difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{file_path.name}",
        tofile=f"b/{file_path.name}",
        lineterm="",
    ))
