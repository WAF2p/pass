"""Auto-fix engine for WAF++ PASS.

Derives and applies surgical text patches to Terraform (.tf) source files
based on failing WAF++ check results.  The engine is deliberately conservative:

- It only patches assertions whose desired value can be derived unambiguously
  from the control definition (is_true → true, equals → <expected>, …).
- It guards against overwriting Terraform expressions (var., local., ${ … }).
- Dry-run is the default; ``--apply`` must be passed explicitly in the CLI.
- One patch per (file, address, attribute) — duplicates are deduplicated.
- Tags-map insertions are batched so the tags block is only rewritten once
  even when multiple tag keys are missing from the same resource.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from wafpass.engine import SkipAssertion, evaluate_assertion
from wafpass.iac.base import IaCBlock, IaCState
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
    "attribute_exists":             "no unambiguous default value can be derived",
    "attribute_exists_or_fallback": "no unambiguous default value can be derived",
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

# Expression pattern: Terraform dynamic references that we must not overwrite
_EXPR_RE = re.compile(
    r'\$\{'                     # interpolation  ${...}
    r'|\bvar\.'                 # variable ref   var.foo
    r'|\blocal\.'               # local ref      local.foo
    r'|\bdata\.'                # data ref       data.foo
    r'|\bmodule\.'              # module ref     module.foo
    r'|\bmerge\s*\('            # function call  merge(...)
    r'|\bconcat\s*\('           # function call  concat(...)
    r'|\btoset\s*\('            # function call  toset(...)
    r'|\btomap\s*\('            # function call  tomap(...)
)


# ── Data structures ────────────────────────────────────────────────────────────

class PatchKind(Enum):
    SET_FLAT    = auto()   # replace / insert  attr = value  at resource scope
    SET_NESTED  = auto()   # replace / insert  outer { inner = value }
    ADD_TAG_KEY = auto()   # add "key" = "TODO-fill-in" inside tags = { }


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
    """A single, atomic text change to a .tf source file."""
    file_path: Path
    address: str            # resource address
    attribute_path: str     # dotted attribute path, e.g. "tags" or "versioning.enabled"
    patch_kind: PatchKind
    hcl_value: str          # rendered HCL literal to write
    tag_key: str | None     # only for ADD_TAG_KEY
    check_id: str
    control_id: str
    description: str
    already_applied: bool = False  # True if deduplicated away


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


# ── HCL value renderer ────────────────────────────────────────────────────────

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
    return f'"{value}"'


def _is_expression(text: str) -> bool:
    """Return True if text contains a Terraform dynamic reference."""
    return bool(_EXPR_RE.search(text))


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
    """Scans .tf files to build an index of resource and provider block positions."""

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
) -> Patch | SkippedFix | None:
    """Derive a Patch for one assertion, or SkippedFix if not auto-fixable.

    Returns None when the assertion is already passing (no fix needed).
    """
    op = assertion.op

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
        )

    # ── Derive hcl_value for scalar operators ─────────────────────────────────
    hcl_value: str | None = None

    if op == "is_true":
        hcl_value = "true"
    elif op == "is_false":
        hcl_value = "false"
    elif op in ("equals", "greater_than_or_equal", "less_than_or_equal"):
        if assertion.expected is None:
            return SkippedFix(
                check_id=check.id, control_id=control.id, address=address,
                attribute=assertion.attribute, op=op,
                reason="assertion has no 'expected' value defined",
            )
        hcl_value = _render_hcl(assertion.expected)
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
        hcl_value = _render_hcl(expected_list[0])

    if hcl_value is None:
        return SkippedFix(
            check_id=check.id, control_id=control.id, address=address,
            attribute=assertion.attribute, op=op,
            reason="could not derive an HCL value from the assertion",
        )

    # ── Determine patch kind from attribute path depth ────────────────────────
    attr_parts = assertion.attribute.split(".")
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
                        f"resource not found in scanned .tf files "
                        f"(may be in a module or dynamically generated)"
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
                )

                if result is None:
                    continue  # already passing

                if isinstance(result, SkippedFix):
                    plan.skipped.append(result)
                    continue

                # Deduplication key
                dedup_attr = (
                    f"{result.attribute_path}:{result.tag_key}"
                    if result.patch_kind == PatchKind.ADD_TAG_KEY
                    else result.attribute_path
                )
                key = (result.file_path, address, dedup_attr)
                if key in seen_patch_keys:
                    result.already_applied = True
                else:
                    seen_patch_keys.add(key)

                plan.patches.append(result)

    return plan


# ── TextPatcher ────────────────────────────────────────────────────────────────

class TextPatcher:
    """Applies a list of Patches to a single .tf file's text content."""

    def __init__(self, content: str) -> None:
        self._content = content

    def apply(self, patches: list[Patch], location: ResourceLocation) -> str:
        """Apply all patches for the given resource location.

        Returns the full modified file content.
        """
        lines = self._content.splitlines(keepends=True)
        start = location.start_line
        end   = location.end_line

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
                f'{nested_indent}"{k}" = "TODO-fill-in"\n'
                for k in tag_keys
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
        for k in tag_keys:
            new_block_lines.append(f'{nested_indent}"{k}" = "TODO-fill-in"\n')
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


# ── Apply plan ────────────────────────────────────────────────────────────────

def apply_fix_plan(
    plan: FixPlan,
    locator: ResourceLocator,
    dry_run: bool = True,
    backup: bool = True,
) -> dict[Path, tuple[str, str]]:
    """Apply a FixPlan to disk (or just compute diffs in dry-run mode).

    Returns a mapping of ``file_path → (original_content, patched_content)``
    for every file that has at least one non-trivial change.
    """
    results: dict[Path, tuple[str, str]] = {}

    # Group active patches by file
    patches_by_file: dict[Path, list[Patch]] = {}
    for p in plan.active_patches:
        patches_by_file.setdefault(p.file_path, []).append(p)

    for file_path, patches in patches_by_file.items():
        try:
            original = file_path.read_text(encoding="utf-8")
        except OSError:
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
            # Re-instantiate patcher with the current (possibly already patched) content
            patcher2 = TextPatcher(patched)
            patched = patcher2.apply(addr_patches, loc)

        if patched == original:
            continue  # no net change

        results[file_path] = (original, patched)

        if not dry_run:
            if backup:
                bak = file_path.with_suffix(file_path.suffix + ".bak")
                bak.write_text(original, encoding="utf-8")
            file_path.write_text(patched, encoding="utf-8")

    return results


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
    """Return coloured diff lines for Rich rendering.

    Each item is a tuple (text, style) where style is a Rich markup string.
    Use ``rich.text.Text`` to assemble.
    """
    return list(difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{file_path.name}",
        tofile=f"b/{file_path.name}",
        lineterm="",
    ))
