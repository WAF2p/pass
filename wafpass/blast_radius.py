"""Blast radius analysis for WAF++ PASS.

Given a set of WAF++ check results and the parsed IaC state, this module:

1. Extracts cross-resource references from each IaCBlock's attributes
   (Terraform: ``${resource_type.name.attr}`` interpolation syntax).
2. Builds a *downstream impact graph*: for every resource X, which other
   resources directly reference X and would therefore be affected if X is
   misconfigured or compromised.
3. Performs a BFS from every resource that FAILED at least one control to
   produce a ranked, hop-annotated blast radius result.

Hop semantics
-------------
- **Hop 0** — the root-cause resource itself (control failed here).
- **Hop 1** — directly references the root; inherits the misconfiguration
  risk (e.g. an RDS instance using a KMS key whose rotation is disabled).
- **Hop 2** — references a hop-1 resource; secondary exposure.
- **Hop 3+** — tertiary / residual exposure.

Criticality labels map hop distance to an impact tier:

    hop 0: severity of the failing control  (CRITICAL / HIGH / MEDIUM / LOW)
    hop 1: HIGH
    hop 2: MEDIUM
    hop 3+: LOW
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from wafpass.iac.base import IaCBlock, IaCState
from wafpass.models import Report

# ── Reference extraction ──────────────────────────────────────────────────────

# Matches ${resource_type.resource_name.anything} — captures resource_type.resource_name
_REF_RE = re.compile(r"\$\{([a-z][a-z0-9_]+\.[a-zA-Z][a-zA-Z0-9_]*)[\.\}]")

# Prefixes that are NOT resource references
_NON_RESOURCE = {"var", "local", "module", "data", "path", "each", "self", "count",
                 "terraform", "env"}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _iter_strings(obj: object):
    """Recursively yield every string found in a nested dict/list structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_strings(item)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)


def extract_resource_refs(block: IaCBlock) -> set[str]:
    """Return the set of ``resource_type.resource_name`` addresses this block references."""
    refs: set[str] = set()
    for s in _iter_strings(block.attributes):
        for m in _REF_RE.finditer(s):
            ref = m.group(1)
            prefix = ref.split(".")[0]
            if prefix not in _NON_RESOURCE:
                refs.add(ref)
    return refs


def build_dependency_graph(state: IaCState) -> dict[str, set[str]]:
    """Build a downstream impact graph.

    Returns ``{source_address: {dependent_address, ...}}`` — i.e. for each
    resource, the set of other resources that *reference* it and would be
    indirectly affected if the source is misconfigured.
    """
    all_addresses = {b.address for b in state.resources}
    downstream: dict[str, set[str]] = defaultdict(set)

    for block in state.resources:
        for ref in extract_resource_refs(block):
            if ref in all_addresses:
                downstream[ref].add(block.address)

    return dict(downstream)


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class BlastNode:
    """A single node in the blast radius result."""

    address: str
    hop: int                          # 0 = root cause
    is_root: bool                     # True when this resource itself failed a control
    failed_controls: list[str]        # control IDs that failed (root nodes only)
    failed_severity: str | None       # highest severity among failed controls
    impact_label: str                 # CRITICAL / HIGH / MEDIUM / LOW
    parents: list[str] = field(default_factory=list)   # addresses this node was reached from


@dataclass
class BlastResult:
    """Full blast radius analysis output."""

    roots: list[BlastNode]            # resources that directly failed controls
    affected: list[BlastNode]         # downstream resources, sorted by hop
    edges: list[tuple[str, str]]      # (source, dependent) pairs for graph rendering
    total_affected: int               # len(roots) + len(affected)


# ── Analysis ──────────────────────────────────────────────────────────────────

def _highest_severity(severities: list[str]) -> str:
    if not severities:
        return "low"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s.lower(), 0))


def _impact_label(hop: int, root_severity: str | None = None) -> str:
    if hop == 0:
        return (root_severity or "low").upper()
    return {1: "HIGH", 2: "MEDIUM"}.get(hop, "LOW")


def compute_blast_radius(
    report: Report,
    state: IaCState,
    graph: dict[str, set[str]],
) -> BlastResult:
    """Compute the blast radius for all failing resources in *report*.

    Args:
        report:  The WAF++ check report (contains FAIL results).
        state:   Parsed IaC state (used for address resolution).
        graph:   Downstream impact graph from :func:`build_dependency_graph`.

    Returns:
        :class:`BlastResult` with root and affected nodes, plus edge list.
    """
    # ── Collect failed resources ──────────────────────────────────────────────
    failed: dict[str, list[tuple[str, str]]] = defaultdict(list)  # addr -> [(ctrl_id, sev)]
    for cr in report.results:
        if cr.status == "FAIL":
            for r in cr.results:
                if r.status == "FAIL":
                    failed[r.resource].append((cr.control.id, cr.control.severity))

    if not failed:
        return BlastResult(roots=[], affected=[], edges=[], total_affected=0)

    # ── BFS from every failed resource ───────────────────────────────────────
    visited: dict[str, int] = {}       # address -> hop
    parents: dict[str, list[str]] = defaultdict(list)
    edges: list[tuple[str, str]] = []
    queue: deque[tuple[str, int]] = deque()

    for addr in failed:
        visited[addr] = 0
        queue.append((addr, 0))

    while queue:
        current, hop = queue.popleft()
        for dependent in sorted(graph.get(current, [])):
            edges.append((current, dependent))
            if dependent not in visited:
                visited[dependent] = hop + 1
                parents[dependent].append(current)
                queue.append((dependent, hop + 1))
            elif visited[dependent] == hop + 1:
                parents[dependent].append(current)

    # ── Build node objects ────────────────────────────────────────────────────
    roots: list[BlastNode] = []
    affected: list[BlastNode] = []

    for addr, hop in visited.items():
        controls = failed.get(addr, [])
        ctrl_ids = [c for c, _ in controls]
        severities = [s for _, s in controls]
        sev = _highest_severity(severities) if severities else None
        node = BlastNode(
            address=addr,
            hop=hop,
            is_root=(hop == 0 or bool(controls)),
            failed_controls=ctrl_ids,
            failed_severity=sev,
            impact_label=_impact_label(hop, sev),
            parents=parents.get(addr, []),
        )
        if hop == 0:
            roots.append(node)
        else:
            affected.append(node)

    affected.sort(key=lambda n: (n.hop, n.address))

    return BlastResult(
        roots=roots,
        affected=affected,
        edges=edges,
        total_affected=len(roots) + len(affected),
    )
