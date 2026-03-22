"""Rendering for WAF++ PASS blast radius analysis.

Provides two output formats:

- **Rich terminal tree** — printed to stdout with colour-coded criticality.
- **Mermaid diagram** — written to a ``.md`` file, renderable in GitHub,
  GitLab, Notion, or any Mermaid-aware viewer.

Criticality colour scheme
-------------------------
+----------+--------+--------------------------------------------------------+
| Label    | Colour | Meaning                                                |
+==========+========+========================================================+
| CRITICAL | Red    | Root cause; control failure severity = critical        |
+----------+--------+--------------------------------------------------------+
| HIGH     | Orange | Directly depends on a failing resource (hop 1), or    |
|          |        | root cause with high-severity failure                  |
+----------+--------+--------------------------------------------------------+
| MEDIUM   | Yellow | Two hops from a failing resource                       |
+----------+--------+--------------------------------------------------------+
| LOW      | Dim    | Three or more hops from a failing resource             |
+----------+--------+--------------------------------------------------------+
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from wafpass.blast_radius import BlastNode, BlastResult

# ── Colour helpers ────────────────────────────────────────────────────────────

_LABEL_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "dim",
}

_LABEL_ICON: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "⚪",
}

# Mermaid node fill colours
_MERMAID_FILL: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#c0392b", "#ffffff"),
    "HIGH":     ("#e67e22", "#ffffff"),
    "MEDIUM":   ("#f1c40f", "#333333"),
    "LOW":      ("#95a5a6", "#ffffff"),
}


def _node_style(node: BlastNode) -> str:
    return _LABEL_STYLE.get(node.impact_label, "")


def _node_icon(node: BlastNode) -> str:
    return _LABEL_ICON.get(node.impact_label, "⚪")


def _node_label(node: BlastNode) -> str:
    parts = [node.address]
    if node.failed_controls:
        parts.append(f"  FAIL: {', '.join(node.failed_controls)}")
    return "  ".join(parts)


# ── Rich terminal renderer ────────────────────────────────────────────────────

def print_blast_radius(result: BlastResult, console: Console | None = None) -> None:
    """Print a colour-coded blast radius tree to the terminal."""
    if console is None:
        console = Console()

    if not result.roots:
        console.print("\n[dim]No failing resources — blast radius analysis skipped.[/dim]")
        return

    # Header
    affected_count = len(result.affected)
    summary = (
        f"[bold]{len(result.roots)}[/bold] failing resource(s) directly affect "
        f"[bold]{affected_count}[/bold] downstream resource(s)."
        if affected_count
        else f"[bold]{len(result.roots)}[/bold] failing resource(s) — no downstream dependents found."
    )
    console.print()
    console.print(Panel(
        summary,
        title="[bold white]Blast Radius Analysis[/bold white]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()

    # Build a lookup of all nodes
    all_nodes: dict[str, BlastNode] = {n.address: n for n in result.roots + result.affected}

    # Build children map from edges
    children: dict[str, list[str]] = {n.address: [] for n in result.roots + result.affected}
    for src, dst in result.edges:
        if src in children:
            children[src].append(dst)

    # Render each root as a tree
    for root in sorted(result.roots, key=lambda n: (-(_SEVERITY_RANK(n)), n.address)):
        icon = _node_icon(root)
        style = _node_style(root)
        label = Text()
        label.append(f"{icon} {root.address}", style=style)
        if root.failed_controls:
            label.append(f"  [{', '.join(root.failed_controls)}]", style="dim")
        label.append(f"  {root.impact_label}", style=style)

        tree = Tree(label)
        _add_children(tree, root.address, children, all_nodes, visited=set())
        console.print(tree)
        console.print()

    # Legend
    console.print(
        "  [bold red]🔴 CRITICAL[/bold red]  "
        "[bold yellow]🟠 HIGH[/bold yellow]  "
        "[yellow]🟡 MEDIUM[/yellow]  "
        "[dim]⚪ LOW[/dim]"
        "  — blast radius criticality based on hop distance from root cause"
    )
    console.print()


def _SEVERITY_RANK(node: BlastNode) -> int:  # noqa: N802
    ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return ranks.get(node.impact_label, 0)


def _add_children(
    tree: Tree,
    address: str,
    children: dict[str, list[str]],
    all_nodes: dict[str, BlastNode],
    visited: set[str],
) -> None:
    if address in visited:
        return
    visited = visited | {address}
    for child_addr in sorted(children.get(address, [])):
        node = all_nodes.get(child_addr)
        if node is None:
            continue
        icon = _node_icon(node)
        style = _node_style(node)
        label = Text()
        label.append(f"{icon} {node.address}", style=style)
        if node.failed_controls:
            label.append(f"  [{', '.join(node.failed_controls)}]", style="dim")
        label.append(f"  {node.impact_label}", style="dim")
        branch = tree.add(label)
        _add_children(branch, child_addr, children, all_nodes, visited)


# ── Mermaid diagram renderer ──────────────────────────────────────────────────

def _mermaid_node_id(address: str) -> str:
    """Convert a resource address to a valid Mermaid node ID."""
    return address.replace(".", "__").replace("-", "_")


def _mermaid_node_label(node: BlastNode) -> str:
    lines = [node.address]
    if node.failed_controls:
        lines.append("FAIL: " + " · ".join(node.failed_controls))
    lines.append(node.impact_label)
    return "\\n".join(lines)


def write_mermaid(result: BlastResult, output_path: Path) -> None:
    """Write a Mermaid ``graph LR`` diagram to *output_path*.

    The resulting ``.md`` file renders natively in GitHub, GitLab, Notion,
    and any Mermaid-aware viewer.
    """
    if not result.roots:
        return

    all_nodes: dict[str, BlastNode] = {n.address: n for n in result.roots + result.affected}
    lines: list[str] = []

    lines.append("# WAF++ PASS — Blast Radius Analysis")
    lines.append("")
    lines.append(
        f"> **{len(result.roots)}** failing resource(s) affect "
        f"**{len(result.affected)}** downstream resource(s)."
    )
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph LR")
    lines.append("")

    # Node definitions
    for node in result.roots + result.affected:
        nid = _mermaid_node_id(node.address)
        label = _mermaid_node_label(node)
        lines.append(f'    {nid}["{label}"]')

    lines.append("")

    # Edges
    for src, dst in result.edges:
        lines.append(f"    {_mermaid_node_id(src)} --> {_mermaid_node_id(dst)}")

    lines.append("")

    # Styles
    for node in result.roots + result.affected:
        nid = _mermaid_node_id(node.address)
        fill, color = _MERMAID_FILL.get(node.impact_label, ("#95a5a6", "#ffffff"))
        stroke = fill  # keep border same colour as fill for clean look
        lines.append(f"    style {nid} fill:{fill},stroke:{stroke},color:{color}")

    lines.append("```")
    lines.append("")

    # Criticality table
    lines.append("## Resource summary")
    lines.append("")
    lines.append("| Resource | Criticality | Hop | Failed controls |")
    lines.append("|---|---|---|---|")
    for node in sorted(result.roots + result.affected, key=lambda n: (n.hop, n.address)):
        icon = _LABEL_ICON.get(node.impact_label, "⚪")
        ctrl = ", ".join(node.failed_controls) if node.failed_controls else "—"
        lines.append(f"| `{node.address}` | {icon} {node.impact_label} | {node.hop} | {ctrl} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("| Icon | Criticality | Meaning |")
    lines.append("|---|---|---|")
    lines.append("| 🔴 | CRITICAL | Root cause — control failure at critical severity |")
    lines.append("| 🟠 | HIGH | Directly depends on a failing resource (1 hop) or high-severity failure |")
    lines.append("| 🟡 | MEDIUM | Two hops from a failing resource |")
    lines.append("| ⚪ | LOW | Three or more hops from a failing resource |")

    output_path.write_text("\n".join(lines), encoding="utf-8")
