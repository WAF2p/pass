"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import typer

from wafpass import __name_full__, __version__
from wafpass.engine import filter_by_severity, run_controls
from wafpass.iac import registry
from wafpass.iac.base import IaCState
from wafpass.loader import load_controls
from wafpass.models import Report
from wafpass.reporter import print_report, print_summary_only
from wafpass.waivers import DEFAULT_SKIP_FILE, apply_waivers, load_waivers

_DEFAULT_STATE_DIR = Path(".wafpass-state")

app = typer.Typer(
    name="wafpass",
    help="WAF++ PASS – IaC controls checker for the WAF++ framework.",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__name_full__} v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """WAF++ PASS – check IaC files against WAF++ controls."""


@app.command()
def check(
    paths: List[Path] = typer.Argument(
        ...,
        help=(
            "Path(s) to IaC files (directories or individual files). "
            "Pass multiple paths to merge results from different cloud folders, "
            "e.g. wafpass check ./aws ./azure ./gcp"
        ),
    ),
    iac: str = typer.Option(
        "terraform",
        "--iac",
        help=(
            "IaC framework plugin to use for parsing. "
            f"Available: terraform, bicep, cdk, pulumi. "
            "Default: terraform."
        ),
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files.",
    ),
    pillar: str | None = typer.Option(
        None,
        "--pillar",
        help="Filter by pillar name: cost, sovereign, security, reliability, operations, architecture, governance.",
    ),
    control_ids: str | None = typer.Option(
        None,
        "--controls",
        help="Comma-separated list of control IDs to run (e.g. WAF-COST-010,WAF-COST-020).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Minimum severity level to evaluate: low, medium, high, critical.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show all results including PASSes (default: only show FAILs and SKIPs).",
    ),
    fail_on: str = typer.Option(
        "fail",
        "--fail-on",
        help="Exit non-zero condition: 'fail' (default), 'skip', 'any'.",
    ),
    output: str = typer.Option(
        "console",
        "--output",
        help="Output format: console, pdf.",
    ),
    pdf_out: Path = typer.Option(
        None,
        "--pdf-out",
        help="Destination path for the PDF report (default: wafpass-report.pdf). Only used with --output pdf.",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary",
        help="Print only the summary table, not per-control details.",
    ),
    skip_file: Path = typer.Option(
        None,
        "--skip-file",
        help=(
            f"Path to a YAML waiver file listing controls to intentionally skip "
            f"(default: auto-discovered '{DEFAULT_SKIP_FILE}' in the current directory)."
        ),
    ),
    baseline_path: Path = typer.Option(
        None,
        "--baseline",
        help="Path to a JSON baseline from a previous run — enables trend/delta in the PDF report.",
    ),
    save_baseline_path: Path = typer.Option(
        None,
        "--save-baseline",
        help="Save the current run as a JSON baseline file for future trend comparison.",
    ),
    state_dir: Path = typer.Option(
        _DEFAULT_STATE_DIR,
        "--state-dir",
        help=(
            "Directory for versioned run state files "
            f"(default: {_DEFAULT_STATE_DIR}). Each run is saved as a JSON snapshot. "
            "Set to empty string to disable."
        ),
    ),
    no_state: bool = typer.Option(
        False,
        "--no-state",
        help="Disable automatic run state saving and change tracking.",
    ),
    export: str | None = typer.Option(
        None,
        "--export",
        help=(
            "Comma-separated list of export plugin names to push the run snapshot to "
            "(e.g. 'grafana', 'grafana,webhook', 'slack'). "
            "Available: grafana, prometheus, datadog, splunk, slack, webhook."
        ),
    ),
    export_config: Path = typer.Option(
        None,
        "--export-config",
        help=(
            "Path to a YAML export config file (default: auto-discovered "
            "'.wafpass-export.yml' in the current directory). "
            "See README for the expected format."
        ),
    ),
    blast_radius: bool = typer.Option(
        False,
        "--blast-radius",
        help=(
            "After the main report, analyse and visualise how failing resources "
            "affect downstream dependent resources (blast radius). "
            "Also writes a Mermaid diagram to blast_radius.md."
        ),
    ),
    blast_radius_out: Path = typer.Option(
        Path("blast_radius.md"),
        "--blast-radius-out",
        help="Destination for the Mermaid blast radius diagram (default: blast_radius.md).",
    ),
    no_secrets: bool = typer.Option(
        False,
        "--no-secrets",
        help="Disable the hardcoded-secret scanner (enabled by default).",
    ),
) -> None:
    """Check IaC files against WAF++ YAML controls."""

    # ── Resolve plugin ─────────────────────────────────────────────────────────
    plugin = registry.get(iac.lower())
    if plugin is None:
        available = ", ".join(registry.available) or "(none)"
        typer.echo(
            f"ERROR: Unknown IaC plugin '{iac}'. Available: {available}",
            err=True,
        )
        raise typer.Exit(code=2)

    # ── Validate paths ─────────────────────────────────────────────────────────
    for p in paths:
        if not p.exists():
            typer.echo(f"ERROR: Path does not exist: {p}", err=True)
            raise typer.Exit(code=2)

    # ── Secret scanner (runs before controls, prints prominently) ─────────────
    _secret_findings: list = []
    if not no_secrets:
        from wafpass.secret_scanner import scan_secrets, REMEDIATION_GUIDANCE
        from rich.console import Console as _RichConsole
        from rich.panel import Panel as _Panel
        from rich.table import Table as _Table
        from rich.text import Text as _Text

        _secret_findings = [f for f in scan_secrets(list(paths)) if not f.suppressed]
        _suppressed_count = sum(1 for f in scan_secrets(list(paths)) if f.suppressed)

        if _secret_findings:
            _rc = _RichConsole(stderr=True)
            _sev_style = {"critical": "bold red", "high": "red", "medium": "yellow"}

            _tbl = _Table(show_header=True, header_style="bold white on dark_red",
                          show_lines=True, expand=True)
            _tbl.add_column("Severity", style="bold", width=10)
            _tbl.add_column("File : Line", style="cyan", no_wrap=True)
            _tbl.add_column("Finding", style="white")
            _tbl.add_column("Attribute", style="dim")
            _tbl.add_column("Value (masked)", style="dim")

            for _f in _secret_findings:
                _style = _sev_style.get(_f.severity, "white")
                _tbl.add_row(
                    _Text(_f.severity.upper(), style=_style),
                    f"{_f.file}:{_f.line_no}",
                    _f.pattern_name,
                    _f.matched_key or "—",
                    _f.masked_value,
                )

            _rc.print()
            _rc.print(_Panel(
                _tbl,
                title="[bold white on dark_red] ⚠  HARDCODED SECRETS DETECTED [/bold white on dark_red]",
                border_style="red",
                padding=(0, 1),
            ))
            _rc.print()
            _rc.print(f"[bold red]{len(_secret_findings)} hardcoded secret(s) found.[/bold red] "
                      f"These must be remediated before deployment.")
            if _suppressed_count:
                _rc.print(f"[dim]{_suppressed_count} finding(s) suppressed via wafpass:ignore-secret.[/dim]")
            _rc.print()
            _rc.print("[bold]How to fix:[/bold]")
            for _line in REMEDIATION_GUIDANCE.splitlines():
                _rc.print(f"  [dim]{_line}[/dim]" if _line.startswith(" ") else f"  {_line}")
            _rc.print()

    # Parse control ID list
    ids: list[str] | None = None
    if control_ids:
        ids = [i.strip() for i in control_ids.split(",") if i.strip()]

    # ── Load controls ──────────────────────────────────────────────────────────
    try:
        controls = load_controls(controls_dir, pillar=pillar, ids=ids)
    except Exception as exc:
        typer.echo(f"ERROR loading controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if not controls:
        _hint = (f" (pillar={pillar})" if pillar else "") + (f" (ids={ids})" if ids else "")
        typer.echo(f"No controls found in '{controls_dir}'{_hint}", err=True)
        typer.echo("", err=True)
        typer.echo("Controls are not bundled with WAF++ PASS — they must be obtained separately.", err=True)
        typer.echo("", err=True)
        typer.echo("Option A — Download from the WAF++ website:", err=True)
        typer.echo("  1. Visit https://waf2p.dev/wafpass/ and click \"Download Controls\"", err=True)
        typer.echo("  2. Unzip the archive and copy the *.yml files into your controls directory:", err=True)
        typer.echo(f"       cp /path/to/download/*.yml {controls_dir}/", err=True)
        typer.echo("", err=True)
        typer.echo("Option B — Clone the WAF++ framework repository:", err=True)
        typer.echo("  git clone https://github.com/WAF2p/framework.git", err=True)
        typer.echo(f"  cp framework/modules/controls/controls/*.yml {controls_dir}/", err=True)
        typer.echo("", err=True)
        typer.echo("Then re-run your wafpass command.", err=True)
        raise typer.Exit(code=2)

    # ── Parse IaC files (merge across all paths) ───────────────────────────────
    merged_state = IaCState()
    all_regions: list[tuple[str, str]] = []

    for p in paths:
        if len(paths) > 1:
            typer.echo(f"Scanning [{iac}]: {p}")
        try:
            state = plugin.parse(p)
        except Exception as exc:
            typer.echo(f"ERROR parsing {iac} files in {p}: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        merged_state.resources.extend(state.resources)
        merged_state.providers.extend(state.providers)
        merged_state.variables.extend(state.variables)
        merged_state.modules.extend(state.modules)
        merged_state.config_blocks.extend(state.config_blocks)
        all_regions.extend(plugin.extract_regions(state))

    # Deduplicate regions while preserving order
    seen_region_keys: set[tuple[str, str]] = set()
    unique_regions: list[tuple[str, str]] = []
    for r in all_regions:
        key = (r[0].lower(), r[1])
        if key not in seen_region_keys:
            seen_region_keys.add(key)
            unique_regions.append(r)

    # ── Run controls ───────────────────────────────────────────────────────────
    try:
        results = run_controls(controls, merged_state, engine_name=iac.lower())
    except Exception as exc:
        typer.echo(f"ERROR running controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # ── Apply severity filter ──────────────────────────────────────────────────
    if severity:
        results = filter_by_severity(results, severity)

    # ── Apply waivers ──────────────────────────────────────────────────────────
    def _find_skip_file() -> Path | None:
        candidates = [Path(DEFAULT_SKIP_FILE)]
        for p in paths:
            d = p if p.is_dir() else p.parent
            candidate = d / DEFAULT_SKIP_FILE
            if candidate not in candidates:
                candidates.append(candidate)
        for c in candidates:
            if c.exists():
                return c
        return None

    resolved_skip_file = skip_file or _find_skip_file()
    if resolved_skip_file:
        try:
            waivers = load_waivers(resolved_skip_file)
        except ValueError as exc:
            typer.echo(f"ERROR in waiver file: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        if waivers:
            expired = apply_waivers(results, waivers)
            waived_ids = [w.id for w in waivers]
            typer.echo(
                f"Waivers applied: {len(waived_ids)} control(s) marked as WAIVED "
                f"({', '.join(waived_ids)})"
            )
            for w in expired:
                typer.echo(
                    f"WARNING: Waiver for {w.id} expired on {w.expires} — "
                    "please review and renew or remove it.",
                    err=True,
                )

    # ── Build report ───────────────────────────────────────────────────────────
    str_paths = [str(p) for p in paths]
    path_display = " | ".join(str_paths)
    report = Report(
        path=path_display,
        controls_loaded=len(controls),
        controls_run=len(results),
        results=results,
        detected_regions=unique_regions,
        source_paths=str_paths,
    )

    # ── Run state: load previous, compute diff, save current ───────────────────
    run_diff: dict | None = None
    snapshot: dict | None = None
    _state_enabled = not no_state and state_dir and str(state_dir) not in ("", "none")

    if _state_enabled:
        from wafpass.state import (
            build_run_snapshot,
            compute_diff,
            generate_run_id,
            load_latest_run,
            save_run,
        )

        run_id = generate_run_id()
        snapshot = build_run_snapshot(report, run_id=run_id, iac_plugin=iac.lower())

        previous_run = load_latest_run(state_dir)
        if previous_run is not None:
            run_diff = compute_diff(previous_run, snapshot)
            # Embed provenance of previous run into the snapshot for traceability
            snapshot["diff_from_previous"] = run_diff

        try:
            saved_to = save_run(snapshot, state_dir)
            typer.echo(f"Run state saved: {saved_to}  (run-id: {run_id})")
        except Exception as exc:
            typer.echo(f"WARNING: Could not save run state to '{state_dir}': {exc}", err=True)

    # ── Blast radius computation (needed by both console and PDF output) ────────
    _br_result = None
    if blast_radius:
        from wafpass.blast_radius import build_dependency_graph, compute_blast_radius
        graph = build_dependency_graph(merged_state)
        _br_result = compute_blast_radius(report, merged_state, graph)

    # ── Carbon footprint (always computed for PDF; skipped for console-only) ──
    _carbon_result = None
    if output == "pdf":
        try:
            from wafpass.carbon import compute_carbon
            _carbon_result = compute_carbon(merged_state, report, unique_regions)
        except Exception as exc:
            typer.echo(f"WARNING: Could not compute carbon footprint: {exc}", err=True)

    # ── Output ─────────────────────────────────────────────────────────────────
    if output == "console":
        if summary_only:
            print_summary_only(report)
        else:
            print_report(report, verbose=verbose, diff=run_diff)
    elif output == "pdf":
        try:
            from wafpass.pdf_reporter import generate_pdf
        except ImportError:
            typer.echo(
                "ERROR: PDF output requires 'reportlab'. Install with: pip install reportlab",
                err=True,
            )
            raise typer.Exit(code=2)
        from wafpass.baseline import build_baseline, load_baseline, save_baseline as save_baseline_file

        dest = pdf_out or Path("wafpass-report.pdf")

        baseline_data: dict | None = None
        if baseline_path:
            try:
                baseline_data = load_baseline(baseline_path)
            except Exception as exc:
                typer.echo(f"WARNING: Could not load baseline '{baseline_path}': {exc}", err=True)

        generate_pdf(report, dest, baseline=baseline_data, diff=run_diff,
                     blast_radius_result=_br_result,
                     secret_findings=_secret_findings or None,
                     carbon_result=_carbon_result)
        typer.echo(f"PDF report written to: {dest}")

        if save_baseline_path:
            snap = build_baseline(report)
            save_baseline_file(snap, save_baseline_path)
            typer.echo(f"Baseline saved to: {save_baseline_path}")
        # Also print summary to console so CI pipelines see the result
        print_summary_only(report)
    else:
        typer.echo(f"Output format '{output}' is not yet supported.", err=True)
        raise typer.Exit(code=2)

    # ── Export to monitoring systems ───────────────────────────────────────────
    if export and _state_enabled and snapshot is not None:
        import wafpass.export.plugins  # noqa: F401 — triggers self-registration
        from wafpass.export.registry import registry as export_registry
        from wafpass.export.config import load_export_config, DEFAULT_EXPORT_CONFIG

        # Load export config file
        _export_cfg_path = export_config or DEFAULT_EXPORT_CONFIG
        _export_configs: dict[str, dict] = {}
        if _export_cfg_path.exists():
            try:
                _export_configs = load_export_config(_export_cfg_path)
            except Exception as exc:
                typer.echo(f"WARNING: Could not load export config '{_export_cfg_path}': {exc}", err=True)
        elif export_config is not None:
            typer.echo(f"ERROR: Export config file not found: {export_config}", err=True)
            raise typer.Exit(code=2)

        for plugin_name in [n.strip() for n in export.split(",") if n.strip()]:
            exp_plugin = export_registry.get(plugin_name)
            if exp_plugin is None:
                available_exp = ", ".join(export_registry.available) or "(none)"
                typer.echo(
                    f"WARNING: Unknown export plugin '{plugin_name}'. "
                    f"Available: {available_exp}",
                    err=True,
                )
                continue
            plugin_cfg = _export_configs.get(plugin_name, {})
            typer.echo(f"Exporting to [{plugin_name}]...")
            result = exp_plugin.export(snapshot, plugin_cfg)
            if result.success:
                typer.echo(f"  ✓ {plugin_name}: {result.message}")
            else:
                typer.echo(f"  ✗ {plugin_name}: {result.message}", err=True)
    elif export and not _state_enabled:
        typer.echo(
            "WARNING: --export requires run state tracking. "
            "Remove --no-state or set --state-dir to enable export.",
            err=True,
        )

    # ── Blast radius analysis — terminal + Mermaid output ─────────────────────
    if blast_radius and _br_result is not None:
        from wafpass.blast_renderer import print_blast_radius, write_mermaid
        from rich.console import Console

        print_blast_radius(_br_result, console=Console())
        try:
            write_mermaid(_br_result, blast_radius_out)
            typer.echo(f"Blast radius diagram written to: {blast_radius_out}")
        except Exception as exc:
            typer.echo(f"WARNING: Could not write blast radius diagram: {exc}", err=True)

    # ── Exit code ──────────────────────────────────────────────────────────────
    fail_on_lower = fail_on.lower()
    if fail_on_lower == "fail" and report.total_fail > 0:
        raise typer.Exit(code=1)
    elif fail_on_lower == "skip" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
    elif fail_on_lower == "any" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
