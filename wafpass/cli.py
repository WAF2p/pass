"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
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

# ── UI server helpers ──────────────────────────────────────────────────────────

_UI_PID_FILE = Path.home() / ".wafpass" / "ui.pid"
_UI_LOG_FILE = Path.home() / ".wafpass" / "ui.log"

# The serve package lives next to wafpass/ inside the same project root.
_SERVE_ROOT = Path(__file__).parent.parent  # …/pass/


def _pid_file_read() -> int | None:
    """Return the PID from the pid-file, or None if absent / stale."""
    if not _UI_PID_FILE.exists():
        return None
    try:
        pid = int(_UI_PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return None
    # Verify the process still exists
    try:
        os.kill(pid, 0)
        return pid
    except (ProcessLookupError, PermissionError):
        return None


def _pid_file_write(pid: int) -> None:
    _UI_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _UI_PID_FILE.write_text(str(pid))


def _pid_file_remove() -> None:
    try:
        _UI_PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass

app = typer.Typer(
    name="wafpass",
    help="WAF++ PASS – IaC controls checker for the WAF++ framework.",
    add_completion=False,
)

ui_app = typer.Typer(
    name="ui",
    help="Manage the WAF++ PASS web UI server.",
    add_completion=False,
)
app.add_typer(ui_app, name="ui")

control_app = typer.Typer(
    name="control",
    help="Author, validate, and manage WAF++ PASS controls.",
    add_completion=False,
)
app.add_typer(control_app, name="control")


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
        help="Output format: console, pdf, json.",
    ),
    push: str | None = typer.Option(
        None,
        "--push",
        help=(
            "POST the result to this URL (e.g. http://localhost:8000/runs). "
            "Pass [bold]@[/bold] to push to the server from 'wafpass login' using your stored token. "
            "Requires --output json."
        ),
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_API_KEY",
        help=(
            "API key sent as 'X-Api-Key' header when using --push. "
            "Not needed after 'wafpass login' — Bearer token is used automatically. "
            "Can also be set via the WAFPASS_API_KEY environment variable."
        ),
    ),
    project: str = typer.Option(
        "",
        "--project",
        help="Project / repo name to embed in the result (used by wafpass-server).",
    ),
    branch: str = typer.Option(
        "",
        "--branch",
        help="VCS branch name (auto-detected from git if not set).",
    ),
    git_sha: str = typer.Option(
        "",
        "--git-sha",
        help="Commit SHA (auto-detected from git if not set).",
    ),
    triggered_by: str = typer.Option(
        "",
        "--triggered-by",
        help="Trigger source: local, github-actions, gitlab-ci, … (auto-detected if not set).",
    ),
    stage: str = typer.Option(
        "",
        "--stage",
        help="Deployment stage this run targets, e.g. dev, staging, prod.",
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
    plan_file: Path = typer.Option(
        None,
        "--plan-file",
        help=(
            "Path to a JSON file produced by 'terraform show -json <plan>' or "
            "'terraform plan -json'. When provided the parsed resource-change "
            "summary is embedded in the JSON output and pushed to the dashboard "
            "as 'plan_changes', enabling Change Overview analysis."
        ),
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
        # Discover both the canonical risk_acceptance.yml and legacy .wafpass-skip.yml
        _names = ["risk_acceptance.yml", DEFAULT_SKIP_FILE]
        candidates: list[Path] = []
        for name in _names:
            candidates.append(Path(name))
            for p in paths:
                d = p if p.is_dir() else p.parent
                candidate = d / name
                if candidate not in candidates:
                    candidates.append(candidate)
        for c in candidates:
            if c.exists():
                return c
        return None

    _active_waivers: list = []
    resolved_skip_file = skip_file or _find_skip_file()
    if resolved_skip_file:
        try:
            waivers = load_waivers(resolved_skip_file)
        except ValueError as exc:
            typer.echo(f"ERROR in waiver file: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        if waivers:
            _active_waivers = waivers
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
        snapshot = build_run_snapshot(report, run_id=run_id, iac_plugin=iac.lower(), stage=stage)

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
                     carbon_result=_carbon_result,
                     waivers=_active_waivers or None)
        typer.echo(f"PDF report written to: {dest}")

        if save_baseline_path:
            snap = build_baseline(report)
            save_baseline_file(snap, save_baseline_path)
            typer.echo(f"Baseline saved to: {save_baseline_path}")
        # Also print summary to console so CI pipelines see the result
        print_summary_only(report)
    elif output == "json":
        import json as _json
        from wafpass.schema import ControlCheckMetaSchema, ControlMetaSchema, FindingSchema, SecretFindingSchema, WafpassResultSchema

        # Auto-detect git metadata when flags are not provided
        def _git(cmd: list[str]) -> str:
            try:
                return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            except Exception:
                return ""

        _branch = branch or _git(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        _sha = git_sha or _git(["git", "rev-parse", "HEAD"])

        _triggered = triggered_by
        if not _triggered:
            if os.environ.get("GITHUB_ACTIONS"):
                _triggered = "github-actions"
            elif os.environ.get("GITLAB_CI"):
                _triggered = "gitlab-ci"
            elif os.environ.get("CI"):
                _triggered = "ci"
            else:
                _triggered = "local"

        # Build findings list
        _findings: list[FindingSchema] = []
        for cr in report.results:
            for chk in cr.results:
                _findings.append(FindingSchema(
                    check_id=chk.check_id,
                    check_title=chk.check_title,
                    control_id=chk.control_id,
                    pillar=cr.control.pillar,
                    severity=chk.severity,
                    status=chk.status,
                    resource=chk.resource,
                    message=chk.message,
                    remediation=chk.remediation,
                    example=chk.example,
                ))
            if cr.status == "WAIVED" and not cr.results:
                _findings.append(FindingSchema(
                    check_id=f"{cr.control.id}-WAIVED",
                    check_title=cr.control.title,
                    control_id=cr.control.id,
                    pillar=cr.control.pillar,
                    severity=cr.control.severity,
                    status="WAIVED",
                    resource="",
                    message=cr.waived_reason or "",
                    remediation="",
                ))

        # Compute scores
        _pillar_totals: dict[str, list[int]] = {}
        for cr in report.results:
            _pillar_totals.setdefault(cr.control.pillar, []).append(
                1 if cr.status == "PASS" else 0
            )
        _pillar_scores = {
            p: int(sum(v) / len(v) * 100) if v else 0
            for p, v in _pillar_totals.items()
        }
        _score = int(sum(_pillar_scores.values()) / len(_pillar_scores)) if _pillar_scores else 0

        # Serialize loaded controls into lightweight metadata
        _controls_meta: list[ControlMetaSchema] = []
        for _ctrl in controls:
            _ctrl_checks = [
                ControlCheckMetaSchema(
                    id=_chk.id,
                    title=_chk.title,
                    severity=_chk.severity,
                    remediation=_chk.remediation,
                    example=_chk.example,
                )
                for _chk in _ctrl.checks
            ]
            _controls_meta.append(ControlMetaSchema(
                id=_ctrl.id,
                title=_ctrl.title,
                pillar=_ctrl.pillar,
                severity=_ctrl.severity,
                category=_ctrl.category,
                description=_ctrl.description,
                rationale=_ctrl.rationale,
                threat=_ctrl.threat,
                regulatory_mapping=_ctrl.regulatory_mapping,
                checks=_ctrl_checks,
            ))

        # ── Parse terraform plan file if provided ─────────────────────────────
        _plan_changes: dict | None = None
        if plan_file:
            if not plan_file.exists():
                typer.echo(f"ERROR: --plan-file path does not exist: {plan_file}", err=True)
                raise typer.Exit(code=2)
            try:
                from wafpass.plan_parser import parse_plan_file as _parse_plan
                _plan_changes = _parse_plan(plan_file)
                _total_changes = sum(
                    v for k, v in _plan_changes.get("summary", {}).items() if k != "no_op"
                )
                typer.echo(
                    f"Plan file parsed: {_total_changes} resource change(s) detected "
                    f"({plan_file})",
                    err=True,
                )
            except Exception as exc:
                typer.echo(f"WARNING: Could not parse --plan-file '{plan_file}': {exc}", err=True)

        _secret_schema_findings = [
            SecretFindingSchema(
                file=str(_sf.file),
                line_no=_sf.line_no,
                pattern_name=_sf.pattern_name,
                severity=_sf.severity,
                matched_key=_sf.matched_key,
                masked_value=_sf.masked_value,
            )
            for _sf in (_secret_findings or [])
        ]

        _result = WafpassResultSchema(
            project=project,
            branch=_branch,
            git_sha=_sha,
            triggered_by=_triggered,
            iac_framework=iac.lower(),
            stage=stage,
            score=_score,
            pillar_scores=_pillar_scores,
            path=report.path,
            controls_loaded=report.controls_loaded,
            controls_run=report.controls_run,
            detected_regions=[list(r) for r in report.detected_regions],
            source_paths=report.source_paths,
            controls_meta=_controls_meta,
            findings=_findings,
            secret_findings=_secret_schema_findings,
            plan_changes=_plan_changes,
        )

        _json_str = _result.model_dump_json(indent=2)
        typer.echo(_json_str)

        if push:
            try:
                import httpx as _httpx
                from wafpass.auth import resolve_push_target, get_valid_credentials

                _push_url, _auto_headers = resolve_push_target(push)

                if push == "@" and _push_url is None:
                    typer.echo(
                        "ERROR: --push @ requires an active login session. "
                        "Run 'wafpass login <server-url>' first.",
                        err=True,
                    )
                    raise typer.Exit(code=1)

                _push_headers: dict[str, str] = {
                    "Content-Type": "application/json",
                    **_auto_headers,
                }
                # Explicit --api-key always wins over the stored Bearer token
                if api_key:
                    _push_headers.pop("Authorization", None)
                    _push_headers["X-Api-Key"] = api_key

                _resp = _httpx.post(
                    _push_url,
                    content=_json_str,
                    headers=_push_headers,
                    timeout=30,
                )
                if _resp.status_code == 401:
                    # Token may have just expired — try one refresh and retry
                    _creds = get_valid_credentials()
                    if _creds and not api_key:
                        _push_headers["Authorization"] = _creds.bearer()
                        _resp = _httpx.post(_push_url, content=_json_str, headers=_push_headers, timeout=30)
                _resp.raise_for_status()
                typer.echo(f"Pushed to {_push_url}  →  HTTP {_resp.status_code}", err=True)
            except SystemExit:
                raise
            except Exception as exc:
                typer.echo(f"ERROR: Push to '{push}' failed: {exc}", err=True)
                raise typer.Exit(code=2)

    else:
        typer.echo(f"Output format '{output}' is not yet supported.", err=True)
        raise typer.Exit(code=2)

    # ── Push for non-JSON output modes (--push without --output json) ──────────
    if push and output != "json":
        _push_hint = push if push != "@" else "@ (stored server)"
        typer.echo(
            f"NOTE: --push only works with --output json. "
            f"Re-run with --output json --push {_push_hint}.",
            err=True,
        )

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


# ── Shared pipeline helper ──────────────────────────────────────────────────────

def _run_check_pipeline(
    paths: list[Path],
    plugin,
    controls,
    iac: str,
    severity: str | None,
    skip_file: Path | None,
) -> tuple[list, "IaCState", list]:
    """Run parse → controls → filter → waivers. Returns (results, merged_state, waivers)."""
    merged_state = IaCState()
    all_regions: list[tuple[str, str]] = []

    for p in paths:
        try:
            state = plugin.parse(p)
        except Exception as exc:
            typer.echo(f"ERROR parsing IaC files in {p}: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        merged_state.resources.extend(state.resources)
        merged_state.providers.extend(state.providers)
        merged_state.variables.extend(state.variables)
        merged_state.modules.extend(state.modules)
        merged_state.config_blocks.extend(state.config_blocks)
        all_regions.extend(plugin.extract_regions(state))

    try:
        results = run_controls(controls, merged_state, engine_name=iac.lower())
    except Exception as exc:
        typer.echo(f"ERROR running controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if severity:
        results = filter_by_severity(results, severity)

    active_waivers: list = []
    if skip_file and skip_file.exists():
        try:
            active_waivers = load_waivers(skip_file)
        except ValueError as exc:
            typer.echo(f"ERROR in waiver file: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        if active_waivers:
            apply_waivers(results, active_waivers)

    return results, merged_state, active_waivers


@app.command()
def fix(
    paths: List[Path] = typer.Argument(
        ...,
        help=(
            "Path(s) to IaC files or directories to scan and fix. "
            "The same paths are passed to both the check and the patch step."
        ),
    ),
    iac: str = typer.Option(
        "terraform",
        "--iac",
        help="IaC framework plugin (terraform, bicep, cdk, pulumi). Default: terraform.",
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files.",
    ),
    pillar: str | None = typer.Option(
        None,
        "--pillar",
        help="Limit fixes to a single pillar (cost, security, reliability, …).",
    ),
    control_ids: str | None = typer.Option(
        None,
        "--controls",
        help="Comma-separated control IDs to fix (e.g. WAF-SEC-010,WAF-COST-020).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Minimum severity level to fix: low, medium, high, critical.",
    ),
    skip_file: Path | None = typer.Option(
        None,
        "--skip-file",
        help="Path to waiver/skip YAML — waived controls are never auto-fixed.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        is_flag=True,
        help="Write the patches to disk.  Without this flag the command is a dry-run.",
    ),
    backup: bool = typer.Option(
        True,
        "--backup/--no-backup",
        help="Create <file>.tf.bak before modifying (default: true, only with --apply).",
    ),
) -> None:
    """Auto-fix failing WAF++ checks by patching IaC source files.

    By default this command runs in **dry-run / preview mode** and only prints
    a coloured diff of what would change.  Pass ``--apply`` to actually write
    the patches to disk.

    Only assertions whose desired value can be derived unambiguously from the
    control definition are patched:

    \b
      is_true / is_false → attribute = true / false
      equals             → attribute = <expected>
      ≥ / ≤ numeric      → attribute = <threshold>
      in                 → attribute = <first allowed value>
      key_exists (tags)  → inserts "key" = "TODO-fill-in" into tags block

    Assertions using Terraform expressions (var., local., ${…}) are left
    untouched.  Structural changes (missing resource blocks, runtime operators)
    are reported as manual-fix items.

    After ``--apply`` the checks are re-run and an improvement delta is printed.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    rc = Console()

    # ── Resolve plugin ────────────────────────────────────────────────────────
    plugin = registry.get(iac.lower())
    if plugin is None:
        typer.echo(f"ERROR: Unknown IaC plugin '{iac}'.", err=True)
        raise typer.Exit(code=2)

    for p in paths:
        if not p.exists():
            typer.echo(f"ERROR: Path does not exist: {p}", err=True)
            raise typer.Exit(code=2)

    # ── Parse control IDs filter ──────────────────────────────────────────────
    ids: list[str] | None = None
    if control_ids:
        ids = [i.strip() for i in control_ids.split(",") if i.strip()]

    # ── Load controls ─────────────────────────────────────────────────────────
    try:
        controls = load_controls(controls_dir, pillar=pillar, ids=ids)
    except Exception as exc:
        typer.echo(f"ERROR loading controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if not controls:
        typer.echo(f"No controls found in '{controls_dir}'.", err=True)
        raise typer.Exit(code=2)

    # ── Resolve waiver file ───────────────────────────────────────────────────
    resolved_skip_file: Path | None = skip_file
    if resolved_skip_file is None:
        for name in ["risk_acceptance.yml", DEFAULT_SKIP_FILE]:
            for p in [Path(name)] + [p / name for p in paths if p.is_dir()]:
                if p.exists():
                    resolved_skip_file = p
                    break
            if resolved_skip_file:
                break

    # ── Run initial check pipeline ────────────────────────────────────────────
    rc.print()
    rc.print(Rule("[bold cyan]WAF++ PASS — Auto-Fix[/bold cyan]", style="cyan"))
    rc.print()

    results, merged_state, _ = _run_check_pipeline(
        paths=paths,
        plugin=plugin,
        controls=controls,
        iac=iac,
        severity=severity,
        skip_file=resolved_skip_file,
    )

    total_fail = sum(1 for cr in results for r in cr.results if r.status == "FAIL")
    if total_fail == 0:
        rc.print("[bold green]✓  Nothing to fix — all checks pass.[/bold green]")
        raise typer.Exit(code=0)

    rc.print(f"[bold]{total_fail}[/bold] failing check(s) found. Deriving patches…")
    rc.print()

    # ── Build locator and fix plan ────────────────────────────────────────────
    from wafpass.fixer import (
        FixPlan,
        PatchKind,
        ResourceLocator,
        apply_fix_plan,
        build_fix_plan,
        compute_fix_delta,
        render_diff,
    )

    locator = ResourceLocator(list(paths)).build()
    plan = build_fix_plan(
        control_results=results,
        merged_state=merged_state,
        controls=controls,
        locator=locator,
    )

    # ── Compute diffs (always, for preview) ───────────────────────────────────
    diff_map = apply_fix_plan(plan, locator, dry_run=True, backup=False)

    # ── Print per-file diff panels ────────────────────────────────────────────
    if diff_map:
        for file_path, (original, patched) in sorted(diff_map.items()):
            file_patches = [p for p in plan.active_patches if p.file_path == file_path]
            diff_lines = render_diff(original, patched, file_path)

            diff_text = Text()
            for dl in diff_lines:
                line = dl.rstrip("\n")
                if line.startswith("+++") or line.startswith("---"):
                    diff_text.append(line + "\n", style="dim")
                elif line.startswith("+"):
                    diff_text.append(line + "\n", style="bold green")
                elif line.startswith("-"):
                    diff_text.append(line + "\n", style="bold red")
                elif line.startswith("@@"):
                    diff_text.append(line + "\n", style="cyan")
                else:
                    diff_text.append(line + "\n", style="dim white")

            patch_label = f"{len(file_patches)} fix(es)"
            rc.print(Panel(
                diff_text,
                title=f"[bold cyan]{file_path}[/bold cyan]  [dim]{patch_label}[/dim]",
                border_style="cyan",
                padding=(0, 1),
            ))
    else:
        rc.print("[dim]No file changes could be derived from the failing checks.[/dim]")

    # ── Patch summary ─────────────────────────────────────────────────────────
    rc.print(Rule("[bold]Fix Plan Summary[/bold]", style="dim"))
    rc.print()

    active_count = len(plan.active_patches)
    dedup_count  = len([p for p in plan.patches if p.already_applied])
    skipped_count = len(plan.skipped)
    files_count  = len(plan.files_affected)

    summary_tbl = Table(show_header=False, box=None, padding=(0, 2))
    summary_tbl.add_column("key",   style="dim",       no_wrap=True)
    summary_tbl.add_column("value", style="bold white", no_wrap=True)
    summary_tbl.add_column("note",  style="dim",       no_wrap=True)

    summary_tbl.add_row(
        "Patches to apply:",
        str(active_count),
        f"across {files_count} file(s)"  if files_count else "no files affected",
    )
    summary_tbl.add_row(
        "Deduplicated:",
        str(dedup_count),
        "same attribute targeted by multiple controls",
    )
    summary_tbl.add_row(
        "Manual remediation:",
        str(skipped_count),
        "see table below",
    )
    rc.print(summary_tbl)
    rc.print()

    if plan.patches:
        # Detail table of what will be patched
        detail_tbl = Table(
            show_header=True,
            header_style="bold white on dark_blue",
            show_lines=True,
            expand=True,
        )
        detail_tbl.add_column("Resource",  style="cyan",  no_wrap=True)
        detail_tbl.add_column("Attribute", style="white", no_wrap=True)
        detail_tbl.add_column("New value", style="green", no_wrap=True)
        detail_tbl.add_column("Control",   style="dim",   no_wrap=True)
        detail_tbl.add_column("File",      style="dim",   no_wrap=True)

        for p in plan.active_patches:
            label = p.tag_key if p.patch_kind == PatchKind.ADD_TAG_KEY else p.attribute_path
            val   = f'tag "{p.tag_key}" = "TODO-fill-in"' if p.patch_kind == PatchKind.ADD_TAG_KEY else p.hcl_value
            detail_tbl.add_row(
                p.address,
                label,
                val,
                p.control_id,
                p.file_path.name,
            )

        rc.print(detail_tbl)
        rc.print()

    # ── Manual-fix items ──────────────────────────────────────────────────────
    if plan.skipped:
        skip_tbl = Table(
            show_header=True,
            header_style="bold white on dark_orange3",
            show_lines=True,
            expand=True,
            title="[bold yellow]Manual Remediation Required[/bold yellow]",
        )
        skip_tbl.add_column("Check",     style="dim",    no_wrap=True)
        skip_tbl.add_column("Resource",  style="yellow", no_wrap=True)
        skip_tbl.add_column("Attribute", style="white",  no_wrap=True)
        skip_tbl.add_column("Operator",  style="dim",    no_wrap=True)
        skip_tbl.add_column("Reason",    style="dim")

        for s in plan.skipped:
            skip_tbl.add_row(s.check_id, s.address, s.attribute, s.op, s.reason)

        rc.print(skip_tbl)
        rc.print()

    if plan.patches and any(p.patch_kind == PatchKind.ADD_TAG_KEY for p in plan.active_patches):
        rc.print(
            "[bold yellow]⚠  Tag patches use TODO-fill-in as placeholder.[/bold yellow]"
            "  Replace with real values before deploying."
        )
        rc.print()

    # ── Apply ─────────────────────────────────────────────────────────────────
    if not apply:
        rc.print(
            "[dim]Dry-run complete. Pass [bold]--apply[/bold] to write the patches to disk.[/dim]"
        )
        raise typer.Exit(code=0)

    if not diff_map:
        rc.print("[dim]Nothing to write.[/dim]")
        raise typer.Exit(code=0)

    apply_fix_plan(plan, locator, dry_run=False, backup=backup)

    files_written = list(diff_map.keys())
    rc.print(Rule("[bold green]Patches Applied[/bold green]", style="green"))
    rc.print()
    for f in sorted(files_written):
        bak_note = f"  [dim](backup: {f.name}.bak)[/dim]" if backup else ""
        rc.print(f"  [green]✓[/green]  {f}{bak_note}")
    rc.print()
    rc.print(
        f"[bold green]Applied {active_count} patch(es) to {len(files_written)} file(s).[/bold green]"
    )
    rc.print()

    # ── Re-run and show improvement delta ────────────────────────────────────
    rc.print(Rule("[bold cyan]Re-checking after fix…[/bold cyan]", style="cyan"))
    rc.print()

    new_results, _, _ = _run_check_pipeline(
        paths=paths,
        plugin=plugin,
        controls=controls,
        iac=iac,
        severity=severity,
        skip_file=resolved_skip_file,
    )

    delta = compute_fix_delta(results, new_results)

    if delta.resolved:
        rc.print(f"[bold green]Resolved ({len(delta.resolved)}):[/bold green]")
        for check_id, addr in delta.resolved:
            rc.print(f"  [green]✓[/green]  {check_id}  [dim]{addr}[/dim]  [dim]FAIL → PASS[/dim]")
        rc.print()

    if delta.still_failing:
        rc.print(f"[bold yellow]Still failing ({len(delta.still_failing)}) — manual remediation required:[/bold yellow]")
        for check_id, addr in delta.still_failing:
            rc.print(f"  [yellow]─[/yellow]  {check_id}  [dim]{addr}[/dim]")
        rc.print()

    if delta.regressions:
        rc.print(f"[bold red]⚠  Regressions introduced ({len(delta.regressions)}) — please review:[/bold red]")
        for check_id, addr in delta.regressions:
            rc.print(f"  [red]✗[/red]  {check_id}  [dim]{addr}[/dim]  [dim]PASS → FAIL[/dim]")
        rc.print()

    total_orig = len(delta.resolved) + len(delta.still_failing)
    rc.print(
        f"[bold]Fixed {len(delta.resolved)}/{total_orig} failing check(s).[/bold]"
    )

    exit_code = 1 if delta.still_failing or delta.regressions else 0
    raise typer.Exit(code=exit_code)


# ── wafpass ui ─────────────────────────────────────────────────────────────────


@ui_app.command("start")
def ui_start(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host address to bind the server to.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="TCP port to listen on (default: 8080).",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        is_flag=True,
        help="Do not open the browser automatically after starting.",
    ),
    reload: bool = typer.Option(
        False,
        "--reload",
        is_flag=True,
        help="Enable uvicorn auto-reload (for development).",
    ),
) -> None:
    """Start the WAF++ PASS web UI server in the background."""
    from rich.console import Console

    rc = Console()

    existing_pid = _pid_file_read()
    if existing_pid is not None:
        rc.print(
            f"[yellow]Server is already running[/yellow] (PID {existing_pid})  "
            f"[dim]http://{host}:{port}[/dim]"
        )
        rc.print("Run [bold]wafpass ui stop[/bold] first to restart.")
        raise typer.Exit(code=1)

    cmd = [
        sys.executable, "-m", "uvicorn",
        "serve.app:app",
        "--host", host,
        "--port", str(port),
    ]
    if reload:
        cmd.append("--reload")

    _UI_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_fh = _UI_LOG_FILE.open("w")

    proc = subprocess.Popen(
        cmd,
        cwd=str(_SERVE_ROOT),
        stdout=log_fh,
        stderr=log_fh,
        start_new_session=True,   # detach from the terminal's process group
    )

    _pid_file_write(proc.pid)

    # Brief pause so uvicorn can fail fast on port-in-use errors
    time.sleep(1.2)

    if _pid_file_read() is None:
        rc.print("[red]✗  Server failed to start.[/red]")
        rc.print(f"[dim]Check the log: {_UI_LOG_FILE}[/dim]")
        raise typer.Exit(code=1)

    url = f"http://{host}:{port}"
    rc.print(f"[green]✓  WAF++ PASS UI started[/green]  PID [bold]{proc.pid}[/bold]")
    rc.print(f"   [bold cyan]{url}[/bold cyan]")
    rc.print(f"   [dim]Log: {_UI_LOG_FILE}[/dim]")
    rc.print("   Run [bold]wafpass ui stop[/bold] to shut it down.")

    if not no_browser:
        import webbrowser
        time.sleep(0.5)
        webbrowser.open(url)


@ui_app.command("status")
def ui_status(
    host: str = typer.Option("127.0.0.1", "--host", help="Host the server was bound to."),
    port: int = typer.Option(8080, "--port", "-p", help="Port the server is listening on."),
) -> None:
    """Show whether the WAF++ PASS web UI server is running."""
    from rich.console import Console

    rc = Console()
    pid = _pid_file_read()

    if pid is None:
        rc.print("[red]●[/red]  Server is [bold]not running[/bold].")
        if _UI_PID_FILE.exists():
            rc.print(f"[dim]Stale PID file removed: {_UI_PID_FILE}[/dim]")
            _pid_file_remove()
        raise typer.Exit(code=1)

    url = f"http://{host}:{port}"
    rc.print(f"[green]●[/green]  Server is [bold green]running[/bold green]  PID [bold]{pid}[/bold]")
    rc.print(f"   [bold cyan]{url}[/bold cyan]")
    rc.print(f"   [dim]Log: {_UI_LOG_FILE}[/dim]")


@ui_app.command("stop")
def ui_stop() -> None:
    """Stop the WAF++ PASS web UI server."""
    from rich.console import Console

    rc = Console()
    pid = _pid_file_read()

    if pid is None:
        rc.print("[yellow]Server is not running.[/yellow]")
        _pid_file_remove()
        raise typer.Exit(code=0)

    try:
        if sys.platform == "win32":
            os.kill(pid, signal.SIGTERM)
        else:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass

    # Wait up to 5 seconds for graceful shutdown
    for _ in range(50):
        time.sleep(0.1)
        if _pid_file_read() is None:
            break
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break

    _pid_file_remove()
    rc.print(f"[green]✓  Server stopped[/green]  (was PID {pid})")


# ── wafpass control * ──────────────────────────────────────────────────────────


@control_app.command("generate")
def control_generate(
    non_interactive: Path = typer.Option(
        None,
        "--non-interactive",
        "-n",
        help=(
            "Path to a JSON or YAML spec file.  Skips the interactive wizard — "
            "validates the spec, exports files, and optionally pushes to the server."
        ),
        metavar="SPEC_FILE",
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory.  Wizard output goes to <controls-dir>/<pillar>/<id>.yml.",
    ),
    checkov_dir: Path = typer.Option(
        Path("checkov_checks"),
        "--checkov-dir",
        help="Directory for Checkov Python stubs.  Default: ./checkov_checks/",
    ),
    server_url: str = typer.Option(
        "",
        "--server-url",
        help=(
            "wafpass-server base URL for step 7 push "
            "(overrides WAFPASS_SERVER_URL env var)."
        ),
    ),
) -> None:
    """Interactive wizard to author a new WAF++ control (7 steps)."""
    from wafpass.wizard import run_wizard, run_wizard_non_interactive

    effective_url: str | None = server_url or os.environ.get("WAFPASS_SERVER_URL") or None

    if non_interactive:
        result = run_wizard_non_interactive(
            non_interactive,
            controls_dir=controls_dir,
            checkov_dir=checkov_dir,
            server_url=effective_url,
        )
    else:
        result = run_wizard(
            controls_dir=controls_dir,
            checkov_dir=checkov_dir,
            server_url=effective_url,
        )

    if result is None:
        raise typer.Exit(code=1)


@control_app.command("validate")
def control_validate(
    file: Path = typer.Argument(..., help="Path to the YAML control file to validate."),
) -> None:
    """Validate a YAML control file against the WizardControl Pydantic schema."""
    import yaml
    from pydantic import ValidationError
    from rich.console import Console
    from wafpass.control_schema import WizardControl

    rc = Console()

    if not file.exists():
        rc.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(code=2)

    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        rc.print(f"[red]YAML parse error: {exc}[/red]")
        raise typer.Exit(code=1)

    if not isinstance(raw, dict):
        rc.print("[red]File does not contain a YAML mapping.[/red]")
        raise typer.Exit(code=1)

    # Strip header comment keys that might appear if file was hand-edited
    try:
        control = WizardControl.model_validate(raw)
    except ValidationError as exc:
        rc.print(f"[red]Validation failed:[/red] {file}")
        for e in exc.errors():
            loc = " → ".join(str(x) for x in e["loc"])
            rc.print(f"  • [bold]{loc}[/bold]: {e['msg']}")
        raise typer.Exit(code=1)

    rc.print(f"[green]✓ Valid[/green]  {control.id}  ({control.pillar} / {control.severity})")


@control_app.command("list")
def control_list(
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory to scan.",
    ),
    pillar: str = typer.Option(
        "",
        "--pillar",
        help="Filter by pillar name.",
    ),
) -> None:
    """List all controls found under the controls directory."""
    import yaml
    from rich.console import Console
    from rich.table import Table

    rc = Console()

    if not controls_dir.exists():
        rc.print(f"[red]Controls directory not found: {controls_dir}[/red]")
        raise typer.Exit(code=2)

    yml_files = sorted(controls_dir.rglob("*.yml")) + sorted(controls_dir.rglob("*.yaml"))
    if not yml_files:
        rc.print(f"[yellow]No YAML files found in {controls_dir}[/yellow]")
        return

    table = Table(title=f"WAF++ Controls — {controls_dir}", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Pillar", style="magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Description")

    count = 0
    for yml_path in yml_files:
        try:
            raw = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(raw, dict):
            continue

        ctrl_id = str(raw.get("id", yml_path.stem))
        ctrl_pillar = str(raw.get("pillar", ""))
        ctrl_severity = str(raw.get("severity", ""))
        ctrl_desc = str(raw.get("description", "")).strip().split("\n")[0][:80]

        if pillar and ctrl_pillar.lower() != pillar.lower():
            continue

        sev_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
        }.get(ctrl_severity.lower(), "white")
        table.add_row(
            ctrl_id,
            ctrl_pillar,
            f"[{sev_color}]{ctrl_severity}[/{sev_color}]",
            ctrl_desc,
        )
        count += 1

    rc.print(table)
    rc.print(f"[dim]{count} control(s) found[/dim]")


@control_app.command("show")
def control_show(
    control_id: str = typer.Argument(..., help="Control ID to display (e.g. SOV-011)."),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory to search.",
    ),
) -> None:
    """Print a control by ID."""
    import yaml
    from rich.console import Console
    from rich.syntax import Syntax

    rc = Console()

    if not controls_dir.exists():
        rc.print(f"[red]Controls directory not found: {controls_dir}[/red]")
        raise typer.Exit(code=2)

    target_id = control_id.strip().upper()
    for yml_path in sorted(controls_dir.rglob("*.yml")) + sorted(controls_dir.rglob("*.yaml")):
        # Fast check on filename stem before loading
        if yml_path.stem.upper() == target_id:
            rc.print(Syntax(yml_path.read_text(encoding="utf-8"), "yaml", theme="monokai"))
            return
        # Slower: check id field inside file
        try:
            raw = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(raw, dict) and str(raw.get("id", "")).upper() == target_id:
            rc.print(Syntax(yml_path.read_text(encoding="utf-8"), "yaml", theme="monokai"))
            return

    rc.print(f"[red]Control not found:[/red] {control_id}")
    raise typer.Exit(code=1)


# ── wafpass login / logout / whoami ───────────────────────────────────────────


@app.command("login")
def cmd_login(
    server_url: str = typer.Argument(
        ...,
        help="Base URL of the wafpass-server, e.g. https://wafpass.example.com or http://localhost:8000.",
    ),
    username: str = typer.Option(
        None,
        "--username",
        "-u",
        help="Username (prompted if not given).",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Disable TLS certificate verification (insecure — development only).",
    ),
) -> None:
    """Authenticate with a wafpass-server and store a session token.

    Your password is never written to disk — only the issued JWT token is saved
    to ~/.wafpass/credentials.json (chmod 600).

    After login you can push scan results without --api-key:

    \b
        wafpass check ./infra --output json --push @
        wafpass check ./infra --output json --push http://my-server:8000/runs
    """
    from rich.console import Console
    from rich.prompt import Prompt
    import httpx as _httpx
    from wafpass.auth import do_login, _CREDS_FILE

    rc = Console()

    # Normalise URL — strip trailing slash, add scheme if bare hostname given
    _url = server_url.rstrip("/")
    if not _url.startswith(("http://", "https://")):
        _url = f"https://{_url}"

    # Quick reachability check
    try:
        _health_resp = _httpx.get(
            f"{_url}/health",
            timeout=8,
            verify=not no_verify,
            follow_redirects=True,
        )
        if _health_resp.status_code not in (200, 404):
            rc.print(f"[yellow]Warning: /health returned HTTP {_health_resp.status_code} — check URL.[/yellow]")
    except _httpx.ConnectError:
        rc.print(f"[red]Cannot reach {_url} — check the URL and network connectivity.[/red]")
        raise typer.Exit(code=1)
    except Exception:
        pass  # Non-fatal — proceed to login

    if not username:
        username = Prompt.ask("[bold]Username[/bold]")
    password = Prompt.ask("[bold]Password[/bold]", password=True)

    rc.print(f"  Authenticating with [cyan]{_url}[/cyan]…")

    try:
        from wafpass.auth import do_login as _do_login
        creds = _do_login(_url, username, password)
    except _httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            rc.print("[red]Login failed: invalid username or password.[/red]")
        elif exc.response.status_code == 403:
            rc.print("[red]Login failed: account is disabled.[/red]")
        else:
            rc.print(f"[red]Login failed: HTTP {exc.response.status_code}[/red]")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Login failed: {exc}[/red]")
        raise typer.Exit(code=1)

    # Friendly expiry display
    from datetime import datetime, timezone
    try:
        exp = datetime.fromisoformat(creds.expires_at)
        _exp_str = exp.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        _exp_str = creds.expires_at

    rc.print(f"[green]✓  Logged in[/green] as [bold]{creds.username}[/bold] ([cyan]{creds.role}[/cyan])")
    rc.print(f"   Server   : {creds.server_url}")
    rc.print(f"   Token    : valid until {_exp_str}  [dim](auto-refreshed via refresh token)[/dim]")
    rc.print(f"   Stored   : {_CREDS_FILE}")
    rc.print()
    rc.print("  Push scan results using [bold]--push @[/bold] to use this server automatically:")
    rc.print(f"  [dim]wafpass check ./infra --output json --push @[/dim]")


@app.command("logout")
def cmd_logout() -> None:
    """Revoke the stored session and remove local credentials.

    The refresh token is invalidated on the server so the session cannot be
    silently extended after logout.
    """
    from rich.console import Console
    from wafpass.auth import load, do_logout, clear

    rc = Console()
    creds = load()
    if creds is None:
        rc.print("[yellow]Not logged in — nothing to do.[/yellow]")
        return

    rc.print(f"  Revoking session for [bold]{creds.username}[/bold] on {creds.server_url}…")
    do_logout(creds)
    clear()
    rc.print("[green]✓  Logged out[/green] — local credentials removed.")


@app.command("whoami")
def cmd_whoami() -> None:
    """Show the currently stored login session."""
    from rich.console import Console
    from rich.table import Table
    from datetime import datetime, timezone
    from wafpass.auth import get_valid_credentials, load

    rc = Console()
    raw = load()
    if raw is None:
        rc.print("[yellow]Not logged in.[/yellow]  Run [bold]wafpass login <server-url>[/bold] first.")
        raise typer.Exit(code=1)

    creds = get_valid_credentials()

    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column()

    table.add_row("Server",   raw.server_url)
    table.add_row("Username", f"[bold]{raw.username}[/bold]")
    table.add_row("Role",     f"[cyan]{raw.role}[/cyan]")

    try:
        exp = datetime.fromisoformat(raw.expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = exp - now
        if delta.total_seconds() < 0:
            _exp_label = f"[red]expired {abs(int(delta.total_seconds() // 60))} min ago[/red]"
        elif delta.total_seconds() < 300:
            _exp_label = f"[yellow]expires in {int(delta.total_seconds())}s (refreshing…)[/yellow]"
        else:
            _exp_label = f"[green]valid for {int(delta.total_seconds() // 60)} min[/green]  ({exp.strftime('%Y-%m-%d %H:%M UTC')})"
    except Exception:
        _exp_label = raw.expires_at

    table.add_row("Token",    _exp_label)

    if creds is None:
        table.add_row("Session", "[red]Refresh failed — run 'wafpass login' again.[/red]")
    elif creds.access_token != raw.access_token:
        table.add_row("Session", "[green]Auto-refreshed ✓[/green]")

    rc.print(table)
    rc.print()
    rc.print("  Use [bold]--push @[/bold] to push scan results to this server.")
