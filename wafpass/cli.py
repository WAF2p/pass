"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from wafpass import __name_full__, __version__
from wafpass.engine import filter_by_severity, run_controls
from wafpass.loader import load_controls
from wafpass.models import Report
from wafpass.parser import TerraformState, parse_terraform
from wafpass.reporter import print_report, print_summary_only


def _is_literal_string(val: object) -> bool:
    """Return True if val is a plain string, not a Terraform expression."""
    if not isinstance(val, str):
        return False
    v = val.strip()
    return bool(v) and "${" not in v and not v.startswith("var.") and not v.startswith("local.")


def _extract_regions(tf_state: TerraformState) -> list[tuple[str, str]]:
    """Extract (region_name, provider) tuples from parsed Terraform state."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []

    def add(val: object, provider: str) -> None:
        if _is_literal_string(val):
            key = (str(val).strip().lower(), provider)
            if key not in seen:
                seen.add(key)
                result.append((str(val).strip(), provider))

    for blk in tf_state.providers:
        pname = blk.type.lower()
        if pname == "aws":
            add(blk.attributes.get("region"), "aws")
        elif pname in ("azurerm", "azuread", "azurestack"):
            add(blk.attributes.get("location") or blk.attributes.get("region"), "azure")
        elif pname in ("google", "google-beta"):
            add(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")

    for blk in tf_state.resources:
        rtype = blk.type.lower()
        if rtype.startswith("aws_"):
            add(blk.attributes.get("region"), "aws")
        elif rtype.startswith("azurerm_"):
            add(blk.attributes.get("location"), "azure")
        elif rtype.startswith("google_"):
            add(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")

    return result

app = typer.Typer(
    name="wafpass",
    help="WAF++ PASS – Terraform controls checker for the WAF++ framework.",
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
    """WAF++ PASS – check Terraform files against WAF++ controls."""


@app.command()
def check(
    path: Path = typer.Argument(
        ...,
        help="Path to Terraform files (directory or single .tf file).",
        exists=True,
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
) -> None:
    """Check Terraform files against WAF++ YAML controls."""

    # Parse control ID list
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
        typer.echo(
            f"No controls found in '{controls_dir}'"
            + (f" (pillar={pillar})" if pillar else "")
            + (f" (ids={ids})" if ids else ""),
            err=True,
        )
        raise typer.Exit(code=2)

    # ── Parse Terraform ───────────────────────────────────────────────────────
    try:
        tf = parse_terraform(path)
    except Exception as exc:
        typer.echo(f"ERROR parsing Terraform files: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # ── Run controls ──────────────────────────────────────────────────────────
    try:
        results = run_controls(controls, tf)
    except Exception as exc:
        typer.echo(f"ERROR running controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # ── Apply severity filter ─────────────────────────────────────────────────
    if severity:
        results = filter_by_severity(results, severity)

    # ── Build report ──────────────────────────────────────────────────────────
    report = Report(
        path=str(path),
        controls_loaded=len(controls),
        controls_run=len(results),
        results=results,
        detected_regions=_extract_regions(tf),
    )

    # ── Output ────────────────────────────────────────────────────────────────
    if output == "console":
        if summary_only:
            print_summary_only(report)
        else:
            print_report(report, verbose=verbose)
    elif output == "pdf":
        try:
            from wafpass.pdf_reporter import generate_pdf
        except ImportError:
            typer.echo(
                "ERROR: PDF output requires 'reportlab'. Install with: pip install reportlab",
                err=True,
            )
            raise typer.Exit(code=2)
        dest = pdf_out or Path("wafpass-report.pdf")
        generate_pdf(report, dest)
        typer.echo(f"PDF report written to: {dest}")
        # Also print summary to console so CI pipelines see the result
        print_summary_only(report)
    else:
        typer.echo(f"Output format '{output}' is not yet supported.", err=True)
        raise typer.Exit(code=2)

    # ── Exit code ─────────────────────────────────────────────────────────────
    fail_on_lower = fail_on.lower()
    if fail_on_lower == "fail" and report.total_fail > 0:
        raise typer.Exit(code=1)
    elif fail_on_lower == "skip" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
    elif fail_on_lower == "any" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
