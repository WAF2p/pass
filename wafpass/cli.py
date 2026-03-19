"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import re
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


_AZ_RE = re.compile(r"^([a-z]{2}-[a-z]+-\d+)[a-z]$")
_REGION_IN_STRING_RE = re.compile(r"\b([a-z]{2}-(?:central|west|east|north|south|southeast|northeast|northwest|southwest)-\d+)\b")


def _region_from_az(val: str) -> str | None:
    """Return the AWS region from an AZ string, e.g. 'eu-central-1a' → 'eu-central-1'."""
    m = _AZ_RE.match(val.strip())
    return m.group(1) if m else None


def _region_from_string(val: str) -> str | None:
    """Extract an AWS region embedded in an arbitrary string (e.g. service endpoint)."""
    m = _REGION_IN_STRING_RE.search(val)
    return m.group(1) if m else None


def _extract_regions(tf_state: TerraformState) -> list[tuple[str, str]]:
    """Extract (region_name, provider) tuples from parsed Terraform state."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []

    def add(region: str, provider: str) -> None:
        key = (region.lower(), provider)
        if key not in seen:
            seen.add(key)
            result.append((region, provider))

    def try_add_literal(val: object, provider: str) -> None:
        """Add val directly if it is a literal region string."""
        if _is_literal_string(val):
            add(str(val).strip(), provider)

    def try_add_aws_val(val: object) -> None:
        """Try to extract an AWS region from a literal attribute value."""
        if not _is_literal_string(val):
            return
        s = str(val).strip()
        # Direct region string (e.g. "eu-central-1")
        if re.match(r"^[a-z]{2}-[a-z]+-\d+$", s):
            add(s, "aws")
            return
        # AZ string (e.g. "eu-central-1a")
        region = _region_from_az(s)
        if region:
            add(region, "aws")
            return
        # Embedded in a service name / ARN (e.g. "com.amazonaws.eu-central-1.s3")
        region = _region_from_string(s)
        if region:
            add(region, "aws")

    for blk in tf_state.providers:
        pname = blk.type.lower()
        if pname == "aws":
            try_add_literal(blk.attributes.get("region"), "aws")
        elif pname in ("azurerm", "azuread", "azurestack"):
            try_add_literal(blk.attributes.get("location") or blk.attributes.get("region"), "azure")
        elif pname in ("google", "google-beta"):
            try_add_literal(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")

    for blk in tf_state.resources:
        rtype = blk.type.lower()
        if rtype.startswith("aws_"):
            for attr in ("region", "availability_zone", "service_name"):
                try_add_aws_val(blk.attributes.get(attr))
            # subnet_ids list items may be expressions; skip
        elif rtype.startswith("azurerm_"):
            try_add_literal(blk.attributes.get("location"), "azure")
        elif rtype.startswith("google_"):
            try_add_literal(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")

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
