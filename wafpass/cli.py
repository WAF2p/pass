"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List

import typer

from wafpass import __name_full__, __version__
from wafpass.engine import filter_by_severity, run_controls
from wafpass.loader import load_controls
from wafpass.models import Report
from wafpass.parser import TerraformState, parse_terraform
from wafpass.reporter import print_report, print_summary_only
from wafpass.waivers import DEFAULT_SKIP_FILE, apply_waivers, load_waivers


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


def _region_from_zone(val: str) -> str | None:
    """Return region from a zone string (Alibaba/Yandex).

    Examples: 'cn-hangzhou-b' → 'cn-hangzhou', 'ru-central1-a' → 'ru-central1'
    Returns None if val doesn't look like a zone identifier (e.g. plain 'cn-hangzhou').
    """
    parts = val.strip().split("-")
    if len(parts) >= 3 and len(parts[-1]) == 1 and parts[-1].isalpha():
        return "-".join(parts[:-1])
    return None


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

    def try_add_zone_val(val: object, provider: str) -> None:
        """Add a region extracted from an Alibaba/Yandex zone string."""
        if not _is_literal_string(val):
            return
        s = str(val).strip()
        region = _region_from_zone(s) or s  # fall back to the value itself if no zone suffix
        add(region, provider)

    for blk in tf_state.providers:
        pname = blk.type.lower()
        if pname == "aws":
            try_add_literal(blk.attributes.get("region"), "aws")
        elif pname in ("azurerm", "azuread", "azurestack"):
            try_add_literal(blk.attributes.get("location") or blk.attributes.get("region"), "azure")
        elif pname in ("google", "google-beta"):
            try_add_literal(blk.attributes.get("region") or blk.attributes.get("location"), "gcp")
        elif pname == "alicloud":
            try_add_zone_val(blk.attributes.get("region") or blk.attributes.get("zone"), "alicloud")
        elif pname == "yandex":
            try_add_zone_val(blk.attributes.get("zone") or blk.attributes.get("region"), "yandex")
        elif pname == "oci":
            try_add_literal(blk.attributes.get("region"), "oci")

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
        elif rtype.startswith("alicloud_"):
            try_add_zone_val(
                blk.attributes.get("region") or blk.attributes.get("zone") or blk.attributes.get("zone_id"),
                "alicloud",
            )
        elif rtype.startswith("yandex_"):
            try_add_zone_val(blk.attributes.get("zone") or blk.attributes.get("region"), "yandex")
        elif rtype.startswith("oci_"):
            try_add_literal(blk.attributes.get("region"), "oci")

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
    paths: List[Path] = typer.Argument(
        ...,
        help=(
            "Path(s) to Terraform files (directories or .tf files). "
            "Pass multiple paths to merge results from different cloud folders, "
            "e.g. wafpass check ./aws ./azure ./gcp"
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
) -> None:
    """Check Terraform files against WAF++ YAML controls."""

    # ── Validate paths ────────────────────────────────────────────────────────
    for p in paths:
        if not p.exists():
            typer.echo(f"ERROR: Path does not exist: {p}", err=True)
            raise typer.Exit(code=2)

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

    # ── Parse Terraform (merge across all paths) ──────────────────────────────
    merged_tf = TerraformState()
    all_regions: list[tuple[str, str]] = []

    for p in paths:
        if len(paths) > 1:
            typer.echo(f"Scanning: {p}")
        try:
            tf = parse_terraform(p)
        except Exception as exc:
            typer.echo(f"ERROR parsing Terraform files in {p}: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        merged_tf.resources.extend(tf.resources)
        merged_tf.providers.extend(tf.providers)
        merged_tf.variables.extend(tf.variables)
        merged_tf.modules.extend(tf.modules)
        merged_tf.terraform_blocks.extend(tf.terraform_blocks)
        all_regions.extend(_extract_regions(tf))

    # Deduplicate regions while preserving order
    seen_region_keys: set[tuple[str, str]] = set()
    unique_regions: list[tuple[str, str]] = []
    for r in all_regions:
        key = (r[0].lower(), r[1])
        if key not in seen_region_keys:
            seen_region_keys.add(key)
            unique_regions.append(r)

    # ── Run controls ──────────────────────────────────────────────────────────
    try:
        results = run_controls(controls, merged_tf)
    except Exception as exc:
        typer.echo(f"ERROR running controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # ── Apply severity filter ─────────────────────────────────────────────────
    if severity:
        results = filter_by_severity(results, severity)

    # ── Apply waivers ─────────────────────────────────────────────────────────
    # Discovery order: explicit --skip-file > CWD > each scanned path directory
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

    # ── Build report ──────────────────────────────────────────────────────────
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
        from wafpass.baseline import build_baseline, load_baseline, save_baseline as save_baseline_file

        dest = pdf_out or Path("wafpass-report.pdf")

        baseline_data: dict | None = None
        if baseline_path:
            try:
                baseline_data = load_baseline(baseline_path)
            except Exception as exc:
                typer.echo(f"WARNING: Could not load baseline '{baseline_path}': {exc}", err=True)

        generate_pdf(report, dest, baseline=baseline_data)
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

    # ── Exit code ─────────────────────────────────────────────────────────────
    fail_on_lower = fail_on.lower()
    if fail_on_lower == "fail" and report.total_fail > 0:
        raise typer.Exit(code=1)
    elif fail_on_lower == "skip" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
    elif fail_on_lower == "any" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
