"""WAF++ PASS core library — public API.

Quick start
-----------
::

    from wafpass import run_scan, WafpassResultSchema

    result: WafpassResultSchema = run_scan(
        paths=["infra/"],
        controls_dir="controls/",
    )
    print(result.score)

Public symbols
--------------
* :func:`run_scan`             — run a compliance scan, return a result schema object
* :class:`WafpassResultSchema` — Pydantic model for the wafpass-result.json contract
* :class:`FindingSchema`       — Pydantic model for a single finding within a result
* :class:`Report`              — internal dataclass report (pre-schema, for CLI/PDF use)
* ``IaCPlugin``, ``IaCBlock``, ``IaCState`` — protocol types for IaC adapters
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("wafpass-core")
except PackageNotFoundError:
    __version__ = "1.0.0"

__name_full__ = "WAF++ PASS"

# ── Result schema (public contract) ───────────────────────────────────────────
from wafpass.schema import FindingSchema, WafpassResultSchema  # noqa: E402

# ── Internal report model (used by CLI, PDF reporter, etc.) ───────────────────
from wafpass.models import Report  # noqa: E402

# ── IaC adapter protocol types ────────────────────────────────────────────────
from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState  # noqa: E402


def run_scan(
    paths: list[str],
    controls_dir: str = "controls/",
    *,
    severity_filter: str | None = None,
    waivers_file: str | None = None,
) -> "WafpassResultSchema":
    """Run a WAF++ PASS compliance scan and return a structured result.

    Parameters
    ----------
    paths:
        One or more file-system paths to scan (Terraform ``.tf`` files or
        directories).
    controls_dir:
        Directory containing WAF++ YAML control definitions.
    severity_filter:
        If given, only evaluate checks at or above this severity level
        (``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``).
    waivers_file:
        Path to a ``waivers.yml`` risk-acceptance file.

    Returns
    -------
    WafpassResultSchema
        The full scan result as a validated Pydantic model, ready to be
        serialised (``result.model_dump()`` / ``result.model_dump_json()``)
        or posted to ``wafpass-server``.
    """
    from pathlib import Path

    from wafpass.engine import filter_by_severity, run_controls
    from wafpass.iac import registry
    from wafpass.loader import load_controls
    from wafpass.models import Report as _Report
    from wafpass.waivers import apply_waivers, load_waivers

    controls_path = Path(controls_dir)
    controls = load_controls(controls_path)

    # Build IaC state from all paths
    all_blocks: list[IaCBlock] = []
    source_paths: list[str] = []
    detected_regions: list[tuple[str, str]] = []

    for p in paths:
        state = registry.load(Path(p))
        all_blocks.extend(state.blocks)
        source_paths.append(p)
        detected_regions.extend(state.detected_regions)

    from wafpass.iac.base import IaCState as _IaCState

    merged = _IaCState(blocks=all_blocks, detected_regions=detected_regions)

    # Apply severity filter
    if severity_filter:
        controls = filter_by_severity(controls, severity_filter)

    # Evaluate controls
    results = run_controls(controls, merged)

    # Apply waivers
    if waivers_file:
        waivers = load_waivers(Path(waivers_file))
        results = apply_waivers(results, waivers)

    # Build internal Report
    display_path = " | ".join(paths) if len(paths) > 1 else paths[0] if paths else ""
    report = _Report(
        path=display_path,
        controls_loaded=len(controls),
        controls_run=len([r for r in results if r.status != "SKIP"]),
        results=results,
        detected_regions=detected_regions,
        source_paths=source_paths,
    )

    # Convert to WafpassResultSchema
    findings: list[FindingSchema] = []
    for cr in report.results:
        for chk in cr.results:
            findings.append(
                FindingSchema(
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
                )
            )
        # If waived, add a synthetic WAIVED finding
        if cr.status == "WAIVED" and not cr.results:
            findings.append(
                FindingSchema(
                    check_id=f"{cr.control.id}-WAIVED",
                    check_title=cr.control.title,
                    control_id=cr.control.id,
                    pillar=cr.control.pillar,
                    severity=cr.control.severity,
                    status="WAIVED",
                    resource="",
                    message=cr.waived_reason or "",
                    remediation="",
                )
            )

    # Compute pillar scores
    pillar_totals: dict[str, list[int]] = {}
    for cr in report.results:
        p = cr.control.pillar
        pillar_totals.setdefault(p, [])
        pillar_totals[p].append(1 if cr.status == "PASS" else 0)

    pillar_scores = {
        p: int(sum(v) / len(v) * 100) if v else 0
        for p, v in pillar_totals.items()
    }
    overall_score = (
        int(sum(pillar_scores.values()) / len(pillar_scores))
        if pillar_scores
        else 0
    )

    return WafpassResultSchema(
        project="",
        branch="",
        git_sha="",
        triggered_by="local",
        iac_framework="terraform",
        score=overall_score,
        pillar_scores=pillar_scores,
        path=report.path,
        controls_loaded=report.controls_loaded,
        controls_run=report.controls_run,
        detected_regions=[list(r) for r in report.detected_regions],
        source_paths=report.source_paths,
        findings=findings,
    )


__all__ = [
    "__version__",
    "__name_full__",
    "run_scan",
    "WafpassResultSchema",
    "FindingSchema",
    "Report",
    "IaCPlugin",
    "IaCBlock",
    "IaCState",
]
