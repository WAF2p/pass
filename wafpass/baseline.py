"""Baseline snapshot support for WAF++ PASS trend/delta reporting."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

_SEV_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}

def build_baseline(report) -> dict:
    """Build a JSON-serialisable baseline snapshot from a Report."""
    total_w = fail_w = 0
    pillar_data: dict[str, dict] = {}
    control_statuses: dict[str, str] = {}
    for cr in report.results:
        w = _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        total_w += w
        pillar = (cr.control.pillar or "unknown").lower()
        if pillar not in pillar_data:
            pillar_data[pillar] = {"total_w": 0, "fail_w": 0}
        pillar_data[pillar]["total_w"] += w
        if cr.status == "FAIL":
            fail_w += w
            pillar_data[pillar]["fail_w"] += w
        control_statuses[cr.control.id] = cr.status
    score = int(fail_w / max(total_w, 1) * 100)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "total_fail": report.total_fail,
        "total_pass": report.total_pass,
        "total_skip": report.total_skip,
        "total_waived": report.total_waived,
        "controls_run": report.controls_run,
        "pillar_scores": {p: int(d["fail_w"] / max(d["total_w"], 1) * 100) for p, d in pillar_data.items()},
        "control_statuses": control_statuses,
    }

def save_baseline(baseline: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, default=str))

def load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
