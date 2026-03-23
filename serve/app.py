"""WAF++ PASS – internal web UI server.

Start with:
    cd pass/
    uvicorn serve.app:app --reload --port 8080

Or directly:
    python -m serve.app

Requires:
    pip install fastapi uvicorn
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Allow importing wafpass from the parent directory when run without install
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CONTROLS_DIR = BASE_DIR.parent / "controls"
TEMPLATES_DIR = BASE_DIR / "templates"
WAIVERS_FILE = BASE_DIR / "waivers.yml"
LAST_RESULTS_FILE = BASE_DIR / "last_results.json"

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WAF++ PASS Web UI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

_TEMPLATE_TEXT: str | None = None

def _render_index(controls_json: str, waivers_json: str, results_json: str) -> str:
    """Read the HTML template and substitute data placeholders (no Jinja2 required)."""
    global _TEMPLATE_TEXT
    if _TEMPLATE_TEXT is None:
        _TEMPLATE_TEXT = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
    html = _TEMPLATE_TEXT
    html = html.replace("__CONTROLS_JSON__", controls_json)
    html = html.replace("__WAIVERS_JSON__", waivers_json)
    html = html.replace("__RESULTS_JSON__", results_json)
    # Replace the mode marker exactly once (the string literal in the script block)
    html = html.replace('window.__MODE__ = "__MODE__";', 'window.__MODE__ = "internal";', 1)
    return html


# ── Helpers ────────────────────────────────────────────────────────────────

def _controls_as_dicts() -> list[dict]:
    """Load all controls and return as JSON-serialisable list."""
    try:
        from wafpass.loader import load_controls
        controls = load_controls(CONTROLS_DIR)
    except Exception:
        return []

    result = []
    for c in controls:
        result.append({
            "id": c.id,
            "title": c.title,
            "pillar": c.pillar,
            "severity": c.severity,
            "category": c.category,
            "description": c.description,
            "checks_count": len(c.checks),
            "automated_checks": [
                {"id": ch.id, "title": ch.title, "severity": ch.severity}
                for ch in c.checks
            ],
            "regulatory_mapping": c.regulatory_mapping,
        })
    return result


def _raw_control(control_id: str) -> dict | None:
    """Return raw YAML dict for a single control."""
    for f in CONTROLS_DIR.glob("WAF-*.yml"):
        with f.open() as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict) and data.get("id") == control_id:
            return data
    return None


def _load_waivers() -> dict[str, dict]:
    """Load waivers.yml and return dict keyed by control ID."""
    if not WAIVERS_FILE.exists():
        return {}
    with WAIVERS_FILE.open() as fh:
        data = yaml.safe_load(fh) or {}
    return {e["id"]: e for e in data.get("waivers", []) if "id" in e}


def _save_waivers(waivers: dict[str, dict]) -> None:
    with WAIVERS_FILE.open("w") as fh:
        yaml.safe_dump({"waivers": list(waivers.values())}, fh, default_flow_style=False)


def _compute_score(results: list[dict]) -> int:
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_w = pass_w = 0
    for r in results:
        if r["status"] in ("SKIP", "WAIVED"):
            continue
        w = weights.get(r.get("severity", "medium"), 2)
        total_w += w
        if r["status"] == "PASS":
            pass_w += w
    return round(pass_w / total_w * 100) if total_w else 100


def _pillar_scores(results: list[dict]) -> dict[str, int]:
    pillars: dict[str, tuple[int, int]] = {}  # pillar -> (pass, total)
    for r in results:
        pillar = r.get("pillar", "unknown")
        if r["status"] in ("SKIP", "WAIVED"):
            continue
        p, t = pillars.get(pillar, (0, 0))
        pillars[pillar] = (p + (1 if r["status"] == "PASS" else 0), t + 1)
    return {
        p: round(ps / t * 100) if t else 100
        for p, (ps, t) in pillars.items()
    }


def _report_to_dict(report: Any) -> dict:
    from wafpass.models import Report
    results = []
    for cr in report.results:
        results.append({
            "control_id": cr.control.id,
            "control_title": cr.control.title,
            "pillar": cr.control.pillar,
            "severity": cr.control.severity,
            "category": cr.control.category,
            "description": cr.control.description,
            "status": cr.status,
            "waived_reason": cr.waived_reason,
            "regulatory_mapping": cr.control.regulatory_mapping,
            "check_results": [
                {
                    "check_id": r.check_id,
                    "check_title": r.check_title,
                    "severity": r.severity,
                    "status": r.status,
                    "resource": r.resource,
                    "message": r.message,
                    "remediation": r.remediation,
                }
                for r in cr.results
            ],
        })

    return {
        "path": report.path,
        "run_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "timestamp": datetime.now().isoformat(),
        "controls_loaded": report.controls_loaded,
        "controls_run": report.controls_run,
        "total_pass": report.total_pass,
        "total_fail": report.total_fail,
        "total_skip": report.total_skip,
        "total_waived": report.total_waived,
        "score": _compute_score(results),
        "pillar_scores": _pillar_scores(results),
        "detected_regions": [[r, p] for r, p in report.detected_regions],
        "results": results,
    }


# ── Pydantic models ────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str
    iac: str = "terraform"
    pillar: str | None = None
    severity: str | None = None


class WaiverEntry(BaseModel):
    id: str
    reason: str
    owner: str = ""
    expires: str = ""


class WaiversPayload(BaseModel):
    waivers: list[WaiverEntry]


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    controls = _controls_as_dicts()
    waivers = _load_waivers()
    last_results: dict | None = None
    if LAST_RESULTS_FILE.exists():
        with LAST_RESULTS_FILE.open() as fh:
            last_results = json.load(fh)

    html = _render_index(
        controls_json=json.dumps(controls),
        waivers_json=json.dumps(waivers),
        results_json=json.dumps(last_results),
    )
    return HTMLResponse(content=html)


@app.get("/api/controls")
async def api_controls():
    return _controls_as_dicts()


@app.get("/api/controls/{control_id}")
async def api_control_detail(control_id: str):
    data = _raw_control(control_id)
    if not data:
        raise HTTPException(status_code=404, detail="Control not found")
    return data


@app.get("/api/waivers")
async def api_get_waivers():
    return _load_waivers()


@app.put("/api/waivers")
async def api_save_waivers(payload: WaiversPayload):
    waivers = {w.id: w.model_dump() for w in payload.waivers}
    _save_waivers(waivers)
    return {"saved": len(waivers)}


@app.delete("/api/waivers/{control_id}")
async def api_delete_waiver(control_id: str):
    waivers = _load_waivers()
    waivers.pop(control_id, None)
    _save_waivers(waivers)
    return {"ok": True}


@app.get("/api/waivers/export")
async def api_export_waivers():
    waivers = _load_waivers()
    skip = {
        "version": "1",
        "waivers": [
            {k: v for k, v in e.items() if v}
            for e in waivers.values()
        ],
    }
    content = yaml.safe_dump(skip, default_flow_style=False, sort_keys=False)
    return Response(
        content=content,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename=".wafpass-skip.yml"'},
    )


@app.post("/api/scan")
async def api_run_scan(req: ScanRequest):
    """Run an in-process WAF++ PASS scan and return results as JSON."""
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")

    try:
        from wafpass.engine import run_controls
        from wafpass.iac import registry
        from wafpass.iac.base import IaCState
        from wafpass.loader import load_controls
        from wafpass.models import Report
        from wafpass.waivers import apply_waivers, load_waivers

        controls = load_controls(CONTROLS_DIR, pillar=req.pillar)
        if not controls:
            raise HTTPException(status_code=422, detail="No controls loaded from controls directory.")

        plugin = registry.get(req.iac.lower())
        if plugin is None:
            raise HTTPException(status_code=422, detail=f"Unknown IaC plugin: {req.iac}")

        state = plugin.parse(path)
        results = run_controls(controls, state)

        waivers_data = []
        if WAIVERS_FILE.exists():
            waivers_data = load_waivers(WAIVERS_FILE)
        apply_waivers(results, waivers_data)

        report = Report(
            path=str(path),
            controls_loaded=len(controls),
            controls_run=len([r for r in results if r.results]),
            results=results,
            detected_regions=[],
            source_paths=[str(path)],
        )
        data = _report_to_dict(report)

        # Persist for next page load
        with LAST_RESULTS_FILE.open("w") as fh:
            json.dump(data, fh, indent=2)

        return data

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/results")
async def api_get_results():
    if not LAST_RESULTS_FILE.exists():
        return None
    with LAST_RESULTS_FILE.open() as fh:
        return json.load(fh)


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("serve.app:app", host="0.0.0.0", port=8080, reload=True)
