"""WAF++ PASS export plugin — Grafana via Prometheus Pushgateway.

This plugin pushes WAF++ run metrics to a **Prometheus Pushgateway** instance.
Grafana then visualises the metrics via a Prometheus datasource.

Works with:
- Self-hosted Grafana + Prometheus + Pushgateway (OSS stack)
- Grafana Cloud when a Grafana Agent / Alloy is configured to scrape the
  Pushgateway and remote_write to Grafana Cloud Metrics

Metrics pushed
--------------
All metrics carry labels: ``iac_plugin``, ``run_id``, ``tool_version``,
and the first source path as ``source``.

+--------------------------------------------+-------+--------------------------------------------+
| Metric                                     | Type  | Description                                |
+============================================+=======+============================================+
| ``wafpass_score``                          | gauge | Overall risk score (0=clean, 100=all fail) |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_controls_total``                 | gauge | Control count by ``status`` label          |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_checks_total``                   | gauge | Check count by ``status`` label            |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_pillar_score``                   | gauge | Risk score per ``pillar`` label            |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_control_status``                 | gauge | Per-control status: 0=PASS 1=FAIL 2=SKIP   |
|                                            |       | 3=WAIVED — enables per-control alerts      |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_score_delta``                    | gauge | Score change vs previous run (+ve=worse)   |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_regressions_total``              | gauge | Controls newly entering FAIL this run      |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_improvements_total``             | gauge | Controls leaving FAIL this run             |
+--------------------------------------------+-------+--------------------------------------------+
| ``wafpass_run_timestamp_seconds``          | gauge | Unix timestamp of this run                 |
+--------------------------------------------+-------+--------------------------------------------+

Config keys (``exports.grafana`` in ``.wafpass-export.yml``)
------------------------------------------------------------
.. code-block:: yaml

    exports:
      grafana:
        pushgateway_url: "http://pushgateway.monitoring.svc:9091"  # required
        job: "wafpass"           # optional; Pushgateway job label (default: wafpass)
        instance: ""             # optional; Pushgateway instance label (default: first source path)
        username: ""             # optional; HTTP Basic Auth user (Grafana Cloud: numeric ID)
        password: "${GRAFANA_CLOUD_TOKEN}"  # optional; HTTP Basic Auth password / API token
        timeout: 10              # optional; HTTP timeout in seconds (default: 10)

Grafana Cloud setup
-------------------
Grafana Cloud's Prometheus endpoint requires binary remote_write format.
The recommended approach for Grafana Cloud is to deploy **Grafana Alloy** or
**Grafana Agent** alongside a Prometheus Pushgateway and configure remote_write
from the agent to Grafana Cloud.  This plugin then targets the Pushgateway URL.

Alternatively, if you run a Prometheus Pushgateway with ``--web.enable-admin-api``
in front of Grafana Cloud, point this plugin at the Pushgateway and let the
Pushgateway federation handle the rest.
"""

from __future__ import annotations

import base64
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from wafpass.export.base import ExportResult
from wafpass.export.registry import registry

_STATUS_INT = {"PASS": 0, "FAIL": 1, "SKIP": 2, "WAIVED": 3}


def _prometheus_text(snapshot: dict, job: str, instance: str) -> str:
    """Render the Prometheus text exposition format for a run snapshot."""
    run_id = snapshot.get("run_id", "unknown")
    iac_plugin = snapshot.get("iac_plugin", "unknown")
    tool_version = snapshot.get("tool_version", "unknown")
    source_paths = snapshot.get("source_paths", [])
    source = source_paths[0] if source_paths else ""
    totals = snapshot.get("totals", {})
    pillar_scores = snapshot.get("pillar_scores", {})
    control_statuses = snapshot.get("control_statuses", {})
    control_details = snapshot.get("control_details", {})
    diff = snapshot.get("diff_from_previous")

    # Parse run timestamp
    generated_at = snapshot.get("generated_at", "")
    try:
        dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        ts_seconds = int(dt.timestamp())
    except Exception:
        ts_seconds = int(time.time())

    # Base labels shared by all metrics
    base_labels = (
        f'iac_plugin="{_esc(iac_plugin)}",'
        f'run_id="{_esc(run_id)}",'
        f'tool_version="{_esc(tool_version)}",'
        f'source="{_esc(source)}"'
    )

    lines: list[str] = []

    def _g(name: str, help_text: str, labels: str, value: float) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{{{labels}}} {value:.1f}")

    # ── Overall risk score ────────────────────────────────────────────────────
    _g(
        "wafpass_score",
        "WAF++ overall risk score (0=fully compliant, 100=all critical controls failing).",
        base_labels,
        float(snapshot.get("score", 0)),
    )

    # ── Control counts ────────────────────────────────────────────────────────
    lines.append("# HELP wafpass_controls_total Number of controls by status.")
    lines.append("# TYPE wafpass_controls_total gauge")
    for status_key, total_key in [("pass", "pass"), ("fail", "fail"), ("skip", "skip"), ("waived", "waived")]:
        lines.append(
            f'wafpass_controls_total{{{base_labels},status="{status_key}"}}'
            f' {totals.get(total_key, 0):.1f}'
        )

    # ── Check counts ──────────────────────────────────────────────────────────
    lines.append("# HELP wafpass_checks_total Number of individual checks by status.")
    lines.append("# TYPE wafpass_checks_total gauge")
    check_counts: dict[str, int] = {"pass": 0, "fail": 0, "skip": 0}
    for detail in control_details.values():
        for cr in detail.get("check_results", []):
            s = cr.get("status", "SKIP").lower()
            if s in check_counts:
                check_counts[s] += 1
    for status_key, count in check_counts.items():
        lines.append(
            f'wafpass_checks_total{{{base_labels},status="{status_key}"}}'
            f' {count:.1f}'
        )

    # ── Per-pillar scores ─────────────────────────────────────────────────────
    lines.append("# HELP wafpass_pillar_score WAF++ risk score per pillar (0=clean, 100=all failing).")
    lines.append("# TYPE wafpass_pillar_score gauge")
    for pillar, score in pillar_scores.items():
        lines.append(
            f'wafpass_pillar_score{{{base_labels},pillar="{_esc(pillar)}"}}'
            f' {float(score):.1f}'
        )

    # ── Per-control status ────────────────────────────────────────────────────
    lines.append(
        "# HELP wafpass_control_status Status of each control: "
        "0=PASS 1=FAIL 2=SKIP 3=WAIVED."
    )
    lines.append("# TYPE wafpass_control_status gauge")
    for control_id, status in control_statuses.items():
        detail = control_details.get(control_id, {})
        severity = detail.get("severity", "low")
        pillar = detail.get("pillar", "unknown")
        status_int = _STATUS_INT.get(status, 2)
        lines.append(
            f'wafpass_control_status{{'
            f'{base_labels},'
            f'control_id="{_esc(control_id)}",'
            f'severity="{_esc(severity)}",'
            f'pillar="{_esc(pillar)}"}}'
            f' {status_int:.1f}'
        )

    # ── Change tracking (only present when a previous run exists) ─────────────
    if diff is not None:
        score_delta = diff.get("score_delta", 0)
        regressions = len(diff.get("regressions", []))
        improvements = len(diff.get("improvements", []))

        _g(
            "wafpass_score_delta",
            "Risk score change compared to previous run (positive=worse, negative=improved).",
            base_labels,
            float(score_delta),
        )
        _g(
            "wafpass_regressions_total",
            "Number of controls that newly entered FAIL state in this run.",
            base_labels,
            float(regressions),
        )
        _g(
            "wafpass_improvements_total",
            "Number of controls that left FAIL state in this run.",
            base_labels,
            float(improvements),
        )

    # ── Run timestamp ─────────────────────────────────────────────────────────
    _g(
        "wafpass_run_timestamp_seconds",
        "Unix timestamp of this WAF++ run.",
        base_labels,
        float(ts_seconds),
    )

    return "\n".join(lines) + "\n"


def _esc(s: str) -> str:
    """Escape backslashes and double-quotes for Prometheus label values."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


class GrafanaPlugin:
    """Export plugin that pushes WAF++ metrics to a Prometheus Pushgateway.

    Self-registers into the global export registry at import time.
    """

    name = "grafana"
    description = "Push WAF++ run metrics to Grafana via a Prometheus Pushgateway."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        url_base = (config.get("pushgateway_url") or "").rstrip("/")
        if not url_base:
            return ExportResult(
                success=False,
                message=(
                    "grafana plugin: 'pushgateway_url' is required. "
                    "Set it under exports.grafana in .wafpass-export.yml."
                ),
            )

        job = config.get("job") or "wafpass"
        run_id = snapshot.get("run_id", "default")
        instance = config.get("instance") or run_id
        timeout = int(config.get("timeout", 10))

        # Pushgateway URL: /metrics/job/<job>/instance/<instance>
        push_url = (
            f"{url_base}/metrics/job/{urllib.parse.quote(job, safe='')}"
            f"/instance/{urllib.parse.quote(instance, safe='')}"
        )

        payload = _prometheus_text(snapshot, job=job, instance=instance).encode("utf-8")

        req = urllib.request.Request(
            push_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
        )

        # Optional HTTP Basic Auth (required for Grafana Cloud remote_write proxy)
        username = config.get("username") or ""
        password = config.get("password") or ""
        if username or password:
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")[:200]
            return ExportResult(
                success=True,
                message=f"Pushed to Pushgateway: HTTP {status}",
                details={"url": push_url, "http_status": status, "body": body},
            )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:200]
            return ExportResult(
                success=False,
                message=f"Pushgateway returned HTTP {exc.code}: {body}",
                details={"url": push_url, "http_status": exc.code},
            )
        except Exception as exc:
            return ExportResult(
                success=False,
                message=f"grafana plugin error: {exc}",
                details={"url": push_url},
            )


registry.register(GrafanaPlugin())
