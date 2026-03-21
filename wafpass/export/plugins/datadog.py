"""WAF++ PASS export plugin — Datadog.

Sends WAF++ run metrics to Datadog via the Datadog Metrics API v2.
Each WAF++ metric is submitted as a gauge with tags that mirror the
Prometheus labels used by the Grafana plugin.

Metrics submitted
-----------------
- ``wafpass.score``
- ``wafpass.controls.pass`` / ``.fail`` / ``.skip`` / ``.waived``
- ``wafpass.pillar.score`` (tag: ``pillar:<name>``)
- ``wafpass.control.status`` (tags: ``control_id``, ``severity``, ``pillar``)
- ``wafpass.score_delta`` / ``wafpass.regressions`` / ``wafpass.improvements``
  (only when a previous run exists)

Tags applied to all metrics
---------------------------
``iac_plugin``, ``run_id``, ``tool_version``, ``source`` (first source path).

Config keys (``exports.datadog`` in ``.wafpass-export.yml``)
------------------------------------------------------------
.. code-block:: yaml

    exports:
      datadog:
        api_key: "${DD_API_KEY}"    # required
        site: "datadoghq.eu"        # optional; datadoghq.com (US) or datadoghq.eu (EU)
        timeout: 10                 # optional (default: 10s)

Status: **STUB** — raises ``NotImplementedError`` when called.
Implement the ``_send`` method to activate this plugin.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from wafpass.export.base import ExportResult
from wafpass.export.registry import registry

_log = logging.getLogger(__name__)

_DATADOG_SITES: dict[str, str] = {
    "datadoghq.com": "https://api.datadoghq.com",
    "datadoghq.eu": "https://api.datadoghq.eu",
    "us3.datadoghq.com": "https://api.us3.datadoghq.com",
    "us5.datadoghq.com": "https://api.us5.datadoghq.com",
    "ap1.datadoghq.com": "https://api.ap1.datadoghq.com",
}

_STATUS_INT = {"PASS": 0, "FAIL": 1, "SKIP": 2, "WAIVED": 3}


class DatadogPlugin:
    """Export plugin for Datadog metrics.

    Status: STUB.  Implement ``_build_payload`` and ``_send`` to activate.
    """

    name = "datadog"
    description = "Submit WAF++ run metrics to Datadog Metrics API v2 (stub)."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        api_key = config.get("api_key") or ""
        if not api_key:
            return ExportResult(
                success=False,
                message=(
                    "datadog plugin: 'api_key' is required. "
                    "Set it under exports.datadog in .wafpass-export.yml."
                ),
            )

        site_key = config.get("site", "datadoghq.com")
        base_url = _DATADOG_SITES.get(site_key, f"https://api.{site_key}")
        endpoint = f"{base_url}/api/v2/series"
        timeout = int(config.get("timeout", 10))

        try:
            payload = self._build_payload(snapshot)
            self._send(endpoint, api_key, payload, timeout)
            return ExportResult(
                success=True,
                message=f"Submitted {len(payload['series'])} metric series to Datadog.",
                details={"endpoint": endpoint, "series_count": len(payload["series"])},
            )
        except NotImplementedError:
            _log.warning(
                "datadog plugin is a stub. "
                "Implement _build_payload / _send in "
                "wafpass/export/plugins/datadog.py to activate."
            )
            return ExportResult(
                success=False,
                message=(
                    "datadog plugin is not yet implemented. "
                    "See wafpass/export/plugins/datadog.py for the contribution skeleton."
                ),
            )
        except Exception as exc:
            return ExportResult(success=False, message=f"datadog plugin error: {exc}")

    # ── Internal helpers (implement these to activate the plugin) ─────────────

    def _build_payload(self, snapshot: dict) -> dict:
        """Build a Datadog Metrics API v2 JSON payload from *snapshot*.

        Raises ``NotImplementedError`` until implemented.

        Reference: https://docs.datadoghq.com/api/latest/metrics/#submit-metrics
        """
        raise NotImplementedError(
            "datadog plugin: _build_payload is not yet implemented. "
            "See the stub skeleton in wafpass/export/plugins/datadog.py."
        )

        # ── Skeleton (uncomment and adapt when implementing) ──────────────────
        # run_id = snapshot.get("run_id", "unknown")
        # iac_plugin = snapshot.get("iac_plugin", "unknown")
        # tool_version = snapshot.get("tool_version", "unknown")
        # source = (snapshot.get("source_paths") or [""])[0]
        # totals = snapshot.get("totals", {})
        # pillar_scores = snapshot.get("pillar_scores", {})
        # control_statuses = snapshot.get("control_statuses", {})
        # control_details = snapshot.get("control_details", {})
        # diff = snapshot.get("diff_from_previous")
        # now = int(time.time())
        #
        # base_tags = [
        #     f"iac_plugin:{iac_plugin}",
        #     f"run_id:{run_id}",
        #     f"tool_version:{tool_version}",
        #     f"source:{source}",
        # ]
        #
        # def _series(metric: str, value: float, tags: list[str]) -> dict:
        #     return {
        #         "metric": metric,
        #         "type": 3,  # 3 = gauge
        #         "points": [{"timestamp": now, "value": value}],
        #         "tags": base_tags + tags,
        #     }
        #
        # series = [_series("wafpass.score", float(snapshot.get("score", 0)), [])]
        # for status in ("pass", "fail", "skip", "waived"):
        #     series.append(_series(f"wafpass.controls.{status}", float(totals.get(status, 0)), []))
        # for pillar, score in pillar_scores.items():
        #     series.append(_series("wafpass.pillar.score", float(score), [f"pillar:{pillar}"]))
        # for cid, status in control_statuses.items():
        #     detail = control_details.get(cid, {})
        #     series.append(_series("wafpass.control.status", float(_STATUS_INT.get(status, 2)), [
        #         f"control_id:{cid}",
        #         f"severity:{detail.get('severity', 'low')}",
        #         f"pillar:{detail.get('pillar', 'unknown')}",
        #     ]))
        # if diff:
        #     series.append(_series("wafpass.score_delta", float(diff.get("score_delta", 0)), []))
        #     series.append(_series("wafpass.regressions", float(len(diff.get("regressions", []))), []))
        #     series.append(_series("wafpass.improvements", float(len(diff.get("improvements", []))), []))
        # return {"series": series}

    def _send(self, endpoint: str, api_key: str, payload: dict, timeout: int) -> None:
        """POST the metric series to Datadog.

        Raises ``NotImplementedError`` until implemented.
        """
        raise NotImplementedError(
            "datadog plugin: _send is not yet implemented."
        )

        # ── Skeleton ──────────────────────────────────────────────────────────
        # body = json.dumps(payload).encode("utf-8")
        # req = urllib.request.Request(
        #     endpoint,
        #     data=body,
        #     method="POST",
        #     headers={
        #         "Content-Type": "application/json",
        #         "DD-API-KEY": api_key,
        #     },
        # )
        # with urllib.request.urlopen(req, timeout=timeout) as resp:
        #     if resp.status not in (200, 202):
        #         raise RuntimeError(f"Datadog returned HTTP {resp.status}")


registry.register(DatadogPlugin())
