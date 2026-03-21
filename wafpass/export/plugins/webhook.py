"""WAF++ PASS export plugin — Generic HTTP webhook.

POSTs the full WAF++ run snapshot as JSON to any HTTP endpoint.
This is a general-purpose escape hatch for custom integrations: SIEM
ingestion endpoints, internal dashboards, compliance platforms,
notification services, or any system that accepts a JSON payload.

Config keys (``exports.webhook`` in ``.wafpass-export.yml``)
------------------------------------------------------------
.. code-block:: yaml

    exports:
      webhook:
        url: "https://my-webhook.example.com/wafpass"  # required
        method: "POST"        # optional (default: POST); GET also supported
        headers:              # optional additional request headers
          Authorization: "Bearer ${WEBHOOK_TOKEN}"
          X-Source: "wafpass"
        include_full_snapshot: true  # optional (default: true)
                                     # false = send summary only (score + totals + diff)
        timeout: 10           # optional (default: 10s)

Status: **FULLY IMPLEMENTED**.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from wafpass.export.base import ExportResult
from wafpass.export.registry import registry

_log = logging.getLogger(__name__)


class WebhookPlugin:
    """Export plugin that POSTs the WAF++ run snapshot to any HTTP endpoint."""

    name = "webhook"
    description = "POST WAF++ run snapshot as JSON to a generic HTTP webhook endpoint."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        url = (config.get("url") or "").strip()
        if not url:
            return ExportResult(
                success=False,
                message=(
                    "webhook plugin: 'url' is required. "
                    "Set it under exports.webhook in .wafpass-export.yml."
                ),
            )

        method = (config.get("method") or "POST").upper()
        timeout = int(config.get("timeout", 10))
        include_full = config.get("include_full_snapshot", True)

        payload = self._build_payload(snapshot, include_full=include_full)
        body = json.dumps(payload, default=str).encode("utf-8")

        headers: dict[str, str] = {"Content-Type": "application/json"}
        for k, v in (config.get("headers") or {}).items():
            headers[str(k)] = str(v)

        req = urllib.request.Request(url, data=body, method=method, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body_resp = resp.read().decode("utf-8", errors="replace")[:200]
            return ExportResult(
                success=True,
                message=f"Webhook delivered: HTTP {status}",
                details={"url": url, "http_status": status, "response": body_resp},
            )
        except urllib.error.HTTPError as exc:
            body_resp = exc.read().decode("utf-8", errors="replace")[:200]
            return ExportResult(
                success=False,
                message=f"Webhook returned HTTP {exc.code}: {body_resp}",
                details={"url": url, "http_status": exc.code},
            )
        except Exception as exc:
            return ExportResult(
                success=False,
                message=f"webhook plugin error: {exc}",
                details={"url": url},
            )

    def _build_payload(self, snapshot: dict, include_full: bool) -> dict:
        """Return the payload to POST.

        When *include_full* is ``False``, only the lightweight summary fields
        are sent — useful for webhook endpoints with payload size limits.
        """
        if include_full:
            return snapshot

        diff = snapshot.get("diff_from_previous") or {}
        return {
            "schema_version": snapshot.get("schema_version", 1),
            "run_id": snapshot.get("run_id"),
            "generated_at": snapshot.get("generated_at"),
            "tool_version": snapshot.get("tool_version"),
            "iac_plugin": snapshot.get("iac_plugin"),
            "source_paths": snapshot.get("source_paths"),
            "score": snapshot.get("score"),
            "totals": snapshot.get("totals"),
            "pillar_scores": snapshot.get("pillar_scores"),
            "diff_summary": {
                "previous_run_id": diff.get("previous_run_id"),
                "score_delta": diff.get("score_delta"),
                "regressions_count": len(diff.get("regressions", [])),
                "improvements_count": len(diff.get("improvements", [])),
                "other_changes_count": len(diff.get("other_changes", [])),
            } if diff else None,
        }


registry.register(WebhookPlugin())
