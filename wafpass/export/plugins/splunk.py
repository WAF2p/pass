"""WAF++ PASS export plugin — Splunk HTTP Event Collector (HEC).

Sends the WAF++ run snapshot as a structured JSON event to Splunk via the
HTTP Event Collector (HEC) endpoint.  The full snapshot dict is submitted
as the event body, making every field searchable in Splunk immediately.

A second event is optionally sent for each changed control when change
tracking data (``diff_from_previous``) is present — enabling Splunk alerts
on per-control regressions.

Config keys (``exports.splunk`` in ``.wafpass-export.yml``)
-----------------------------------------------------------
.. code-block:: yaml

    exports:
      splunk:
        hec_url: "https://splunk.example.com:8088/services/collector"  # required
        token: "${SPLUNK_HEC_TOKEN}"   # required; HEC token
        index: "main"                  # optional (default: use HEC default)
        source: "wafpass"              # optional (default: wafpass)
        sourcetype: "_json"            # optional (default: _json)
        send_control_events: false     # optional; one event per changed control
        timeout: 10                    # optional (default: 10s)

Status: **STUB** — raises ``NotImplementedError`` when called.
Implement ``_send`` to activate this plugin.
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


class SplunkPlugin:
    """Export plugin for Splunk via HTTP Event Collector.

    Status: STUB.  Implement ``_send`` to activate.
    """

    name = "splunk"
    description = "Send WAF++ run snapshot to Splunk via HTTP Event Collector (stub)."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        hec_url = (config.get("hec_url") or "").rstrip("/")
        token = config.get("token") or ""
        if not hec_url or not token:
            return ExportResult(
                success=False,
                message=(
                    "splunk plugin: 'hec_url' and 'token' are required. "
                    "Set them under exports.splunk in .wafpass-export.yml."
                ),
            )

        try:
            events = self._build_events(snapshot, config)
            self._send(hec_url, token, events, int(config.get("timeout", 10)))
            return ExportResult(
                success=True,
                message=f"Sent {len(events)} event(s) to Splunk HEC.",
                details={"hec_url": hec_url, "event_count": len(events)},
            )
        except NotImplementedError:
            _log.warning(
                "splunk plugin is a stub. "
                "Implement _send in wafpass/export/plugins/splunk.py to activate."
            )
            return ExportResult(
                success=False,
                message=(
                    "splunk plugin is not yet implemented. "
                    "See wafpass/export/plugins/splunk.py for the contribution skeleton."
                ),
            )
        except Exception as exc:
            return ExportResult(success=False, message=f"splunk plugin error: {exc}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_events(self, snapshot: dict, config: dict) -> list[dict]:
        """Build HEC event payloads from *snapshot*."""
        generated_at = snapshot.get("generated_at", "")
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            ts = dt.timestamp()
        except Exception:
            ts = time.time()

        index = config.get("index") or None
        source = config.get("source") or "wafpass"
        sourcetype = config.get("sourcetype") or "_json"

        def _wrap(event_data: dict) -> dict:
            ev: dict = {"time": ts, "event": event_data, "source": source, "sourcetype": sourcetype}
            if index:
                ev["index"] = index
            return ev

        events = [_wrap(snapshot)]

        if config.get("send_control_events"):
            diff = snapshot.get("diff_from_previous") or {}
            for entry in diff.get("regressions", []) + diff.get("improvements", []) + diff.get("other_changes", []):
                events.append(_wrap({
                    "event_type": "control_change",
                    "run_id": snapshot.get("run_id"),
                    **entry,
                }))

        return events

    def _send(self, hec_url: str, token: str, events: list[dict], timeout: int) -> None:
        """POST events to Splunk HEC.

        Raises ``NotImplementedError`` until implemented.
        """
        raise NotImplementedError(
            "splunk plugin: _send is not yet implemented."
        )

        # ── Skeleton ──────────────────────────────────────────────────────────
        # # Splunk HEC accepts newline-delimited JSON (batch mode)
        # body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
        # req = urllib.request.Request(
        #     hec_url,
        #     data=body,
        #     method="POST",
        #     headers={
        #         "Authorization": f"Splunk {token}",
        #         "Content-Type": "application/json",
        #     },
        # )
        # with urllib.request.urlopen(req, timeout=timeout) as resp:
        #     if resp.status != 200:
        #         raise RuntimeError(f"Splunk HEC returned HTTP {resp.status}")


registry.register(SplunkPlugin())
