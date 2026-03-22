"""WAF++ PASS export plugin — Slack incoming webhook.

Posts a WAF++ run summary to a Slack channel via an incoming webhook URL.
The message includes the overall risk score, control counts, score delta,
and a list of regressions (controls that newly failed this run).

Config keys (``exports.slack`` in ``.wafpass-export.yml``)
----------------------------------------------------------
.. code-block:: yaml

    exports:
      slack:
        webhook_url: "${SLACK_WEBHOOK_URL}"  # required
        channel: "#wafpass-alerts"           # optional; overrides webhook default
        only_on_regression: false            # optional; only post when new FAILs appear
        only_on_fail: false                  # optional; only post when total_fail > 0
        timeout: 10                          # optional (default: 10s)

Status: **STUB** — raises ``NotImplementedError`` when called.
Implement ``_send`` to activate this plugin.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from wafpass.export.base import ExportResult
from wafpass.export.registry import registry

_log = logging.getLogger(__name__)


class SlackPlugin:
    """Export plugin that posts WAF++ run summaries to Slack.

    Status: STUB.  Implement ``_send`` to activate.
    """

    name = "slack"
    description = "Post WAF++ run summary to a Slack channel via incoming webhook (stub)."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        webhook_url = config.get("webhook_url") or ""
        if not webhook_url:
            return ExportResult(
                success=False,
                message=(
                    "slack plugin: 'webhook_url' is required. "
                    "Set it under exports.slack in .wafpass-export.yml."
                ),
            )

        totals = snapshot.get("totals", {})
        diff = snapshot.get("diff_from_previous") or {}
        regressions = diff.get("regressions", [])

        # Honour gating flags
        if config.get("only_on_fail") and totals.get("fail", 0) == 0:
            return ExportResult(success=True, message="slack plugin: skipped (no failures, only_on_fail=true).")
        if config.get("only_on_regression") and not regressions:
            return ExportResult(success=True, message="slack plugin: skipped (no regressions, only_on_regression=true).")

        try:
            payload = self._build_payload(snapshot, config)
            self._send(webhook_url, payload, int(config.get("timeout", 10)))
            return ExportResult(success=True, message="Slack notification sent.", details={"webhook_url": webhook_url})
        except NotImplementedError:
            _log.warning(
                "slack plugin is a stub. "
                "Implement _send in wafpass/export/plugins/slack.py to activate."
            )
            return ExportResult(
                success=False,
                message=(
                    "slack plugin is not yet implemented. "
                    "See wafpass/export/plugins/slack.py for the contribution skeleton."
                ),
            )
        except Exception as exc:
            return ExportResult(success=False, message=f"slack plugin error: {exc}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_payload(self, snapshot: dict, config: dict) -> dict:
        """Build a Slack Block Kit message payload."""
        totals = snapshot.get("totals", {})
        score = snapshot.get("score", 0)
        run_id = snapshot.get("run_id", "?")
        iac_plugin = snapshot.get("iac_plugin", "?")
        source = (snapshot.get("source_paths") or ["?"])[0]
        diff = snapshot.get("diff_from_previous") or {}
        score_delta = diff.get("score_delta")
        regressions = diff.get("regressions", [])

        score_emoji = ":white_check_mark:" if score == 0 else (":warning:" if score < 50 else ":red_circle:")
        delta_str = ""
        if score_delta is not None:
            if score_delta > 0:
                delta_str = f"  ↑ +{score_delta} pts (worse)"
            elif score_delta < 0:
                delta_str = f"  ↓ {score_delta} pts (improved)"

        header = f"{score_emoji} *WAF++ PASS — Run `{run_id}`*"
        summary = (
            f"*Score:* {score}/100{delta_str}\n"
            f"*Plugin:* {iac_plugin}  *Source:* `{source}`\n"
            f"✓ PASS: {totals.get('pass', 0)}  "
            f"✗ FAIL: {totals.get('fail', 0)}  "
            f"─ SKIP: {totals.get('skip', 0)}  "
            f"○ WAIVED: {totals.get('waived', 0)}"
        )

        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": "WAF++ PASS Run Summary", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
        ]

        if regressions:
            reg_lines = "\n".join(
                f"• `{r['control_id']}` [{r.get('severity', '?').upper()}] — {r.get('title', '')}"
                for r in regressions[:10]
            )
            if len(regressions) > 10:
                reg_lines += f"\n_…and {len(regressions) - 10} more_"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f":rotating_light: *New regressions:*\n{reg_lines}"}})

        blocks.append({"type": "divider"})

        payload: dict = {"blocks": blocks}
        if config.get("channel"):
            payload["channel"] = config["channel"]
        return payload

    def _send(self, webhook_url: str, payload: dict, timeout: int) -> None:
        """POST payload to Slack.

        Raises ``NotImplementedError`` until implemented.
        """
        raise NotImplementedError(
            "slack plugin: _send is not yet implemented."
        )

        # ── Skeleton ──────────────────────────────────────────────────────────
        # body = json.dumps(payload).encode("utf-8")
        # req = urllib.request.Request(
        #     webhook_url,
        #     data=body,
        #     method="POST",
        #     headers={"Content-Type": "application/json"},
        # )
        # with urllib.request.urlopen(req, timeout=timeout) as resp:
        #     if resp.status != 200:
        #         raise RuntimeError(f"Slack returned HTTP {resp.status}")


registry.register(SlackPlugin())
