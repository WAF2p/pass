"""WAF++ PASS export plugin — Prometheus Pushgateway (standalone).

Pushes WAF++ run metrics directly to a Prometheus Pushgateway in
Prometheus text exposition format.  This plugin is functionally identical
to the ``grafana`` plugin but is provided as a distinct target for teams
that run Prometheus without Grafana, or who want separate Pushgateway
job groupings for each system.

Config keys (``exports.prometheus`` in ``.wafpass-export.yml``)
--------------------------------------------------------------
.. code-block:: yaml

    exports:
      prometheus:
        pushgateway_url: "http://pushgateway.monitoring.svc:9091"  # required
        job: "wafpass"           # optional (default: wafpass)
        instance: ""             # optional (default: run_id)
        timeout: 10              # optional (default: 10s)

Status: **STUB** — delegates to the grafana plugin implementation.
To complete: adjust metric names / labels as needed for your Prometheus
naming conventions, then replace the delegation with direct HTTP code.
"""

from __future__ import annotations

import logging

from wafpass.export.base import ExportResult
from wafpass.export.registry import registry

_log = logging.getLogger(__name__)


class PrometheusPlugin:
    """Export plugin for standalone Prometheus Pushgateway targets.

    Currently a thin wrapper around the Grafana plugin's Pushgateway logic.
    Extend this class to add Prometheus-specific metric naming or label
    conventions without touching the Grafana plugin.
    """

    name = "prometheus"
    description = "Push WAF++ run metrics to a Prometheus Pushgateway (standalone)."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        _log.warning(
            "prometheus plugin: this is a stub that delegates to the grafana "
            "Pushgateway implementation.  Customise wafpass/export/plugins/prometheus.py "
            "to add Prometheus-specific metric names or label conventions."
        )
        # Delegate to the grafana plugin which already implements Pushgateway push.
        from wafpass.export.plugins.grafana import GrafanaPlugin

        return GrafanaPlugin().export(snapshot, config)


registry.register(PrometheusPlugin())
