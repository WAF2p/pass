"""Configuration loader for WAF++ PASS export plugins.

Export plugin configuration lives in a YAML file (default: ``.wafpass-export.yml``).
String values may contain ``${ENV_VAR}`` placeholders that are expanded from the
environment at load time so that secrets stay out of version control.

File format
-----------
.. code-block:: yaml

    exports:
      grafana:
        pushgateway_url: "http://pushgateway.monitoring.svc:9091"
        job: "wafpass"
        instance: "my-project"

      webhook:
        url: "https://my-webhook.example.com/wafpass"
        headers:
          Authorization: "Bearer ${WEBHOOK_TOKEN}"

      datadog:
        api_key: "${DD_API_KEY}"
        site: "datadoghq.eu"

      splunk:
        hec_url: "https://splunk.example.com:8088/services/collector"
        token: "${SPLUNK_HEC_TOKEN}"
        index: "main"

      slack:
        webhook_url: "${SLACK_WEBHOOK_URL}"
        only_on_regression: true

The ``exports`` key is required; plugin-specific sub-keys are validated by each
plugin's own ``export()`` method.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_ENV_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")

DEFAULT_EXPORT_CONFIG = Path(".wafpass-export.yml")


def _expand_env(value: object) -> object:
    """Recursively expand ``${VAR}`` placeholders in string values."""
    if isinstance(value, str):
        def _sub(m: re.Match) -> str:
            var = m.group(1)
            result = os.environ.get(var)
            if result is None:
                raise ValueError(
                    f"Environment variable '{var}' referenced in export config is not set."
                )
            return result

        return _ENV_PLACEHOLDER.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    return value


def load_export_config(path: Path) -> dict[str, dict]:
    """Load and return the ``exports`` section of a YAML export config file.

    Returns a dict mapping plugin name → plugin config dict.
    Raises ``ValueError`` for malformed files or missing env vars.
    Raises ``FileNotFoundError`` when *path* does not exist.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "Export config loading requires PyYAML. Install with: pip install pyyaml"
        ) from exc

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Export config '{path}' must be a YAML mapping at the top level.")

    exports_raw = raw.get("exports")
    if not isinstance(exports_raw, dict):
        raise ValueError(
            f"Export config '{path}' must contain an 'exports:' mapping. "
            "See the README for the expected format."
        )

    try:
        expanded = _expand_env(exports_raw)
    except ValueError as exc:
        raise ValueError(f"Export config '{path}': {exc}") from exc

    return expanded  # type: ignore[return-value]
