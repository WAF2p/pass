"""WAF++ PASS monitoring/observability export plugin system.

Import the registry and plugins via::

    from wafpass.export import registry
    from wafpass.export.plugins import grafana, webhook  # triggers self-registration

Or import the whole package to auto-register all bundled plugins::

    import wafpass.export.plugins  # noqa: F401
"""
