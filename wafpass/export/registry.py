"""Global plugin registry for monitoring/observability export plugins."""

from __future__ import annotations

from typing import Iterator

from wafpass.export.base import ExportPlugin


class ExportPluginRegistry:
    """Registry mapping export plugin names to :class:`~wafpass.export.base.ExportPlugin` instances.

    Usage::

        from wafpass.export.registry import registry

        # Register your plugin (usually done at module level inside the plugin):
        registry.register(MyPlugin())

        # Retrieve a plugin by name:
        plugin = registry.get("grafana")
        result = plugin.export(snapshot, config)
    """

    def __init__(self) -> None:
        self._plugins: dict[str, ExportPlugin] = {}

    def register(self, plugin: ExportPlugin) -> None:
        """Register *plugin* under its ``name``."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ExportPlugin | None:
        """Return the plugin registered under *name*, or ``None``."""
        return self._plugins.get(name)

    def __iter__(self) -> Iterator[ExportPlugin]:
        return iter(self._plugins.values())

    @property
    def available(self) -> list[str]:
        """Sorted list of registered plugin names."""
        return sorted(self._plugins)

    @property
    def descriptions(self) -> dict[str, str]:
        """Map of name → description for all registered plugins."""
        return {p.name: p.description for p in self._plugins.values()}


# Module-level singleton — plugins self-register by importing this and calling
# ``registry.register(…)`` at module scope.
registry = ExportPluginRegistry()
