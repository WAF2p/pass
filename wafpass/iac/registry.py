"""Global plugin registry for IaC parsers."""

from __future__ import annotations

from typing import Iterator

from wafpass.iac.base import IaCPlugin


class PluginRegistry:
    """Registry mapping plugin names to :class:`~wafpass.iac.base.IaCPlugin` instances.

    Usage::

        from wafpass.iac.registry import registry

        # Register your plugin (usually done at module level inside the plugin):
        registry.register(MyPlugin())

        # Retrieve a plugin by name:
        plugin = registry.get("terraform")
        state = plugin.parse(path)
    """

    def __init__(self) -> None:
        self._plugins: dict[str, IaCPlugin] = {}

    def register(self, plugin: IaCPlugin) -> None:
        """Register *plugin* under its ``name``."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> IaCPlugin | None:
        """Return the plugin registered under *name*, or ``None``."""
        return self._plugins.get(name)

    def __iter__(self) -> Iterator[IaCPlugin]:
        return iter(self._plugins.values())

    @property
    def available(self) -> list[str]:
        """Sorted list of registered plugin names."""
        return sorted(self._plugins)


# Module-level singleton — plugins self-register by importing this and calling
# ``registry.register(…)`` at module scope.
registry = PluginRegistry()
