"""WAF++ PASS IaC plugin system.

This package provides the framework-agnostic IaC abstraction layer:

- :class:`~wafpass.iac.base.IaCBlock` — a single parsed IaC construct
- :class:`~wafpass.iac.base.IaCState` — aggregated state from all parsed files
- :class:`~wafpass.iac.base.IaCPlugin` — protocol every plugin must satisfy
- :data:`~wafpass.iac.registry.registry` — global plugin registry

Importing this package also imports all bundled plugins so they are
registered automatically::

    from wafpass.iac import registry
    plugin = registry.get("terraform")   # always available after this import
"""

from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState
from wafpass.iac.registry import registry

# Trigger plugin self-registrations
import wafpass.iac.plugins  # noqa: F401, E402

__all__ = [
    "IaCBlock",
    "IaCState",
    "IaCPlugin",
    "registry",
]
