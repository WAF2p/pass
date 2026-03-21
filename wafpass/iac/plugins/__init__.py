"""IaC plugins for WAF++ PASS.

Importing this package triggers all plugin self-registrations so that the
global registry is fully populated.  Add new plugins here by importing them.
"""

from wafpass.iac.plugins import bicep, cdk, pulumi, terraform  # noqa: F401

__all__ = ["terraform", "bicep", "cdk", "pulumi"]
