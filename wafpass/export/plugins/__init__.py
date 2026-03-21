"""Auto-import all monitoring export plugins so they self-register.

Add a new import here after creating a plugin file in this directory.
"""

from wafpass.export.plugins import grafana  # noqa: F401
from wafpass.export.plugins import prometheus  # noqa: F401
from wafpass.export.plugins import datadog  # noqa: F401
from wafpass.export.plugins import splunk  # noqa: F401
from wafpass.export.plugins import slack  # noqa: F401
from wafpass.export.plugins import webhook  # noqa: F401
