from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("wafpass")
except PackageNotFoundError:
    __version__ = "0.1.0-dev"

__name_full__ = "WAF++ PASS"
