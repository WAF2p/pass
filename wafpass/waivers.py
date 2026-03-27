"""Intentional waiver/skip support for WAF++ PASS.

A waiver file is a YAML document that lists WAF++ control IDs the team has
consciously decided to accept risk for, together with a mandatory justification
and an optional expiry date.

Example (.wafpass-skip.yml):

    waivers:
      - id: WAF-SEC-020
        reason: "Covered by external quarterly IAM review — ticket SEC-1234"
        expires: "2026-09-30"
      - id: WAF-COST-010
        reason: "Cost tagging enforced at Terraform module level, not resource level"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Conventional default filename; auto-discovered when --skip-file is not given
DEFAULT_SKIP_FILE = ".wafpass-skip.yml"


@dataclass
class WaiverEntry:
    """A single intentional waiver for a WAF++ control."""

    id: str
    reason: str
    expires: date | None = None

    @property
    def is_expired(self) -> bool:
        return self.expires is not None and self.expires < date.today()


def load_waivers(path: Path) -> list[WaiverEntry]:
    """Load waivers from a YAML file.

    The file must contain a top-level ``waivers:`` (or legacy ``skips:``) list.
    Each entry requires an ``id`` and a ``reason``; ``expires`` is optional
    (ISO-8601 date string, e.g. ``"2026-12-31"``).

    Raises:
        ValueError: if the file cannot be parsed or has unexpected structure.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Cannot read waiver file '{path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"Waiver file '{path}' must be a YAML mapping")

    entries = raw.get("waivers") or raw.get("skips") or []
    if not isinstance(entries, list):
        raise ValueError(f"'waivers' key in '{path}' must be a list")

    result: list[WaiverEntry] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        control_id = str(item.get("id", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if not control_id:
            logger.warning("Waiver entry missing 'id', skipping: %s", item)
            continue
        if not reason:
            logger.warning("Waiver for %s has no 'reason'", control_id)
            reason = "(no reason provided)"

        expires_raw = item.get("expires")
        expires: date | None = None
        if expires_raw:
            try:
                expires = expires_raw if isinstance(expires_raw, date) else date.fromisoformat(str(expires_raw))
            except ValueError:
                logger.warning("Invalid expires date for %s: '%s'", control_id, expires_raw)

        result.append(WaiverEntry(id=control_id, reason=reason, expires=expires))

    return result


def apply_waivers(results: list, waivers: list[WaiverEntry]) -> list[WaiverEntry]:
    """Apply waivers to control results in-place.

    Matches waivers by control ID (case-insensitive) and sets
    ``cr.waived_reason`` on matching ControlResult objects.

    Returns the list of expired waivers so the caller can warn the user.
    """
    waiver_map = {w.id.upper(): w for w in waivers}
    expired: list[WaiverEntry] = []

    for cr in results:
        waiver = waiver_map.get(cr.control.id.upper())
        if waiver is None:
            continue
        if waiver.is_expired:
            expired.append(waiver)
        cr.waived_reason = waiver.reason
        cr.waived_expires = waiver.expires

    return expired
