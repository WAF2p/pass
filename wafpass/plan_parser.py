"""Parse ``terraform show -json <plan>`` output into a compact change summary.

The canonical way to produce the input file is::

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    wafpass check --plan-file plan.json ...

The parser also tolerates the streaming log format produced by
``terraform plan -json`` (newline-delimited JSON objects) by picking up
every ``change_summary`` event and ``planned_change`` action events.

The normalised output schema is::

    {
      "terraform_version": "1.7.0",
      "format_version":    "1.2",
      "scanned_at":        "2026-03-28T12:00:00Z",
      "summary": {
        "add":     3,
        "change":  2,
        "destroy": 0,
        "replace": 1,
        "no_op":   45
      },
      "changes": [
        {
          "address":        "aws_s3_bucket.logs",
          "module_address": null,
          "type":           "aws_s3_bucket",
          "name":           "logs",
          "provider":       "aws",
          "action":         "create"   // create | update | delete | replace | no-op
        }
      ]
    }
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_ACTION_MAP: dict[tuple[str, ...], str] = {
    ("no-op",):           "no-op",
    ("create",):          "create",
    ("update",):          "update",
    ("delete",):          "delete",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}


def _normalise_actions(actions: list[str]) -> str:
    key = tuple(a.lower() for a in actions)
    return _ACTION_MAP.get(key, actions[0] if actions else "unknown")


def _provider_short(provider_name: str) -> str:
    """'registry.terraform.io/hashicorp/aws' → 'aws'"""
    return provider_name.rstrip("/").rsplit("/", 1)[-1] if provider_name else ""


def _parse_structured(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a ``terraform show -json`` structured plan object."""
    changes: list[dict[str, Any]] = []
    summary: dict[str, int] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}

    for rc in data.get("resource_changes", []):
        change = rc.get("change", {})
        actions: list[str] = change.get("actions", ["no-op"])
        action = _normalise_actions(actions)

        entry: dict[str, Any] = {
            "address":        rc.get("address", ""),
            "module_address": rc.get("module_address"),
            "type":           rc.get("type", ""),
            "name":           rc.get("name", ""),
            "provider":       _provider_short(rc.get("provider_name", "")),
            "action":         action,
        }
        changes.append(entry)

        if action == "no-op":
            summary["no_op"] += 1
        elif action == "create":
            summary["add"] += 1
        elif action == "update":
            summary["change"] += 1
        elif action == "delete":
            summary["destroy"] += 1
        elif action == "replace":
            summary["replace"] += 1

    return {
        "terraform_version": data.get("terraform_version", ""),
        "format_version":    data.get("format_version", ""),
        "scanned_at":        datetime.now(timezone.utc).isoformat(),
        "summary":           summary,
        "changes":           [c for c in changes if c["action"] != "no-op"],
    }


def _parse_streaming(lines: list[str]) -> dict[str, Any]:
    """Parse newline-delimited JSON produced by ``terraform plan -json``."""
    changes: list[dict[str, Any]] = []
    summary: dict[str, int] = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "no_op": 0}
    tf_version = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_type = obj.get("type", "")

        if msg_type == "version":
            tf_version = obj.get("terraform", "")

        elif msg_type == "planned_change":
            change = obj.get("change", {})
            action = change.get("action", "no-op").lower()
            resource = change.get("resource", {})
            addr = resource.get("addr", "")
            res_type = resource.get("resource_type", "")
            res_name = resource.get("resource_name", "")
            module = resource.get("module", "")

            # Map streaming action strings to normalised names
            action_map = {
                "no-op":   "no-op",
                "add":     "create",
                "change":  "update",
                "remove":  "delete",
                "replace": "replace",
            }
            normalised = action_map.get(action, action)

            entry: dict[str, Any] = {
                "address":        addr,
                "module_address": module or None,
                "type":           res_type,
                "name":           res_name,
                "provider":       "",
                "action":         normalised,
            }
            changes.append(entry)

            if normalised == "no-op":
                summary["no_op"] += 1
            elif normalised == "create":
                summary["add"] += 1
            elif normalised == "update":
                summary["change"] += 1
            elif normalised == "delete":
                summary["destroy"] += 1
            elif normalised == "replace":
                summary["replace"] += 1

    return {
        "terraform_version": tf_version,
        "format_version":    "streaming",
        "scanned_at":        datetime.now(timezone.utc).isoformat(),
        "summary":           summary,
        "changes":           [c for c in changes if c["action"] != "no-op"],
    }


def parse_plan_file(path: Path) -> dict[str, Any]:
    """Parse a terraform plan JSON file and return a normalised change summary.

    Accepts both:
    - ``terraform show -json <plan>``  → single structured JSON object
    - ``terraform plan -json``         → newline-delimited JSON stream
    """
    raw = path.read_text(encoding="utf-8")

    # Try single structured JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and ("resource_changes" in data or "format_version" in data):
            return _parse_structured(data)
    except json.JSONDecodeError:
        pass

    # Fall back to streaming format
    return _parse_streaming(raw.splitlines())
