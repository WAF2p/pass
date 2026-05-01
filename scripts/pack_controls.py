#!/usr/bin/env python3
"""Pack the current controls directory into a versioned release folder.

Usage:
    python scripts/pack_controls.py v1.2.0 "Added NIS2 and eIDAS 2.0 controls"
    python scripts/pack_controls.py v1.2.0   # no description is fine

This creates:
    controls-releases/v1.2.0/
        manifest.json          ← version metadata
        WAF-*.yml              ← copy of all active control files

After packing, point WAFPASS_CONTROLS_DIR at the new release directory on the
server and call POST /control-packs/sync with the same version string — or
keep WAFPASS_CONTROLS_DIR pointing at the latest `controls/` directory and just
use the sync endpoint directly.
"""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    controls_dir = repo_root / "controls"
    releases_dir = repo_root / "controls-releases"

    if len(sys.argv) < 2:
        print("Usage: python scripts/pack_controls.py <version> [description]", file=sys.stderr)
        print("Example: python scripts/pack_controls.py v1.2.0 'Added NIS2 controls'", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1].strip()
    description = sys.argv[2].strip() if len(sys.argv) > 2 else ""

    if not version:
        print("Error: version string is empty.", file=sys.stderr)
        sys.exit(1)

    release_dir = releases_dir / version
    if release_dir.exists():
        print(f"Error: release directory '{release_dir}' already exists.", file=sys.stderr)
        sys.exit(1)

    if not controls_dir.is_dir():
        print(f"Error: controls directory '{controls_dir}' not found.", file=sys.stderr)
        sys.exit(1)

    yml_files = sorted(controls_dir.glob("*.yml"))
    if not yml_files:
        print(f"Error: no *.yml files found in '{controls_dir}'.", file=sys.stderr)
        sys.exit(1)

    release_dir.mkdir(parents=True)

    for yml_file in yml_files:
        shutil.copy2(yml_file, release_dir / yml_file.name)

    manifest = {
        "version": version,
        "description": description,
        "control_count": len(yml_files),
        "released_at": datetime.now(timezone.utc).isoformat(),
        "controls": [f.name for f in yml_files],
    }
    (release_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    print(f"✓ Packed {len(yml_files)} controls into {release_dir}")
    print(f"  version:     {version}")
    if description:
        print(f"  description: {description}")
    print()
    print("Next steps:")
    print(f"  1. git add controls-releases/{version} && git commit -m 'chore: release control pack {version}'")
    print(f"  2. On the server, set WAFPASS_CONTROLS_DIR to point at this release directory,")
    print(f"     or copy the YAML files there.")
    print(f"  3. In the dashboard → Admin → Controls Upgrade, sync version '{version}'.")


if __name__ == "__main__":
    main()
