#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2026 Sergi Romero Valderas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _yaml_value(config_path: Path, section: str, name: str, default: str) -> str:
    try:
        import yaml
        with config_path.open("r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
    except (OSError, ImportError):
        return default
    if not isinstance(data, dict):
        return default
    section_data = data.get(section, {})
    if not isinstance(section_data, dict):
        return default
    value = section_data.get(name, default)
    return str(value) if value is not None else default


def _resolve(value: str, config_dir: Path) -> Path:
    p = Path(value)
    if p.is_absolute():
        return p
    return (config_dir / p).resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="clear_results",
        description="Truncate or remove the RIDS runtime result files.",
    )
    parser.add_argument(
        "--config",
        default="config/rids.yaml",
        help="Path to the RIDS YAML (used to locate the result files).",
    )
    parser.add_argument(
        "--snapshots-only",
        action="store_true",
        help="Only clear the snapshots file (leave alerts untouched).",
    )
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Only clear the alerts file (leave snapshots untouched).",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Delete the files entirely instead of truncating them.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done, but don't touch the filesystem.",
    )
    args = parser.parse_args(argv)

    if args.snapshots_only and args.alerts_only:
        parser.error("--snapshots-only and --alerts-only are mutually exclusive")

    config_path = Path(args.config).expanduser().resolve()
    config_dir = config_path.parent

    snapshots = _resolve(
        _yaml_value(config_path, "paths", "snapshots", "results/phase1/snapshots.jsonl"),
        config_dir,
    )
    alerts = _resolve(
        _yaml_value(config_path, "paths", "alerts", "results/phase2/alerts.jsonl"),
        config_dir,
    )

    targets: list[tuple[str, Path]] = []
    if not args.alerts_only:
        targets.append(("snapshots", snapshots))
    if not args.snapshots_only:
        targets.append(("alerts", alerts))

    for label, path in targets:
        if not path.exists():
            print(f"[clear_results] {label}: {path} (missing, nothing to do)")
            continue
        action = "remove" if args.remove else "truncate"
        if args.dry_run:
            print(f"[clear_results] {label}: would {action} {path}")
            continue
        if args.remove:
            path.unlink()
            print(f"[clear_results] {label}: removed {path}")
        else:
            with path.open("w", encoding="utf-8"):
                pass
            print(f"[clear_results] {label}: truncated {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
