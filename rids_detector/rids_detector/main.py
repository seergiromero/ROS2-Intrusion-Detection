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

import argparse
import logging
import signal
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from rids_detector.alert_manager import AlertManager
from rids_detector.baseline import BaselineLoader
from rids_detector.detector import Detector, SnapshotReader

logger = logging.getLogger("rids_detector")


def _config_value(config: dict[str, Any], section: str, name: str, default: Any) -> Any:
    values = config.get(section, {})
    if not isinstance(values, dict):
        raise TypeError(f"Configuration section '{section}' must be a mapping")
    return values.get(name, default)


def _parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    normalized = value.lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare RTPS graph snapshots against a baseline and emit alerts."
    )
    parser.add_argument("--config", help="Global RIDS YAML configuration")
    parser.add_argument("--baseline", help="Override baseline YAML path")
    parser.add_argument("--snapshots", help="Override snapshots JSONL path")
    parser.add_argument(
        "--alerts",
        help="Override alerts JSONL path",
    )
    parser.add_argument(
        "--mode",
        choices=("once", "live"),
        help="Override detector mode",
    )
    parser.add_argument("--poll-interval", type=float, help="Override live polling interval")
    parser.add_argument(
        "--critical-topic",
        action="append",
        dest="critical_topics",
        default=None,
        help="Extra critical topic for this run (repeatable)",
    )
    parser.add_argument(
        "--no-console",
        nargs="?",
        const=True,
        default=None,
        type=_parse_bool,
        help="Disable console logging of alerts",
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config).expanduser().resolve() if args.config else Path("config/rids.yaml").resolve()
    config: dict[str, Any] = {}
    if config_path.is_file():
        with config_path.open("r", encoding="utf-8") as stream:
            loaded = yaml.safe_load(stream)
        if not isinstance(loaded, dict):
            parser.error("Runtime configuration must be a YAML mapping")
        config = loaded

    def resolve(value: str | None, section: str, name: str, default: str) -> Path:
        if value:
            path = Path(value).expanduser()
            return path.resolve()

        selected = _config_value(config, section, name, default)
        path = Path(selected)
        return path if path.is_absolute() else config_path.parent / path

    baseline_path = resolve(args.baseline, "security", "baseline", "config/baseline.yaml")
    snapshots_path = resolve(args.snapshots, "paths", "snapshots", "results/phase1/snapshots.jsonl")
    alerts_path = resolve(args.alerts, "paths", "alerts", "results/phase2/alerts.jsonl")
    mode = args.mode or _config_value(config, "detector", "mode", "live")
    poll_interval = args.poll_interval
    if poll_interval is None:
        poll_interval = float(_config_value(config, "detector", "poll_interval", 0.5))
    console = _config_value(config, "detector", "console", True)
    if args.no_console is not None:
        console = not args.no_console
    critical_topics = args.critical_topics or _config_value(config, "security", "critical_topics", None)

    if poll_interval <= 0:
        parser.error("poll interval must be greater than zero")

    baseline = BaselineLoader().load(baseline_path)
    reader = SnapshotReader(snapshots_path)

    with AlertManager(
        output_path=alerts_path,
        console_output=bool(console),
    ) as manager:
        detector = Detector(
            baseline=baseline,
            alert_manager=manager,
            critical_topics=critical_topics,
        )

        if mode == "once":
            emitted = detector.process_from_reader(reader)
            logger.info("Processed snapshots in once mode; emitted %s new alerts", len(emitted))
            return 0

        logger.info("Detector running in live mode on %s", snapshots_path)
        stop_event = threading.Event()

        def request_shutdown(signum: int, frame: Any) -> None:
            stop_event.set()

        previous_sigint = signal.getsignal(signal.SIGINT)
        previous_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)
        try:
            while not stop_event.is_set():
                detector.process_from_reader(reader)
                stop_event.wait(max(poll_interval, 0.05))
        finally:
            signal.signal(signal.SIGINT, previous_sigint)
            signal.signal(signal.SIGTERM, previous_sigterm)
        return 0


if __name__ == "__main__":
    main()