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

import json
import logging
from collections import deque
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from rids_detector.alert_manager import AlertManager
from rids_detector.compare import SnapshotComparator, SnapshotValidationError
from rids_detector.models import Alert, Baseline
from rids_detector.rules import evaluate_all_rules

logger = logging.getLogger(__name__)

AlertKey = tuple[str, str | None, str | None, str | None]

# Bound memory growth during long live sessions. Oldest IDs are evicted first.
MAX_PROCESSED_SNAPSHOT_IDS = 10_000


def validate_snapshot(snapshot: Any) -> None:
    """Reject snapshots that cannot be compared safely.

    Accepted shapes:
    - GraphBuilder / SnapshotLogger: optional ``graph`` wrapper with ``nodes``
      and ``edges`` lists (``stats`` is optional).
    - Direct sniffer memory: ``participants`` and ``endpoints``.

    Invalid snapshots raise SnapshotValidationError; the detector logs a warning
    and continues. Transient absences versus the baseline are not validated here
    and do not generate security alerts.
    """
    if not isinstance(snapshot, dict):
        raise SnapshotValidationError(
            f"Snapshot must be a dict, got {type(snapshot).__name__}"
        )

    payload = snapshot.get("graph", snapshot)
    if "graph" in snapshot and not isinstance(snapshot["graph"], dict):
        raise SnapshotValidationError("snapshot['graph'] must be a dictionary")
    if not isinstance(payload, dict):
        raise SnapshotValidationError("Snapshot payload must be a dictionary")

    has_graph = "nodes" in payload or "edges" in payload
    has_direct = "participants" in payload or "endpoints" in payload

    if has_graph:
        nodes = payload.get("nodes", [])
        edges = payload.get("edges", [])
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise SnapshotValidationError("'nodes' and 'edges' must be lists")
        return

    if has_direct:
        participants = payload.get("participants", {})
        endpoints = payload.get("endpoints", {})
        if not isinstance(participants, (dict, list)):
            raise SnapshotValidationError("'participants' must be a dict or list")
        if not isinstance(endpoints, (dict, list)):
            raise SnapshotValidationError("'endpoints' must be a dict or list")

        items: Iterable[Any]
        if isinstance(endpoints, dict):
            items = endpoints.values()
        else:
            items = endpoints

        for index, endpoint in enumerate(items):
            if not isinstance(endpoint, dict):
                raise SnapshotValidationError(
                    f"endpoints[{index}] must be a mapping"
                )
            if "topic" not in endpoint or "role" not in endpoint:
                raise SnapshotValidationError(
                    f"endpoints[{index}] must include 'topic' and 'role'"
                )
            qos = endpoint.get("qos", {})
            if qos is not None and not isinstance(qos, dict):
                raise SnapshotValidationError(
                    f"endpoints[{index}].qos must be a mapping"
                )
        return

    raise SnapshotValidationError(
        "Snapshot must contain nodes/edges or participants/endpoints"
    )


def snapshot_identity(snapshot: dict[str, Any]) -> str | float | None:
    """Stable identity used to skip already processed snapshots.

    ``id`` / ``snapshot_id`` / ``timestamp`` may legitimately be ``0``.
    Snapshots with none of those fields are processed every time they appear.
    """
    if "id" in snapshot:
        return snapshot["id"]
    if "snapshot_id" in snapshot:
        return snapshot["snapshot_id"]
    if "timestamp" in snapshot:
        return snapshot["timestamp"]
    return None


class Detector:
    """Orchestrates snapshot processing, rule evaluation, alert deduplication, and notification.

    ``baseline.critical_topics`` is the stored configuration. ``detector.critical_topics``
    is the effective policy for this run (union of baseline topics and optional extras).
    The Baseline instance is never mutated.

    Missing baseline participants/endpoints/topics are retained in ComparisonResult
    for diagnostics but do not generate security alerts (incomplete discovery is
    common at startup and under packet loss).
    """

    def __init__(
        self,
        baseline: Baseline,
        alert_manager: AlertManager,
        critical_topics: Iterable[str] | None = None,
        rules: list[Callable[..., list[Alert]]] | None = None,
    ) -> None:
        self.baseline = baseline
        self.alert_manager = alert_manager
        self.rules = rules

        extra = set(critical_topics) if critical_topics is not None else set()
        self.critical_topics: tuple[str, ...] = tuple(
            sorted(set(baseline.critical_topics) | extra)
        )

        self.comparator = SnapshotComparator(self.baseline)
        self._active_alert_keys: set[AlertKey] = set()
        self._processed_snapshot_ids: set[str | float] = set()
        self._processed_snapshot_id_order: deque[str | float] = deque()
        self._last_snapshot: dict[str, Any] | None = None

    def process_snapshot(self, snapshot: dict[str, Any]) -> list[Alert]:
        """Validates, compares, evaluates rules, deduplicates, and emits alerts for a snapshot."""
        if not isinstance(snapshot, dict):
            logger.warning(
                "Invalid snapshot skipped: expected dict, got %s", type(snapshot)
            )
            return []

        identity = snapshot_identity(snapshot)
        if identity is not None:
            if identity in self._processed_snapshot_ids:
                logger.debug("Skipping already processed snapshot ID: %s", identity)
                return []
            self._remember_snapshot_id(identity)

        try:
            validate_snapshot(snapshot)
        except SnapshotValidationError as exc:
            logger.warning("Invalid snapshot skipped: %s", exc)
            return []

        try:
            comparison = self.comparator.compare(snapshot)
        except (SnapshotValidationError, TypeError, ValueError, KeyError, AttributeError) as exc:
            logger.warning("Snapshot comparison failed; snapshot ignored: %s", exc)
            return []

        if self.rules:
            raw_alerts: list[Alert] = []
            for rule_func in self.rules:
                raw_alerts.extend(
                    rule_func(
                        self.baseline, snapshot, comparison, self.critical_topics
                    )
                )
        else:
            raw_alerts = evaluate_all_rules(
                self.baseline, snapshot, comparison, self.critical_topics
            )

        new_alerts = self._deduplicate(raw_alerts)

        for alert in new_alerts:
            self.alert_manager.emit(alert)

        self._last_snapshot = snapshot
        return new_alerts

    def process_from_reader(self, reader: SnapshotReader) -> list[Alert]:
        """Read newly available JSONL snapshots and process each in order."""
        emitted: list[Alert] = []
        for snapshot in reader.read_new_snapshots():
            emitted.extend(self.process_snapshot(snapshot))
        return emitted

    def _remember_snapshot_id(self, identity: str | float) -> None:
        self._processed_snapshot_ids.add(identity)
        self._processed_snapshot_id_order.append(identity)
        while len(self._processed_snapshot_id_order) > MAX_PROCESSED_SNAPSHOT_IDS:
            oldest = self._processed_snapshot_id_order.popleft()
            self._processed_snapshot_ids.discard(oldest)

    def _alert_key(self, alert: Alert) -> AlertKey:
        """Generates a unique state key for deduplication."""
        return (
            getattr(alert, "rule", "unknown_rule"),
            getattr(alert, "participant", None),
            getattr(alert, "endpoint", None),
            getattr(alert, "topic", None),
        )

    def _deduplicate(self, current_alerts: list[Alert]) -> list[Alert]:
        """Filters out active anomalies and cleans state when anomalies resolve."""
        current_keys = {self._alert_key(a) for a in current_alerts}
        new_alerts = [
            a for a in current_alerts if self._alert_key(a) not in self._active_alert_keys
        ]
        self._active_alert_keys = current_keys
        return new_alerts

    def reset(self) -> None:
        """Resets all internal tracking state."""
        self._active_alert_keys.clear()
        self._processed_snapshot_ids.clear()
        self._processed_snapshot_id_order.clear()
        self._last_snapshot = None


class SnapshotReader:
    """Incremental reader for growing JSONL snapshot files.

    Incomplete trailing lines are left unread until they are completed.
    Empty lines and malformed JSON are skipped. JSON values that are not
    objects are skipped. If the file is truncated or rotated so that its
    size is smaller than the last read position, the reader restarts at
    offset 0.
    """

    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)
        self._file_pos = 0

    def read_new_snapshots(self) -> list[dict[str, Any]]:
        """Reads and parses new complete JSON lines from the snapshot file."""
        if not self.file_path.exists():
            return []

        size = self.file_path.stat().st_size
        if size < self._file_pos:
            logger.warning(
                "Snapshot file %s was truncated or rotated; resetting read position",
                self.file_path,
            )
            self._file_pos = 0

        snapshots: list[dict[str, Any]] = []

        with open(self.file_path, encoding="utf-8") as handle:
            handle.seek(self._file_pos)

            while True:
                line_start = handle.tell()
                line = handle.readline()

                if not line:
                    break

                if not line.endswith("\n") and not line.endswith("\r\n"):
                    handle.seek(line_start)
                    break

                self._file_pos = handle.tell()
                line_str = line.strip()

                if not line_str:
                    continue

                try:
                    data = json.loads(line_str)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed JSON line in %s", self.file_path)
                    continue

                if isinstance(data, dict):
                    snapshots.append(data)
                else:
                    logger.warning(
                        "Skipping non-object JSON value in %s", self.file_path
                    )

        return snapshots

