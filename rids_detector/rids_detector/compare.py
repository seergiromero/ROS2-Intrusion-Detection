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

from dataclasses import dataclass, field
from typing import Any

if __package__:
    from .models import Baseline, BaselineEndpoint, ObservedEndpoint
else:
    from models import Baseline, BaselineEndpoint, ObservedEndpoint


class SnapshotValidationError(ValueError):
    """Raised when an observed snapshot structure fails validation."""
    pass

@dataclass(frozen=True)
class QoSChange:
    guid: str
    topic: str
    participant: str | None
    observed_qos: dict[str, str]
    expected_qos: dict[str, str]


@dataclass(frozen=True)
class TypeChange:
    guid: str
    topic: str
    participant: str | None
    observed_type: str
    expected_type: str


@dataclass(frozen=True)
class RoleChange:
    guid: str
    topic: str
    participant: str | None
    observed_role: str
    expected_role: str


@dataclass
class ComparisonResult:
    new_participants: set[str] = field(default_factory=set)
    removed_participants: set[str] = field(default_factory=set)
    new_endpoints: list[ObservedEndpoint] = field(default_factory=list)
    removed_endpoints: list[BaselineEndpoint] = field(default_factory=list)
    qos_changes: list[QoSChange] = field(default_factory=list)
    type_changes: list[TypeChange] = field(default_factory=list)
    role_changes: list[RoleChange] = field(default_factory=list)
    new_topics: set[str] = field(default_factory=set)
    removed_topics: set[str] = field(default_factory=set)

    def has_differences(self, include_missing: bool = False) -> bool:
        """
        Returns True if structural or attribute differences were detected.

        Args:
            include_missing: If True, flags missing elements (participants, endpoints,
                             topics) as differences. Defaults to False to avoid false
                             positives caused by transient startup or packet loss.
        """
        has_active_anomalies = bool(
            self.new_participants
            or self.new_endpoints
            or self.qos_changes
            or self.type_changes
            or self.role_changes
            or self.new_topics
        )
        if not include_missing:
            return has_active_anomalies

        return has_active_anomalies or bool(
            self.removed_participants or self.removed_endpoints or self.removed_topics
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes the comparison result to a standard dictionary format."""
        return {
            "has_differences": self.has_differences(),
            "has_missing_elements": bool(
                self.removed_participants or self.removed_endpoints or self.removed_topics
            ),
            "new_participants": sorted(self.new_participants),
            "removed_participants": sorted(self.removed_participants),
            "new_endpoints": [ep.to_dict() for ep in self.new_endpoints],
            "removed_endpoints": [ep.to_dict() for ep in self.removed_endpoints],
            "qos_changes": [
                {
                    "guid": c.guid,
                    "topic": c.topic,
                    "participant": c.participant,
                    "observed": c.observed_qos,
                    "expected": c.expected_qos,
                }
                for c in self.qos_changes
            ],
            "type_changes": [
                {
                    "guid": c.guid,
                    "topic": c.topic,
                    "participant": c.participant,
                    "observed": c.observed_type,
                    "expected": c.expected_type,
                }
                for c in self.type_changes
            ],
            "role_changes": [
                {
                    "guid": c.guid,
                    "topic": c.topic,
                    "participant": c.participant,
                    "observed": c.observed_role,
                    "expected": c.expected_role,
                }
                for c in self.role_changes
            ],
            "new_topics": sorted(self.new_topics),
            "removed_topics": sorted(self.removed_topics),
        }


class SnapshotComparator:
    """
    Compares observed RTPS snapshots or real-time graph states against a reference Baseline.
    """

    def __init__(self, baseline: Baseline) -> None:
        self.baseline = baseline

        # Indexing for O(1) lookups
        self.baseline_participants: set[str] = set(baseline.participants)
        self.baseline_endpoints_by_guid: dict[str, BaselineEndpoint] = {
            ep.guid: ep for ep in baseline.endpoints
        }
        self.baseline_topics: set[str] = {ep.topic for ep in baseline.endpoints}

    def compare(self, snapshot: dict[str, Any]) -> ComparisonResult:
        """
        Computes the structural delta between the baseline and the provided snapshot.
        """
        result = ComparisonResult()

        observed_participants, observed_endpoints = self._normalize_snapshot(snapshot)
        observed_topics = {
            ep.topic for ep in observed_endpoints.values() if ep.topic
        }

        result.new_participants = observed_participants - self.baseline_participants
        result.removed_participants = self.baseline_participants - observed_participants

        result.new_topics = observed_topics - self.baseline_topics
        result.removed_topics = self.baseline_topics - observed_topics

        for guid, ep in observed_endpoints.items():
            if guid not in self.baseline_endpoints_by_guid:
                result.new_endpoints.append(ep)
                continue

            baseline_ep = self.baseline_endpoints_by_guid[guid]
            participant = ep.participant
            topic = ep.topic or baseline_ep.topic

            if ep.role and ep.role != baseline_ep.role:
                result.role_changes.append(
                    RoleChange(
                        guid=guid,
                        topic=topic,
                        participant=participant,
                        observed_role=ep.role,
                        expected_role=baseline_ep.role,
                    )
                )

            if ep.type_name and ep.type_name != baseline_ep.type_name:
                result.type_changes.append(
                    TypeChange(
                        guid=guid,
                        topic=topic,
                        participant=participant,
                        observed_type=ep.type_name,
                        expected_type=baseline_ep.type_name,
                    )
                )

            if ep.qos:
                expected_qos = dict(baseline_ep.qos)
                if not self._are_qos_matching(ep.qos, expected_qos):
                    result.qos_changes.append(
                        QoSChange(
                            guid=guid,
                            topic=topic,
                            participant=participant,
                            observed_qos=ep.qos,
                            expected_qos=expected_qos,
                        )
                    )

        for guid, baseline_ep in self.baseline_endpoints_by_guid.items():
            if guid not in observed_endpoints:
                result.removed_endpoints.append(baseline_ep)

        return result

    def _normalize_snapshot(
        self, snapshot: dict[str, Any]
    ) -> tuple[set[str], dict[str, ObservedEndpoint]]:
        """
        Validates and normalizes snapshots from GraphBuilder (nodes & edges)
        or direct sniffer memory dicts (participants & endpoints).
        """
        if not isinstance(snapshot, dict):
            raise SnapshotValidationError("Snapshot must be a dictionary mapping")

        graph = snapshot.get("graph", snapshot)
        if not isinstance(graph, dict):
            raise SnapshotValidationError("Snapshot payload/graph must be a dictionary")

        observed_participants: set[str] = set()
        observed_endpoints: dict[str, ObservedEndpoint] = {}

        # Format A: Graph structure with nodes and edges
        if "nodes" in graph or "edges" in graph:
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])

            if not isinstance(nodes, list) or not isinstance(edges, list):
                raise SnapshotValidationError(
                    "'nodes' and 'edges' in snapshot graph must be lists"
                )

            for node in nodes:
                if isinstance(node, dict) and node.get("node_type") == "participant":
                    raw_id = str(node.get("id", ""))
                    guid_prefix = raw_id.replace("participant:", "").strip()
                    if guid_prefix:
                        observed_participants.add(guid_prefix)

            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                guid = edge.get("guid") or edge.get("key")
                if not guid or not isinstance(guid, str):
                    continue

                src = str(edge.get("source", ""))
                dst = str(edge.get("target", ""))

                topic = ""
                participant = None

                if src.startswith("topic:"):
                    topic = src.replace("topic:", "", 1).strip()
                    if dst.startswith("participant:"):
                        participant = dst.replace("participant:", "", 1).strip() or None
                elif dst.startswith("topic:"):
                    topic = dst.replace("topic:", "", 1).strip()
                    if src.startswith("participant:"):
                        participant = src.replace("participant:", "", 1).strip() or None

                qos = edge.get("qos")
                qos_dict = dict(qos) if isinstance(qos, dict) else {}
                type_name = edge.get("type_name") or edge.get("type")

                observed_endpoints[guid] = ObservedEndpoint(
                    guid=guid.strip(),
                    participant=participant,
                    topic=topic,
                    role=str(edge.get("role")).strip() if edge.get("role") else None,
                    type_name=str(type_name).strip() if type_name else None,
                    qos={str(k): str(v) for k, v in qos_dict.items()},
                )
            return observed_participants, observed_endpoints

        # Format B: Direct dictionary with participants and endpoints.
        raw_participants = graph.get("participants", {})
        if isinstance(raw_participants, dict):
            observed_participants = {str(p) for p in raw_participants}
        elif isinstance(raw_participants, list):
            observed_participants = {str(p) for p in raw_participants}

        raw_endpoints = graph.get("endpoints", {})
        if isinstance(raw_endpoints, dict):
            endpoint_items = raw_endpoints.items()
        elif isinstance(raw_endpoints, list):
            endpoint_items = (
                (ep.get("guid"), ep) for ep in raw_endpoints if isinstance(ep, dict)
            )
        else:
            endpoint_items = ()

        if raw_endpoints:
            for guid, ep_data in endpoint_items:
                if not isinstance(ep_data, dict):
                    continue
                guid_str = str(guid or ep_data.get("guid") or "").strip()
                if not guid_str:
                    continue
                participant = ep_data.get("participant") or ep_data.get("guid_prefix")
                qos = ep_data.get("qos")
                qos_dict = dict(qos) if isinstance(qos, dict) else {}
                type_name = ep_data.get("type_name") or ep_data.get("type")

                observed_endpoints[guid_str] = ObservedEndpoint(
                    guid=guid_str,
                    participant=str(participant).strip() if participant else None,
                    topic=str(ep_data.get("topic", "")).strip(),
                    role=str(ep_data.get("role")).strip() if ep_data.get("role") else None,
                    type_name=str(type_name).strip() if type_name else None,
                    qos={str(k): str(v) for k, v in qos_dict.items()},
                )

        return observed_participants, observed_endpoints

    @staticmethod
    def _are_qos_matching(observed: dict[str, str], expected: dict[str, str]) -> bool:
        """
        Verifies if observed QoS attributes meet expected baseline parameters.

        Note:
            Uses subset matching: every policy defined in `expected` must be present
            and equal in `observed`. Extra keys in `observed` are ignored to prevent
            false positives caused by middleware default values.
        """
        for key, expected_value in expected.items():
            if observed.get(key) != expected_value:
                return False
        return True