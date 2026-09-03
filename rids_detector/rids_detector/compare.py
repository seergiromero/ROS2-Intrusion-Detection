from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

if __package__:
    from .models import Baseline, BaselineEndpoint
else:
    from models import Baseline, BaselineEndpoint


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
    new_endpoints: list[dict[str, Any]] = field(default_factory=list)
    removed_endpoints: list[BaselineEndpoint] = field(default_factory=list)
    qos_changes: list[QoSChange] = field(default_factory=list)
    type_changes: list[TypeChange] = field(default_factory=list)
    role_changes: list[RoleChange] = field(default_factory=list)
    new_topics: set[str] = field(default_factory=set)
    removed_topics: set[str] = field(default_factory=set)

    def has_differences(self) -> bool:
        """Returns True if any structural or attribute difference was detected."""
        
        return bool(
            self.new_participants
            or self.removed_participants
            or self.new_endpoints
            or self.removed_endpoints
            or self.qos_changes
            or self.type_changes
            or self.role_changes
            or self.new_topics
            or self.removed_topics
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes the result to a standard dictionary format."""

        return {
            "has_differences": self.has_differences(),
            "new_participants": sorted(self.new_participants),
            "removed_participants": sorted(self.removed_participants),
            "new_endpoints": self.new_endpoints,
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
            ep.get("topic") for ep in observed_endpoints.values() if ep.get("topic")
        }

        result.new_participants = observed_participants - self.baseline_participants
        result.removed_participants = self.baseline_participants - observed_participants

        result.new_topics = observed_topics - self.baseline_topics
        result.removed_topics = self.baseline_topics - observed_topics

        for guid, ep_data in observed_endpoints.items():
            if guid not in self.baseline_endpoints_by_guid:
                result.new_endpoints.append(ep_data)
                continue

            baseline_ep = self.baseline_endpoints_by_guid[guid]
            participant = ep_data.get("guid_prefix") or ep_data.get("participant")
            topic = ep_data.get("topic", baseline_ep.topic)

            observed_role = ep_data.get("role")
            if observed_role and observed_role != baseline_ep.role:
                result.role_changes.append(
                    RoleChange(
                        guid=guid,
                        topic=topic,
                        participant=participant,
                        observed_role=observed_role,
                        expected_role=baseline_ep.role,
                    )
                )

            observed_type = ep_data.get("type") or ep_data.get("type_name")
            if observed_type and observed_type != baseline_ep.type_name:
                result.type_changes.append(
                    TypeChange(
                        guid=guid,
                        topic=topic,
                        participant=participant,
                        observed_type=observed_type,
                        expected_type=baseline_ep.type_name,
                    )
                )

            observed_qos = ep_data.get("qos")
            if isinstance(observed_qos, dict):
                expected_qos = dict(baseline_ep.qos)
                if not self._are_qos_matching(observed_qos, expected_qos):
                    result.qos_changes.append(
                        QoSChange(
                            guid=guid,
                            topic=topic,
                            participant=participant,
                            observed_qos=observed_qos,
                            expected_qos=expected_qos,
                        )
                    )

        for guid, baseline_ep in self.baseline_endpoints_by_guid.items():
            if guid not in observed_endpoints:
                result.removed_endpoints.append(baseline_ep)

        return result

    def _normalize_snapshot(
        self, snapshot: dict[str, Any]
    ) -> tuple[set[str], dict[str, dict[str, Any]]]:
        """
        Normalizes snapshots from GraphBuilder (nodes & edges) 
        or direct sniffer memory dicts (participants & endpoints).
        """

        graph = snapshot.get("graph", snapshot)
        observed_participants: set[str] = set()
        observed_endpoints: dict[str, dict[str, Any]] = {}

        if "nodes" in graph and "edges" in graph:
            for node in graph.get("nodes", []):
                if node.get("node_type") == "participant":
                    raw_id = node.get("id", "")
                    guid_prefix = raw_id.replace("participant:", "")
                    observed_participants.add(guid_prefix)

            for edge in graph.get("edges", []):
                guid = edge.get("guid") or edge.get("key")
                if not guid:
                    continue

                src = edge.get("source", "")
                dst = edge.get("target", "")
                
                topic = src.replace("topic:", "") if src.startswith("topic:") else dst.replace("topic:", "")
                participant = src.replace("participant:", "") if src.startswith("participant:") else dst.replace("participant:", "")

                observed_endpoints[guid] = {
                    "guid": guid,
                    "guid_prefix": participant,
                    "participant": participant,
                    "topic": topic,
                    "role": edge.get("role"),
                    "type": edge.get("type_name"),
                    "type_name": edge.get("type_name"),
                    "qos": edge.get("qos", {}),
                }
            return observed_participants, observed_endpoints

        raw_participants = graph.get("participants", {})
        if isinstance(raw_participants, dict):
            observed_participants = set(raw_participants.keys())

        raw_endpoints = graph.get("endpoints", {})
        if isinstance(raw_endpoints, dict):
            observed_endpoints = raw_endpoints

        return observed_participants, observed_endpoints

    @staticmethod
    def _are_qos_matching(observed: dict[str, str], expected: dict[str, str]) -> bool:
        """Verifies if observed QoS attributes meet expected baseline parameters."""

        for key, expected_value in expected.items():
            if observed.get(key) != expected_value:
                return False
        return True