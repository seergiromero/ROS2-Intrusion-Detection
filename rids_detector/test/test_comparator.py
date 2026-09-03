from typing import Any
import pytest

from compare import (
    ComparisonResult,
    QoSChange,
    RoleChange,
    SnapshotComparator,
    TypeChange,
)
from models import Baseline, BaselineEndpoint


@pytest.fixture
def sample_baseline() -> Baseline:
    """Fixture providing a standard Baseline for testing."""

    ep1 = BaselineEndpoint(
        guid="010f0000.0001",
        participant="010f0000",
        topic="/cmd_vel",
        role="publisher",
        type_name="geometry_msgs/msg/Twist",
        qos={"reliability": "reliable", "durability": "volatile"},
    )
    ep2 = BaselineEndpoint(
        guid="010f0000.0002",
        participant="010f0000",
        topic="/chatter",
        role="subscriber",
        type_name="std_msgs/msg/String",
        qos={"reliability": "best_effort"},
    )
    return Baseline(
        version=1,
        created_at="2026-09-03T00:00:00Z",
        source="test",
        participants=["010f0000"],
        endpoints=[ep1, ep2],
        critical_topics=["/cmd_vel"],
    )


@pytest.fixture
def graphbuilder_snapshot() -> dict[str, Any]:
    """Fixture providing a valid snapshot in GraphBuilder format."""

    return {
        "stats": {"num_participants": 1, "num_topics": 2, "num_edges": 2},
        "nodes": [
            {"id": "participant:010f0000", "node_type": "participant"},
            {"id": "topic:/cmd_vel", "node_type": "topic"},
            {"id": "topic:/chatter", "node_type": "topic"},
        ],
        "edges": [
            {
                "source": "participant:010f0000",
                "target": "topic:/cmd_vel",
                "key": "010f0000.0001",
                "guid": "010f0000.0001",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "reliable", "durability": "volatile"},
            },
            {
                "source": "topic:/chatter",
                "target": "participant:010f0000",
                "key": "010f0000.0002",
                "guid": "010f0000.0002",
                "role": "subscriber",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "best_effort"},
            },
        ],
    }


def test_no_differences(sample_baseline: Baseline, graphbuilder_snapshot: dict[str, Any]):
    """Tests that an identical snapshot produces no detected differences."""

    comparator = SnapshotComparator(sample_baseline)
    result = comparator.compare(graphbuilder_snapshot)

    assert not result.has_differences()
    assert len(result.new_participants) == 0
    assert len(result.removed_participants) == 0
    assert len(result.new_endpoints) == 0
    assert len(result.removed_endpoints) == 0


def test_new_and_removed_participants(sample_baseline: Baseline):
    """Tests detection of newly joined and missing participants."""

    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [
            {"id": "participant:020a0000", "node_type": "participant"},  # New
        ],
        "edges": [],
    }

    result = comparator.compare(snapshot)

    assert result.has_differences()
    assert "020a0000" in result.new_participants
    assert "010f0000" in result.removed_participants


def test_endpoint_attribute_changes(sample_baseline: Baseline):
    """Tests detection of Role, Type, and QoS mismatches on an existing endpoint."""

    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [
            {"id": "participant:010f0000", "node_type": "participant"},
            {"id": "topic:/cmd_vel", "node_type": "topic"},
        ],
        "edges": [
            {
                "source": "topic:/cmd_vel",
                "target": "participant:010f0000",
                "guid": "010f0000.0001",
                "role": "subscriber",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "best_effort"},
            }
        ],
    }

    result = comparator.compare(snapshot)

    assert result.has_differences()

    # Role Change
    assert len(result.role_changes) == 1
    assert result.role_changes[0] == RoleChange(
        guid="010f0000.0001",
        topic="/cmd_vel",
        participant="010f0000",
        observed_role="subscriber",
        expected_role="publisher",
    )

    # Type Change
    assert len(result.type_changes) == 1
    assert result.type_changes[0] == TypeChange(
        guid="010f0000.0001",
        topic="/cmd_vel",
        participant="010f0000",
        observed_type="std_msgs/msg/String",
        expected_type="geometry_msgs/msg/Twist",
    )

    # QoS Change
    assert len(result.qos_changes) == 1
    assert result.qos_changes[0] == QoSChange(
        guid="010f0000.0001",
        topic="/cmd_vel",
        participant="010f0000",
        observed_qos={"reliability": "best_effort"},
        expected_qos={"reliability": "reliable", "durability": "volatile"},
    )


def test_fallback_sniffer_format(sample_baseline: Baseline):
    """Tests snapshot parsing using the direct sniffer memory dictionary format."""

    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "participants": {"010f0000": {}},
        "endpoints": {
            "010f0000.0001": {
                "guid": "010f0000.0001",
                "participant": "010f0000",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "reliable", "durability": "volatile"},
            }
        },
    }

    result = comparator.compare(snapshot)

    assert result.has_differences()
    assert len(result.removed_endpoints) == 1
    assert result.removed_endpoints[0].guid == "010f0000.0002"


def test_to_dict_serialization(sample_baseline: Baseline):
    """Tests that ComparisonResult.to_dict() converts internal data structures correctly."""

    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [{"id": "participant:99999999", "node_type": "participant"}],
        "edges": [],
    }

    result = comparator.compare(snapshot)
    serialized = result.to_dict()

    assert isinstance(serialized, dict)
    assert serialized["has_differences"] is True
    assert serialized["new_participants"] == ["99999999"]
    assert serialized["removed_participants"] == ["010f0000"]
    assert isinstance(serialized["removed_endpoints"], list)