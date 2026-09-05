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

from typing import Any
import pytest

from compare import (
    ObservedEndpoint,
    QoSChange,
    RoleChange,
    SnapshotComparator,
    SnapshotValidationError,
    TypeChange,
    is_ros2_infra_topic,
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
    assert not result.has_differences(include_missing=True)
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

    assert not result.has_differences()
    assert result.has_differences(include_missing=True)
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
    assert serialized["has_missing_elements"] is True
    assert serialized["new_participants"] == ["99999999"]
    assert serialized["removed_participants"] == ["010f0000"]
    assert isinstance(serialized["removed_endpoints"], list)


# ------------------------------------------------------------------
# Additional tests
# ------------------------------------------------------------------

def test_empty_snapshot(sample_baseline: Baseline):
    """Tests processing of an empty dictionary snapshot."""
    comparator = SnapshotComparator(sample_baseline)
    result = comparator.compare({})

    assert not result.has_differences()
    assert result.has_differences(include_missing=True)
    assert len(result.removed_participants) == len(sample_baseline.participants)
    assert len(result.removed_endpoints) == len(sample_baseline.endpoints)


def test_snapshot_missing_nodes(sample_baseline: Baseline):
    """Tests snapshot containing 'edges' key but missing 'nodes'."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = {"edges": []}

    result = comparator.compare(snapshot)

    assert not result.has_differences()
    assert result.has_differences(include_missing=True)
    assert len(result.removed_participants) == 1


def test_snapshot_missing_edges(sample_baseline: Baseline):
    """Tests snapshot containing 'nodes' key but missing 'edges'."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [{"id": "participant:010f0000", "node_type": "participant"}]
    }

    result = comparator.compare(snapshot)

    assert not result.has_differences()
    assert result.has_differences(include_missing=True)
    assert len(result.removed_endpoints) == 2


def test_invalid_nodes_or_edges_type_raises_validation_error(sample_baseline: Baseline):
    """Tests that non-list nodes or edges raise SnapshotValidationError."""
    comparator = SnapshotComparator(sample_baseline)

    with pytest.raises(SnapshotValidationError, match="must be lists"):
        comparator.compare({"nodes": "not_a_list", "edges": []})

    with pytest.raises(SnapshotValidationError, match="must be lists"):
        comparator.compare({"nodes": [], "edges": {"not": "a_list"}})


def test_edge_without_guid_ignored(sample_baseline: Baseline):
    """Tests that edges lacking both 'guid' and 'key' are ignored gracefully."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [{"id": "participant:010f0000", "node_type": "participant"}],
        "edges": [
            {
                "source": "participant:010f0000",
                "target": "topic:/cmd_vel",
                "role": "publisher",
            }
        ],
    }

    result = comparator.compare(snapshot)

    assert len(result.new_endpoints) == 0
    assert len(result.removed_endpoints) == 2


def test_edge_with_invalid_direction_handled(sample_baseline: Baseline):
    """Tests edge where source/target do not follow topic/participant prefixes."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [],
        "edges": [
            {
                "guid": "unknown.0001",
                "source": "unprefixed_source",
                "target": "unprefixed_target",
                "role": "publisher",
                "type_name": "std_msgs/msg/String",
            }
        ],
    }

    result = comparator.compare(snapshot)

    assert len(result.new_endpoints) == 1
    new_ep = result.new_endpoints[0]
    assert new_ep.guid == "unknown.0001"
    assert new_ep.topic == ""
    assert new_ep.participant is None


def test_new_endpoint_in_graphbuilder_snapshot(
    sample_baseline: Baseline, graphbuilder_snapshot: dict[str, Any]
):
    """Tests detection of a new unauthorized endpoint in GraphBuilder format."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = dict(graphbuilder_snapshot)
    snapshot["edges"] = list(graphbuilder_snapshot["edges"]) + [
        {
            "source": "participant:010f0000",
            "target": "topic:/unauthorized_topic",
            "guid": "010f0000.9999",
            "role": "publisher",
            "type_name": "std_msgs/msg/Header",
            "qos": {"reliability": "reliable"},
        }
    ]

    result = comparator.compare(snapshot)

    assert result.has_differences()
    assert len(result.new_endpoints) == 1
    new_ep = result.new_endpoints[0]
    assert isinstance(new_ep, ObservedEndpoint)
    assert new_ep.guid == "010f0000.9999"
    assert new_ep.topic == "/unauthorized_topic"
    assert new_ep.participant == "010f0000"
    assert "/unauthorized_topic" in result.new_topics


def test_incomplete_observed_qos_flags_change(sample_baseline: Baseline):
    """Tests that observed QoS missing expected policy keys triggers QoSChange."""
    comparator = SnapshotComparator(sample_baseline)

    snapshot = {
        "nodes": [{"id": "participant:010f0000", "node_type": "participant"}],
        "edges": [
            {
                "guid": "010f0000.0001",
                "source": "participant:010f0000",
                "target": "topic:/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "reliable"},  # Missing expected 'durability'
            }
        ],
    }

    result = comparator.compare(snapshot)

    assert result.has_differences()
    assert len(result.qos_changes) == 1
    assert result.qos_changes[0].guid == "010f0000.0001"
    assert result.qos_changes[0].observed_qos == {"reliability": "reliable"}
    assert result.qos_changes[0].expected_qos == {
        "reliability": "reliable",
        "durability": "volatile",
    }


def test_multiple_endpoints_same_topic():
    """Tests that multiple endpoints sharing the same topic are tracked independently."""
    ep_pub = BaselineEndpoint("01.01", "01", "/cmd_vel", "publisher", "std_msgs/String", {})
    ep_sub = BaselineEndpoint("01.02", "01", "/cmd_vel", "subscriber", "std_msgs/String", {})
    baseline = Baseline(
        version=1,
        created_at="2026-09-03T00:00:00Z",
        source="test",
        participants=["01"],
        endpoints=[ep_pub, ep_sub],
        critical_topics=["/cmd_vel"],
    )

    comparator = SnapshotComparator(baseline)
    snapshot = {
        "nodes": [{"id": "participant:01", "node_type": "participant"}],
        "edges": [
            {
                "guid": "01.01",
                "source": "participant:01",
                "target": "topic:/cmd_vel",
                "role": "publisher",
                "type_name": "std_msgs/String",
            },
            {
                "guid": "01.02",
                "source": "topic:/cmd_vel",
                "target": "participant:01",
                "role": "subscriber",
                "type_name": "std_msgs/String",
            },
        ],
    }

    result = comparator.compare(snapshot)

    assert not result.has_differences()
    assert len(result.removed_endpoints) == 0
    assert len(result.new_endpoints) == 0


def test_idempotent_comparison(
    sample_baseline: Baseline, graphbuilder_snapshot: dict[str, Any]
):
    """Tests that repeating compare on the same snapshot produces identical results."""
    comparator = SnapshotComparator(sample_baseline)

    result1 = comparator.compare(graphbuilder_snapshot)
    result2 = comparator.compare(graphbuilder_snapshot)

    assert result1 == result2
    assert result1.to_dict() == result2.to_dict()


# ------------------------------------------------------------------
# ROS 2 action / middleware topics
# ------------------------------------------------------------------

def test_action_topics_are_infra():
    """Action plumbing topics are treated as middleware, not new endpoints."""
    for topic in (
        "/turtle1/rotate_absolute/_action/send_goalRequest",
        "/turtle1/rotate_absolute/_action/send_goalReply",
        "/turtle1/rotate_absolute/_action/cancel_goalRequest",
        "/turtle1/rotate_absolute/_action/cancel_goalReply",
        "/turtle1/rotate_absolute/_action/get_resultRequest",
        "/turtle1/rotate_absolute/_action/get_resultReply",
        "/turtle1/rotate_absolute/_action/feedback",
        "/turtle1/rotate_absolute/_action/status",
        "/nav2/navigate_to_pose/_action/send_goalRequest",
    ):
        assert is_ros2_infra_topic(topic) is True, topic


def test_app_topics_are_not_infra():
    """Application topics (even action-sounding ones) must not be silenced."""
    for topic in (
        "/turtle1/cmd_vel",
        "/turtle1/pose",
        "/chatter",
        "/robot/action_feedback",
        "/action_server/status",
        "/actions",
        None,
    ):
        assert is_ros2_infra_topic(topic) is False, topic


def test_action_endpoints_excluded_from_comparison(sample_baseline: Baseline):
    """A snapshot whose only new endpoints are action topics yields no differences."""
    comparator = SnapshotComparator(sample_baseline)
    snapshot = {
        "nodes": [{"id": "participant:010f0000", "node_type": "participant"}],
        "edges": [
            {
                "guid": "010f0000.00a1",
                "source": "participant:010f0000",
                "target": "topic:/turtle1/rotate_absolute/_action/send_goalRequest",
                "role": "publisher",
                "type_name": "turtlesim::action::dds_::RotateAbsolute_SendGoal_Request_",
            },
            {
                "guid": "010f0000.00a2",
                "source": "topic:/turtle1/rotate_absolute/_action/status",
                "target": "participant:010f0000",
                "role": "subscriber",
                "type_name": "action_msgs::msg::dds_::GoalStatusArray_",
            },
        ],
    }

    result = comparator.compare(snapshot)

    assert len(result.new_endpoints) == 0
    assert len(result.new_topics) == 0
    assert not result.has_differences()