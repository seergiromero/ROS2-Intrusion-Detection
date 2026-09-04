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

import json
import pytest

from rids_detector.alert_manager import AlertManager
from rids_detector.baseline import BaselineLoader
from rids_detector.detector import Detector, SnapshotReader
from rids_detector.main import main
from rids_detector.models import Baseline, BaselineEndpoint


@pytest.fixture
def sample_baseline() -> Baseline:
    """Creates a controlled Baseline instance with critical topics configured."""
    return Baseline(
        version=1,
        created_at="2026-09-04T10:00:00Z",
        source="unit_test",
        critical_topics=("/cmd_vel",),
        participants=("robot_A", "robot_B"),
        endpoints=(
            BaselineEndpoint(
                guid="ep_publisher_chatter",
                participant="robot_A",
                topic="/chatter",
                role="publisher",
                type_name="std_msgs/msg/String",
                qos={"reliability": "RELIABLE", "durability": "VOLATILE"},
            ),
            BaselineEndpoint(
                guid="ep_subscriber_chatter",
                participant="robot_B",
                topic="/chatter",
                role="subscriber",
                type_name="std_msgs/msg/String",
                qos={"reliability": "RELIABLE", "durability": "VOLATILE"},
            ),
            BaselineEndpoint(
                guid="ep_cmd_vel",
                participant="robot_A",
                topic="/cmd_vel",
                role="publisher",
                type_name="geometry_msgs/msg/Twist",
                qos={"reliability": "RELIABLE", "durability": "VOLATILE"},
            ),
        ),
    )


@pytest.fixture
def alert_manager(tmp_path) -> AlertManager:
    """Provides an AlertManager writing to a temporary JSONL file."""
    output_file = tmp_path / "alerts.jsonl"
    return AlertManager(output_path=output_file, console_output=False)


@pytest.fixture
def detector(sample_baseline: Baseline, alert_manager: AlertManager) -> Detector:
    """Provides a fully configured Detector instance."""
    return Detector(baseline=sample_baseline, alert_manager=alert_manager)


@pytest.fixture
def normal_snapshot() -> dict:
    """Snapshot containing only entities known in the baseline."""
    return {
        "id": "snap_normal_001",
        "timestamp": 1788516000.0,
        "participants": {"robot_A": {}, "robot_B": {}},
        "endpoints": {
            "ep_publisher_chatter": {
                "participant": "robot_A",
                "topic": "/chatter",
                "role": "publisher",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_subscriber_chatter": {
                "participant": "robot_B",
                "topic": "/chatter",
                "role": "subscriber",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_cmd_vel": {
                "participant": "robot_A",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
        },
    }


# ------------------------------------------------------------------
# Tests: Rule Evaluations & Anomaly Detection
# ------------------------------------------------------------------


def test_normal_snapshot_generates_no_alerts(detector: Detector, normal_snapshot: dict):
    """Verifies that a completely normal snapshot matching the baseline produces 0 alerts."""
    alerts = detector.process_snapshot(normal_snapshot)
    assert len(alerts) == 0


def test_new_participant_generates_warning(detector: Detector, normal_snapshot: dict):
    """Verifies that an unknown participant generates a WARNING alert."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_new_part"
    snap["participants"]["unknown_robot"] = {}

    alerts = detector.process_snapshot(snap)

    assert len(alerts) == 1
    assert alerts[0].severity == "WARNING"
    assert alerts[0].rule == "check_new_participants"
    assert alerts[0].participant == "unknown_robot"


def test_new_non_critical_endpoint_generates_warning(detector: Detector, normal_snapshot: dict):
    """Verifies that a new endpoint on a non-critical topic generates a WARNING."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_new_ep"
    snap["endpoints"]["new_ep_publisher"] = {
        "participant": "robot_A",
        "topic": "/chatter",
        "role": "publisher",
        "type_name": "std_msgs/msg/String",
        "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
    }

    alerts = detector.process_snapshot(snap)

    warning_alerts = [a for a in alerts if a.severity == "WARNING"]
    assert len(warning_alerts) >= 1
    assert any(a.endpoint == "new_ep_publisher" for a in warning_alerts)


def test_new_publisher_on_cmd_vel_generates_critical(detector: Detector, normal_snapshot: dict):
    """Verifies that an unauthorized publisher on /cmd_vel triggers a CRITICAL alert."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_crit_pub"
    snap["endpoints"]["rogue_publisher"] = {
        "participant": "robot_B",
        "topic": "/cmd_vel",
        "role": "publisher",
        "type_name": "geometry_msgs/msg/Twist",
        "qos": {},
    }

    alerts = detector.process_snapshot(snap)

    critical_alerts = [a for a in alerts if a.severity == "CRITICAL"]
    assert len(critical_alerts) == 1
    assert critical_alerts[0].rule == "check_unauthorized_critical_publishers"
    assert critical_alerts[0].topic == "/cmd_vel"
    assert critical_alerts[0].endpoint == "rogue_publisher"


def test_new_subscriber_on_cmd_vel_generates_warning(detector: Detector, normal_snapshot: dict):
    """Verifies that a new subscriber on /cmd_vel triggers a WARNING alert via check_new_endpoints."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_crit_sub"
    snap["endpoints"]["eavesdropper_sub"] = {
        "participant": "robot_B",
        "topic": "/cmd_vel",
        "role": "subscriber",
        "type_name": "geometry_msgs/msg/Twist",
        "qos": {},
    }

    alerts = detector.process_snapshot(snap)

    sub_alerts = [a for a in alerts if a.endpoint == "eavesdropper_sub"]
    assert len(sub_alerts) == 1
    assert sub_alerts[0].severity == "WARNING"
    assert sub_alerts[0].topic == "/cmd_vel"
    assert sub_alerts[0].endpoint == "eavesdropper_sub"


def test_modified_qos_generates_alert(detector: Detector, normal_snapshot: dict):
    """Verifies that modified QoS parameters trigger a QoS mismatch alert."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_qos_mod"
    snap["endpoints"]["ep_publisher_chatter"]["qos"]["reliability"] = "BEST_EFFORT"

    alerts = detector.process_snapshot(snap)

    qos_alerts = [a for a in alerts if a.rule == "check_qos_changes"]
    assert len(qos_alerts) == 1
    assert qos_alerts[0].topic == "/chatter"
    assert qos_alerts[0].observed_qos == {"reliability": "BEST_EFFORT", "durability": "VOLATILE"}
    assert qos_alerts[0].expected_qos == {"reliability": "RELIABLE", "durability": "VOLATILE"}


# ------------------------------------------------------------------
# Tests: State Management, Deduplication & Lifecycle
# ------------------------------------------------------------------


def test_repeated_alert_is_not_duplicated(detector: Detector, normal_snapshot: dict):
    """Verifies that an ongoing anomaly does not emit duplicate alerts in consecutive snapshots."""
    snap_1 = json.loads(json.dumps(normal_snapshot))
    snap_1["id"] = "snap_001"
    snap_1["participants"]["unknown_robot"] = {}

    snap_2 = json.loads(json.dumps(normal_snapshot))
    snap_2["id"] = "snap_002"
    snap_2["participants"]["unknown_robot"] = {}

    alerts_1 = detector.process_snapshot(snap_1)
    alerts_2 = detector.process_snapshot(snap_2)

    assert len(alerts_1) == 1
    assert len(alerts_2) == 0


def test_alert_reappears_if_anomaly_clears_and_returns(detector: Detector, normal_snapshot: dict):
    """Verifies that an alert is re-emitted if the anomaly disappears and reappears later."""
    snap_anomalous_1 = json.loads(json.dumps(normal_snapshot))
    snap_anomalous_1["id"] = "snap_001"
    snap_anomalous_1["participants"]["unknown_robot"] = {}

    snap_normal = json.loads(json.dumps(normal_snapshot))
    snap_normal["id"] = "snap_002"

    snap_anomalous_2 = json.loads(json.dumps(normal_snapshot))
    snap_anomalous_2["id"] = "snap_003"
    snap_anomalous_2["participants"]["unknown_robot"] = {}

    alerts_1 = detector.process_snapshot(snap_anomalous_1)
    alerts_2 = detector.process_snapshot(snap_normal)
    alerts_3 = detector.process_snapshot(snap_anomalous_2)

    assert len(alerts_1) == 1
    assert len(alerts_2) == 0
    assert len(alerts_3) == 1


def test_duplicate_snapshot_id_is_skipped(detector: Detector, normal_snapshot: dict):
    """Verifies that a snapshot with an already processed ID is ignored completely."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_duplicate_id"
    snap["participants"]["unknown_robot"] = {}

    alerts_first = detector.process_snapshot(snap)
    alerts_duplicate = detector.process_snapshot(snap)

    assert len(alerts_first) == 1
    assert len(alerts_duplicate) == 0


# ------------------------------------------------------------------
# Tests: Output & End-to-End Integration
# ------------------------------------------------------------------


def test_alert_written_to_jsonl_file(
    detector: Detector, alert_manager: AlertManager, normal_snapshot: dict
):
    """Verifies that emitted alerts are physically serialized into the JSONL file."""
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_write_jsonl"
    snap["participants"]["bad_actor"] = {}

    detector.process_snapshot(snap)
    alert_manager.close()

    content = alert_manager.output_path.read_text(encoding="utf-8").strip()
    records = [json.loads(line) for line in content.splitlines()]

    assert len(records) == 1
    assert records[0]["rule"] == "check_new_participants"
    assert records[0]["participant"] == "bad_actor"


def test_full_integration_loader_comparator_rules_manager(tmp_path):
    """Verifies complete flow: BaselineLoader -> SnapshotComparator -> rules -> AlertManager."""
    # 1. Save baseline file
    baseline_file = tmp_path / "baseline.json"
    baseline_data = {
        "version": 1,
        "created_at": "2026-09-04T10:00:00Z",
        "source": "integration_test",
        "critical_topics": ["/cmd_vel"],
        "participants": ["robot_01"],
        "endpoints": [
            {
                "guid": "ep_01",
                "participant": "robot_01",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "RELIABLE"},
            }
        ],
    }
    baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

    # 2. Load baseline via BaselineLoader instance
    loader = BaselineLoader()
    baseline = loader.load(baseline_file)

    # 3. Setup AlertManager & Detector
    alerts_file = tmp_path / "alerts.jsonl"
    with AlertManager(output_path=alerts_file, console_output=False) as manager:
        detector = Detector(baseline=baseline, alert_manager=manager)

        # 4. Process anomalous snapshot
        anomalous_snapshot = {
            "id": "snap_integration_001",
            "timestamp": 1788516000.0,
            "participants": {"robot_01": {}},
            "endpoints": {
                "ep_01": {
                    "participant": "robot_01",
                    "topic": "/cmd_vel",
                    "role": "publisher",
                    "type_name": "geometry_msgs/msg/Twist",
                    "qos": {"reliability": "RELIABLE"},
                },
                "unauthorized_ep": {
                    "participant": "robot_01",
                    "topic": "/cmd_vel",
                    "role": "publisher",
                    "type_name": "geometry_msgs/msg/Twist",
                    "qos": {"reliability": "RELIABLE"},
                },
            },
        }

        alerts = detector.process_snapshot(anomalous_snapshot)

        assert len(alerts) == 1
        assert alerts[0].severity == "CRITICAL"
        assert alerts[0].endpoint == "unauthorized_ep"

    # 5. Verify physical JSONL file contents
    content = alerts_file.read_text(encoding="utf-8").strip()
    record = json.loads(content)
    assert record["severity"] == "CRITICAL"
    assert record["rule"] == "check_unauthorized_critical_publishers"


def test_extra_critical_topics_do_not_mutate_frozen_baseline(
    sample_baseline: Baseline, alert_manager: AlertManager, normal_snapshot: dict
):
    """Detector keeps an effective topic policy without mutating the frozen Baseline."""
    original_topics = sample_baseline.critical_topics

    detector = Detector(
        sample_baseline,
        alert_manager,
        critical_topics=["/scan"],
    )

    assert sample_baseline.critical_topics == original_topics
    assert "/cmd_vel" in detector.critical_topics
    assert "/scan" in detector.critical_topics
    assert "/scan" not in sample_baseline.critical_topics

    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "snap_extra_critical"
    snap["endpoints"]["rogue_scan"] = {
        "participant": "robot_B",
        "topic": "/scan",
        "role": "publisher",
        "type_name": "sensor_msgs/msg/LaserScan",
        "qos": {},
    }

    alerts = detector.process_snapshot(snap)
    critical = [a for a in alerts if a.severity == "CRITICAL"]
    assert len(critical) == 1
    assert critical[0].topic == "/scan"
    assert critical[0].rule == "check_unauthorized_critical_publishers"


def test_snapshot_id_zero_is_not_treated_as_missing(
    detector: Detector, normal_snapshot: dict
):
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = 0
    snap["timestamp"] = 111.0
    snap["participants"]["unknown_robot"] = {}

    first = detector.process_snapshot(snap)
    second = detector.process_snapshot(snap)

    assert len(first) == 1
    assert len(second) == 0


def test_snapshot_id_field_from_introspector_is_used(
    detector: Detector, normal_snapshot: dict
):
    snap = json.loads(json.dumps(normal_snapshot))
    snap.pop("id")
    snap["snapshot_id"] = 0
    snap["participants"]["unknown_robot"] = {}

    first = detector.process_snapshot(snap)
    second = detector.process_snapshot(dict(snap))

    assert len(first) == 1
    assert len(second) == 0


def test_invalid_snapshot_is_skipped(detector: Detector):
    alerts = detector.process_snapshot({"id": "broken", "unexpected": True})
    assert alerts == []


def test_missing_baseline_entities_do_not_generate_alerts(
    detector: Detector, normal_snapshot: dict
):
    snap = json.loads(json.dumps(normal_snapshot))
    snap["id"] = "incomplete_discovery"
    snap["participants"] = {"robot_A": {}}
    snap["endpoints"].pop("ep_subscriber_chatter")

    alerts = detector.process_snapshot(snap)
    assert alerts == []


def test_jsonl_end_to_end_reader_detector_alerts(tmp_path, sample_baseline: Baseline):
    """JSONL file -> SnapshotReader -> Detector -> alerts.jsonl with dedup lifecycle."""
    snapshots_path = tmp_path / "snapshots.jsonl"
    alerts_path = tmp_path / "alerts.jsonl"

    def endpoint_block():
        return {
            "ep_publisher_chatter": {
                "participant": "robot_A",
                "topic": "/chatter",
                "role": "publisher",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_subscriber_chatter": {
                "participant": "robot_B",
                "topic": "/chatter",
                "role": "subscriber",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_cmd_vel": {
                "participant": "robot_A",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
        }

    def snapshot(snapshot_id, extra_endpoint=None):
        endpoints = endpoint_block()
        if extra_endpoint:
            endpoints.update(extra_endpoint)
        return {
            "snapshot_id": snapshot_id,
            "timestamp": 1788516000.0 + snapshot_id,
            "participants": {"robot_A": {}, "robot_B": {}},
            "endpoints": endpoints,
        }

    attacker = {
        "rogue_cmd_vel": {
            "participant": "robot_B",
            "topic": "/cmd_vel",
            "role": "publisher",
            "type_name": "geometry_msgs/msg/Twist",
            "qos": {},
        }
    }

    records = [
        snapshot(0),
        snapshot(1, attacker),
        snapshot(1, attacker),  # duplicate id
        snapshot(2, attacker),  # same anomaly, new id
        snapshot(3),
        snapshot(4, attacker),
    ]
    snapshots_path.write_text(
        "".join(json.dumps(item) + "\n" for item in records),
        encoding="utf-8",
    )

    with AlertManager(output_path=alerts_path, console_output=False) as manager:
        detector = Detector(sample_baseline, manager)
        emitted = detector.process_from_reader(SnapshotReader(snapshots_path))

    written = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert len(emitted) == 2
    assert len(written) == 2
    assert all(row["severity"] == "CRITICAL" for row in written)
    assert all(row["rule"] == "check_unauthorized_critical_publishers" for row in written)
    assert all(row["endpoint"] == "rogue_cmd_vel" for row in written)


def test_main_once_mode_writes_alerts(tmp_path, sample_baseline: Baseline):
    import yaml

    baseline_path = tmp_path / "baseline.yaml"
    snapshots_path = tmp_path / "snapshots.jsonl"
    alerts_path = tmp_path / "alerts.jsonl"

    baseline_path.write_text(
        yaml.safe_dump(sample_baseline.to_dict(), sort_keys=False),
        encoding="utf-8",
    )

    snap = {
        "snapshot_id": 0,
        "participants": {"robot_A": {}, "robot_B": {}},
        "endpoints": {
            "ep_publisher_chatter": {
                "participant": "robot_A",
                "topic": "/chatter",
                "role": "publisher",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_subscriber_chatter": {
                "participant": "robot_B",
                "topic": "/chatter",
                "role": "subscriber",
                "type_name": "std_msgs/msg/String",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "ep_cmd_vel": {
                "participant": "robot_A",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
            },
            "rogue_cmd_vel": {
                "participant": "robot_B",
                "topic": "/cmd_vel",
                "role": "publisher",
                "type_name": "geometry_msgs/msg/Twist",
                "qos": {},
            },
        },
    }
    snapshots_path.write_text(json.dumps(snap) + "\n", encoding="utf-8")

    exit_code = main(
        [
            "--baseline",
            str(baseline_path),
            "--snapshots",
            str(snapshots_path),
            "--alerts",
            str(alerts_path),
            "--mode",
            "once",
            "--no-console",
        ]
    )

    assert exit_code == 0
    lines = [line for line in alerts_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["severity"] == "CRITICAL"