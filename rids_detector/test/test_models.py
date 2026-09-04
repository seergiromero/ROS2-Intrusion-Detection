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

from datetime import datetime, timezone
import json
import pytest

from rids_detector.models import Alert, Baseline, BaselineEndpoint


def test_alert_is_serializable_and_keeps_context():
    alert = Alert(
        timestamp=100.0,
        severity="CRITICAL",
        rule="unauthorized_publisher",
        message="Unknown publisher on /cmd_vel",
        participant="participant-guid",
        endpoint="endpoint-guid",
        topic="/cmd_vel",
        role="publisher",
        observed_qos={"reliability": "BEST_EFFORT"},
        expected_qos={"reliability": "RELIABLE"},
    )

    data = alert.to_dict()
    json.dumps(data)

    assert data["severity"] == "CRITICAL"
    assert data["topic"] == "/cmd_vel"
    assert data["observed_qos"]["reliability"] == "BEST_EFFORT"


def test_baseline_endpoint_to_dict_copies_qos():
    qos = {"reliability": "RELIABLE"}
    endpoint = BaselineEndpoint(
        guid="endpoint-guid",
        participant="participant-guid",
        topic="/scan",
        role="publisher",
        type_name="sensor_msgs/msg/LaserScan",
        qos=qos,
    )

    serialized = endpoint.to_dict()
    serialized["qos"]["reliability"] = "BEST_EFFORT"

    assert qos["reliability"] == "RELIABLE"


def test_alert_now_creates_valid_timestamp():
    """Verifies that Alert.now() generates a valid UTC timestamp."""
    before = datetime.now(timezone.utc).timestamp()
    alert = Alert.now(
        severity="INFO",
        rule="test_rule",
        message="Test alert message",
    )
    after = datetime.now(timezone.utc).timestamp()

    assert isinstance(alert.timestamp, float)
    assert before <= alert.timestamp <= after


def test_alert_optional_fields_default_to_none():
    """Verifies that optional fields default to None when omitted."""
    alert = Alert(
        timestamp=100.0,
        severity="INFO",
        rule="minimal_rule",
        message="Minimal alert",
    )

    assert alert.participant is None
    assert alert.endpoint is None
    assert alert.topic is None
    assert alert.role is None
    assert alert.observed_qos is None
    assert alert.expected_qos is None

    data = alert.to_dict()
    assert data["participant"] is None
    assert data["observed_qos"] is None


def test_alert_full_serialization():
    """Verifies full serialization of all Alert fields to a dictionary and valid JSON."""
    alert = Alert(
        timestamp=123.456,
        severity="WARNING",
        rule="qos_mismatch",
        message="QoS policy mismatch detected",
        participant="p_100",
        endpoint="e_200",
        topic="/sensor_data",
        role="subscriber",
        observed_qos={"durability": "TRANSIENT_LOCAL"},
        expected_qos={"durability": "VOLATILE"},
    )

    expected_dict = {
        "timestamp": 123.456,
        "severity": "WARNING",
        "rule": "qos_mismatch",
        "message": "QoS policy mismatch detected",
        "participant": "p_100",
        "endpoint": "e_200",
        "topic": "/sensor_data",
        "role": "subscriber",
        "observed_qos": {"durability": "TRANSIENT_LOCAL"},
        "expected_qos": {"durability": "VOLATILE"},
    }

    serialized = alert.to_dict()
    assert serialized == expected_dict
    assert json.loads(json.dumps(serialized)) == expected_dict


@pytest.mark.parametrize("valid_severity", ["INFO", "WARNING", "CRITICAL"])
def test_alert_valid_severities(valid_severity):
    """Verifies that all allowed Severity literals are correctly accepted."""
    alert = Alert(
        timestamp=1.0,
        severity=valid_severity,
        rule="rule_name",
        message="Msg",
    )
    assert alert.severity == valid_severity


def test_alert_stable_identity():
    """Verifies that alert.identity produces a consistent tuple key for deduplication."""
    alert = Alert(
        timestamp=999.9,
        severity="CRITICAL",
        rule="unauthorized_publisher",
        message="Different message",
        topic="/cmd_vel",
        endpoint="ep_123",
        participant="part_456",
        role="publisher",
    )

    expected_identity = (
        "unauthorized_publisher",
        "/cmd_vel",
        "ep_123",
        "part_456",
        "publisher",
    )

    assert alert.identity == expected_identity


def test_baseline_guid_helpers():
    endpoint = BaselineEndpoint(
        guid="endpoint-guid",
        participant="participant-guid",
        topic="/scan",
        role="publisher",
        type_name="sensor_msgs/msg/LaserScan",
        qos={"reliability": "RELIABLE"},
    )
    baseline = Baseline(
        version=1,
        created_at="2026-09-04T10:00:00Z",
        source="unit_test",
        critical_topics=("/scan",),
        participants=("participant-guid",),
        endpoints=(endpoint,),
    )

    assert baseline.endpoint_guids() == frozenset({"endpoint-guid"})
    assert baseline.participant_guids() == frozenset({"participant-guid"})