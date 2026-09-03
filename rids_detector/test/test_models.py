import json

from rids_detector.models import Alert, BaselineEndpoint


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
