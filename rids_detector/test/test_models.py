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
