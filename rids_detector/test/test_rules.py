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

from unittest.mock import MagicMock
import pytest

from rids_detector.rules import (
    check_new_endpoints,
    check_new_participants,
    check_qos_changes,
    check_type_or_role_changes,
    check_unauthorized_critical_publishers,
    evaluate_all_rules,
)


@pytest.fixture
def baseline():
    mock_b = MagicMock()
    mock_b.critical_topics = {"/critical/topic_a"}
    return mock_b


@pytest.fixture
def snapshot():
    return {}


@pytest.fixture
def alert_factory(monkeypatch):
    """Mocks Alert.now to return simple dicts or mock objects for easier assertion."""

    def mock_now(
        severity,
        rule,
        message,
        participant=None,
        endpoint=None,
        topic=None,
        role=None,
        observed_qos=None,
        expected_qos=None,
    ):
        alert = MagicMock()
        alert.severity = severity
        alert.rule = rule
        alert.message = message
        alert.participant = participant
        alert.endpoint = endpoint
        alert.topic = topic
        alert.role = role
        alert.observed_qos = observed_qos
        alert.expected_qos = expected_qos
        return alert

    monkeypatch.setattr("rids_detector.rules.Alert.now", mock_now)


# ------------------------------------------------------------------
# Tests: check_new_participants
# ------------------------------------------------------------------


def test_check_new_participants_sorted(baseline, snapshot, alert_factory):
    comparison = MagicMock()
    comparison.new_participants = ["participant_B", "participant_A"]

    alerts = check_new_participants(baseline, snapshot, comparison)

    assert len(alerts) == 2
    assert alerts[0].participant == "participant_A"
    assert alerts[1].participant == "participant_B"
    assert all(a.severity == "WARNING" for a in alerts)


# ------------------------------------------------------------------
# Tests: check_new_endpoints & check_unauthorized_critical_publishers
# ------------------------------------------------------------------


def test_check_new_endpoints_ignores_critical_publishers(
    baseline, snapshot, alert_factory
):
    comparison = MagicMock()
    comparison.new_endpoints = [
        # Critical publisher: MUST be skipped by check_new_endpoints
        {
            "guid": "guid_1",
            "topic": "/critical/topic_a",
            "role": "publisher",
            "participant": "p1",
        },
        # Critical subscriber: MUST be processed by check_new_endpoints
        {
            "guid": "guid_2",
            "topic": "/critical/topic_a",
            "role": "subscriber",
            "participant": "p2",
        },
        # Normal publisher: MUST be processed by check_new_endpoints
        {
            "guid": "guid_3",
            "topic": "/normal/topic_b",
            "role": "publisher",
            "participant": "p3",
        },
    ]

    alerts = check_new_endpoints(baseline, snapshot, comparison)

    assert len(alerts) == 2
    assert {a.endpoint for a in alerts} == {"guid_2", "guid_3"}
    assert all(a.severity == "WARNING" for a in alerts)


def test_check_unauthorized_critical_publishers_detects_only_critical_publishers(
    baseline, snapshot, alert_factory
):
    comparison = MagicMock()
    comparison.new_endpoints = [
        {
            "guid": "guid_1",
            "topic": "/critical/topic_a",
            "role": "publisher",
            "participant": "p1",
        },
        {
            "guid": "guid_2",
            "topic": "/critical/topic_a",
            "role": "subscriber",
            "participant": "p2",
        },
        {
            "guid": "guid_3",
            "topic": "/normal/topic_b",
            "role": "publisher",
            "participant": "p3",
        },
    ]

    alerts = check_unauthorized_critical_publishers(
        baseline, snapshot, comparison
    )

    assert len(alerts) == 1
    assert alerts[0].endpoint == "guid_1"
    assert alerts[0].severity == "CRITICAL"


# ------------------------------------------------------------------
# Tests: check_qos_changes
# ------------------------------------------------------------------


def test_check_qos_changes_diff_keys_and_severity(
    baseline, snapshot, alert_factory
):
    qos_crit = MagicMock()
    qos_crit.topic = "/critical/topic_a"
    qos_crit.guid = "guid_crit"
    qos_crit.participant = "p1"
    qos_crit.expected_qos = {
        "reliability": "RELIABLE",
        "durability": "TRANSIENT",
    }
    qos_crit.observed_qos = {
        "reliability": "BEST_EFFORT",
        "durability": "TRANSIENT",
    }

    qos_norm = MagicMock()
    qos_norm.topic = "/normal/topic_b"
    qos_norm.guid = "guid_norm"
    qos_norm.participant = "p2"
    # Fallback to non-target key diff
    qos_norm.expected_qos = {"custom_key": "val1"}
    qos_norm.observed_qos = {"custom_key": "val2"}

    comparison = MagicMock()
    comparison.qos_changes = [qos_crit, qos_norm]

    alerts = check_qos_changes(baseline, snapshot, comparison)

    assert len(alerts) == 2
    assert alerts[0].severity == "CRITICAL"
    assert "reliability" in alerts[0].message

    assert alerts[1].severity == "WARNING"
    assert "custom_key" in alerts[1].message


# ------------------------------------------------------------------
# Tests: check_type_or_role_changes
# ------------------------------------------------------------------


def test_check_type_or_role_changes(baseline, snapshot, alert_factory):
    rc = MagicMock()
    rc.topic = "/critical/topic_a"
    rc.guid = "guid_role"
    rc.participant = "p1"
    rc.expected_role = "subscriber"
    rc.observed_role = "publisher"

    tc = MagicMock()
    tc.topic = "/normal/topic_b"
    tc.guid = "guid_type"
    tc.participant = "p2"
    tc.expected_type = "std_msgs::String"
    tc.observed_type = "std_msgs::Int32"

    comparison = MagicMock()
    comparison.role_changes = [rc]
    comparison.type_changes = [tc]

    alerts = check_type_or_role_changes(baseline, snapshot, comparison)

    assert len(alerts) == 2
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].rule == "check_type_or_role_changes"
    assert alerts[1].severity == "WARNING"


# ------------------------------------------------------------------
# Tests: evaluate_all_rules
# ------------------------------------------------------------------


def test_evaluate_all_rules_runs_complete_suite(
    baseline, snapshot, alert_factory
):
    comparison = MagicMock()
    comparison.new_participants = ["part_1"]
    comparison.new_endpoints = [
        {
            "guid": "g1",
            "topic": "/critical/topic_a",
            "role": "publisher",
            "participant": "part_1",
        }
    ]
    comparison.qos_changes = []
    comparison.role_changes = []
    comparison.type_changes = []

    alerts = evaluate_all_rules(baseline, snapshot, comparison)

    # Must contain 1 critical alert (critical publisher) + 1 warning alert (new participant)
    assert len(alerts) == 2
    severities = {a.severity for a in alerts}
    assert severities == {"CRITICAL", "WARNING"}