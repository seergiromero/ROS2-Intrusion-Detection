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

import pytest

from rids_detector.compare import (
    ComparisonResult,
    ObservedEndpoint,
    QoSChange,
    RoleChange,
    TypeChange,
)
from rids_detector.models import Alert, Baseline, BaselineEndpoint
from rids_detector.rules import (
    check_new_endpoints,
    check_new_participants,
    check_new_topics,
    check_qos_changes,
    check_role_changes,
    check_type_changes,
    check_unauthorized_critical_publishers,
    evaluate_all_rules,
)


@pytest.fixture
def sample_baseline() -> Baseline:
    """Provides a realistic Baseline instance with critical topics."""
    return Baseline(
        version=1,
        created_at="2026-09-03T00:00:00Z",
        source="test",
        participants=["p_legit"],
        endpoints=[
            BaselineEndpoint(
                guid="p_legit.01",
                participant="p_legit",
                topic="/critical/topic_a",
                role="publisher",
                type_name="std_msgs/msg/String",
                qos={"reliability": "reliable", "durability": "transient"},
            )
        ],
        critical_topics=["/critical/topic_a"],
    )


# ------------------------------------------------------------------
# Tests: check_unauthorized_critical_publishers & Participant Deduplication
# ------------------------------------------------------------------


def test_unauthorized_critical_publisher_suppresses_new_participant_warning(
    sample_baseline: Baseline,
):
    """Tests that a new critical publisher triggers a CRITICAL alert and suppresses WARNING on participant."""
    new_ep = ObservedEndpoint(
        guid="attacker.01",
        participant="attacker_node",
        topic="/critical/topic_a",
        role="publisher",
        type_name="std_msgs/msg/String",
        qos={"reliability": "reliable"},
    )
    comparison = ComparisonResult(
        new_participants=["attacker_node", "innocent_node"],
        new_endpoints=[new_ep],
    )

    # 1. Critical publisher check
    crit_alerts = check_unauthorized_critical_publishers(
        sample_baseline, {}, comparison
    )
    assert len(crit_alerts) == 1
    assert crit_alerts[0].severity == "CRITICAL"
    assert crit_alerts[0].participant == "attacker_node"
    assert crit_alerts[0].topic == "/critical/topic_a"

    # 2. New participant check (should suppress attacker_node and only alert innocent_node)
    part_alerts = check_new_participants(sample_baseline, {}, comparison)
    assert len(part_alerts) == 1
    assert part_alerts[0].severity == "WARNING"
    assert part_alerts[0].participant == "innocent_node"


# ------------------------------------------------------------------
# Tests: check_new_endpoints
# ------------------------------------------------------------------


def test_check_new_endpoints_critical_subscriber_and_normal_publisher(
    sample_baseline: Baseline,
):
    """Tests that new critical subscribers and normal publishers yield WARNING alerts."""
    ep_sub_crit = ObservedEndpoint(
        guid="sub.01",
        participant="reader_node",
        topic="/critical/topic_a",
        role="subscriber",
        type_name="std_msgs/msg/String",
        qos={},
    )
    ep_pub_norm = ObservedEndpoint(
        guid="pub.01",
        participant="writer_node",
        topic="/normal/topic_b",
        role="publisher",
        type_name="std_msgs/msg/Int32",
        qos={},
    )
    ep_pub_crit = ObservedEndpoint(
        guid="pub.99",
        participant="rogue_node",
        topic="/critical/topic_a",
        role="publisher",
        type_name="std_msgs/msg/String",
        qos={},
    )

    comparison = ComparisonResult(
        new_endpoints=[ep_sub_crit, ep_pub_norm, ep_pub_crit]
    )

    alerts = check_new_endpoints(sample_baseline, {}, comparison)

    # ep_pub_crit is handled by check_unauthorized_critical_publishers, so 2 remain
    assert len(alerts) == 2
    assert {a.endpoint for a in alerts} == {"sub.01", "pub.01"}
    assert all(a.severity == "WARNING" for a in alerts)


# ------------------------------------------------------------------
# Tests: check_qos_changes
# ------------------------------------------------------------------


def test_check_qos_changes_multiple_fields_and_critical_severity(
    sample_baseline: Baseline,
):
    """Tests QoS changes with multiple altered attributes and correct severity scaling."""
    qos_crit = QoSChange(
        guid="p_legit.01",
        topic="/critical/topic_a",
        participant="p_legit",
        expected_qos={"reliability": "reliable", "durability": "transient"},
        observed_qos={"reliability": "best_effort", "durability": "volatile"},
    )
    qos_norm = QoSChange(
        guid="p_other.01",
        topic="/normal/topic_b",
        participant="p_other",
        expected_qos={"reliability": "reliable"},
        observed_qos={"reliability": "best_effort"},
    )

    comparison = ComparisonResult(qos_changes=[qos_crit, qos_norm])
    alerts = check_qos_changes(sample_baseline, {}, comparison)

    assert len(alerts) == 2

    # Critical topic QoS mismatch
    assert alerts[0].severity == "CRITICAL"
    assert "reliability" in alerts[0].message
    assert "durability" in alerts[0].message

    # Non-critical topic QoS mismatch
    assert alerts[1].severity == "WARNING"
    assert "reliability" in alerts[1].message


# ------------------------------------------------------------------
# Tests: Role and Type Changes
# ------------------------------------------------------------------


def test_check_role_changes(sample_baseline: Baseline):
    """Tests detection of role changes on critical vs normal topics."""
    rc_crit = RoleChange(
        guid="p_legit.01",
        topic="/critical/topic_a",
        participant="p_legit",
        expected_role="publisher",
        observed_role="subscriber",
    )
    comparison = ComparisonResult(role_changes=[rc_crit])

    alerts = check_role_changes(sample_baseline, {}, comparison)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].rule == "check_role_changes"
    assert alerts[0].role == "subscriber"


def test_check_type_changes_critical_and_normal(sample_baseline: Baseline):
    """Tests message type change detection with CRITICAL severity on critical topics."""
    tc_crit = TypeChange(
        guid="p_legit.01",
        topic="/critical/topic_a",
        participant="p_legit",
        expected_type="std_msgs/msg/String",
        observed_type="std_msgs/msg/Int32",
    )
    tc_norm = TypeChange(
        guid="p_other.01",
        topic="/normal/topic_b",
        participant="p_other",
        expected_type="sensor_msgs/msg/Image",
        observed_type="sensor_msgs/msg/CompressedImage",
    )
    comparison = ComparisonResult(type_changes=[tc_crit, tc_norm])

    alerts = check_type_changes(sample_baseline, {}, comparison)

    assert len(alerts) == 2
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].rule == "check_type_changes"
    assert alerts[1].severity == "WARNING"


# ------------------------------------------------------------------
# Tests: check_new_topics policy
# ------------------------------------------------------------------


def test_new_non_critical_topic_generates_info(sample_baseline: Baseline):
    comparison = ComparisonResult(new_topics={"/diagnostics"})
    alerts = check_new_topics(sample_baseline, {}, comparison)

    assert len(alerts) == 1
    assert alerts[0].severity == "INFO"
    assert alerts[0].rule == "check_new_topics"
    assert alerts[0].topic == "/diagnostics"


def test_new_critical_topic_does_not_generate_critical_without_publisher(
    sample_baseline: Baseline,
):
    comparison = ComparisonResult(new_topics={"/critical/topic_a", "/other"})
    alerts = evaluate_all_rules(sample_baseline, {}, comparison)

    assert not any(a.severity == "CRITICAL" for a in alerts)
    info_alerts = [a for a in alerts if a.rule == "check_new_topics"]
    assert {a.topic for a in info_alerts} == {"/other"}


def test_new_normal_publisher_generates_warning(sample_baseline: Baseline):
    ep = ObservedEndpoint(
        guid="pub.normal",
        participant="writer_node",
        topic="/normal/topic_b",
        role="publisher",
        type_name="std_msgs/msg/Int32",
        qos={},
    )
    comparison = ComparisonResult(new_endpoints=[ep], new_topics={"/normal/topic_b"})
    alerts = evaluate_all_rules(sample_baseline, {}, comparison)

    endpoint_alerts = [a for a in alerts if a.rule == "check_new_endpoints"]
    topic_alerts = [a for a in alerts if a.rule == "check_new_topics"]
    assert len(endpoint_alerts) == 1
    assert endpoint_alerts[0].severity == "WARNING"
    assert len(topic_alerts) == 1
    assert topic_alerts[0].severity == "INFO"


def test_new_subscriber_on_critical_topic_generates_warning(sample_baseline: Baseline):
    ep = ObservedEndpoint(
        guid="sub.crit",
        participant="reader_node",
        topic="/critical/topic_a",
        role="subscriber",
        type_name="std_msgs/msg/String",
        qos={},
    )
    comparison = ComparisonResult(new_endpoints=[ep])
    alerts = evaluate_all_rules(sample_baseline, {}, comparison)

    assert len(alerts) == 1
    assert alerts[0].severity == "WARNING"
    assert alerts[0].rule == "check_new_endpoints"


def test_critical_publisher_generates_exactly_one_critical(sample_baseline: Baseline):
    ep = ObservedEndpoint(
        guid="pub.crit",
        participant="p_legit",
        topic="/critical/topic_a",
        role="publisher",
        type_name="std_msgs/msg/String",
        qos={},
    )
    comparison = ComparisonResult(new_endpoints=[ep])
    alerts = evaluate_all_rules(sample_baseline, {}, comparison)

    critical = [a for a in alerts if a.severity == "CRITICAL"]
    assert len(critical) == 1
    assert critical[0].rule == "check_unauthorized_critical_publishers"
    assert not any(a.rule == "check_new_endpoints" for a in alerts)


# ------------------------------------------------------------------
# Integration Test: evaluate_all_rules with Real Objects
# ------------------------------------------------------------------


def test_evaluate_all_rules_with_real_domain_objects(sample_baseline: Baseline):
    """Integrates all rule evaluations using real Baseline, ComparisonResult, and Alert instances."""
    new_crit_pub = ObservedEndpoint(
        guid="bad_actor.01",
        participant="bad_actor",
        topic="/critical/topic_a",
        role="publisher",
        type_name="std_msgs/msg/String",
        qos={"reliability": "reliable"},
    )
    new_norm_sub = ObservedEndpoint(
        guid="listener.01",
        participant="listener_node",
        topic="/normal/topic_b",
        role="subscriber",
        type_name="std_msgs/msg/Int32",
        qos={},
    )
    type_mod = TypeChange(
        guid="p_legit.01",
        topic="/critical/topic_a",
        participant="p_legit",
        expected_type="std_msgs/msg/String",
        observed_type="std_msgs/msg/Byte",
    )

    comparison = ComparisonResult(
        new_participants=["bad_actor", "listener_node"],
        new_endpoints=[new_crit_pub, new_norm_sub],
        type_changes=[type_mod],
    )

    alerts = evaluate_all_rules(sample_baseline, {}, comparison)

    assert len(alerts) == 4
    assert all(isinstance(a, Alert) for a in alerts)

    severities = [a.severity for a in alerts]
    assert severities.count("CRITICAL") == 2
    assert severities.count("WARNING") == 2

    rules_triggered = {a.rule for a in alerts}
    assert rules_triggered == {
        "check_unauthorized_critical_publishers",
        "check_new_participants",
        "check_new_endpoints",
        "check_type_changes",
    }