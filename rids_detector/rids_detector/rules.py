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

from collections.abc import Callable, Iterable
from typing import Any

from .compare import ComparisonResult
from .models import Alert, Baseline


def _get_attr(obj: Any, attr_name: str, default: Any = None) -> Any:
    """Helper to safely access attributes from both objects and dictionaries."""
    if isinstance(obj, dict):
        return obj.get(attr_name, default)
    return getattr(obj, attr_name, default)


def check_unauthorized_critical_publishers(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect the appearance of an unauthorized publisher on a critical topic."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for ep in comparison.new_endpoints:
        topic = _get_attr(ep, "topic")
        role = _get_attr(ep, "role")

        if role == "publisher" and topic in critical_set:
            participant = _get_attr(ep, "participant") or _get_attr(ep, "guid_prefix")
            guid = _get_attr(ep, "guid")
            qos = _get_attr(ep, "qos", {})

            alerts.append(
                Alert.now(
                    severity="CRITICAL",
                    rule="check_unauthorized_critical_publishers",
                    message=f"CRITICAL: Unauthorized publisher on critical topic '{topic}' (GUID: '{guid}')",
                    participant=participant,
                    endpoint=guid,
                    topic=topic,
                    role="publisher",
                    observed_qos=qos if isinstance(qos, dict) else {},
                )
            )
    return alerts


def check_new_participants(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect participants not registered in the baseline.
    
    Suppresses WARNING alerts for new participants if they already triggered a CRITICAL
    alert via check_unauthorized_critical_publishers.
    """
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    # Identify participants associated with critical publisher violations
    critical_participants: set[str] = set()
    for ep in comparison.new_endpoints:
        topic = _get_attr(ep, "topic")
        role = _get_attr(ep, "role")
        participant = _get_attr(ep, "participant") or _get_attr(ep, "guid_prefix")
        if role == "publisher" and topic in critical_set and participant:
            critical_participants.add(str(participant))

    for participant in sorted(comparison.new_participants):
        if participant in critical_participants:
            continue

        alerts.append(
            Alert.now(
                severity="WARNING",
                rule="check_new_participants",
                message=f"New unauthorized participant detected: '{participant}'",
                participant=participant,
            )
        )
    return alerts


def check_new_endpoints(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect new endpoints (skips critical publishers handled by check_unauthorized_critical_publishers)."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for ep in comparison.new_endpoints:
        topic = _get_attr(ep, "topic")
        role = _get_attr(ep, "role")

        # Avoid duplicating alerts for unauthorized publishers on critical topics
        if role == "publisher" and topic in critical_set:
            continue

        participant = _get_attr(ep, "participant") or _get_attr(ep, "guid_prefix")
        guid = _get_attr(ep, "guid")
        type_name = _get_attr(ep, "type_name") or _get_attr(ep, "type")
        qos = _get_attr(ep, "qos", {})

        alerts.append(
            Alert.now(
                severity="WARNING",
                rule="check_new_endpoints",
                message=f"New endpoint '{guid}' detected on topic '{topic}' ({role}, {type_name})",
                participant=participant,
                endpoint=guid,
                topic=topic,
                role=role if role in ("publisher", "subscriber") else None,
                observed_qos=qos if isinstance(qos, dict) else {},
            )
        )
    return alerts


def check_qos_changes(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect QoS changes and specifically identify which properties changed."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for qos_change in comparison.qos_changes:
        topic = _get_attr(qos_change, "topic")
        severity = "CRITICAL" if topic in critical_set else "WARNING"
        expected_qos = _get_attr(qos_change, "expected_qos", {})
        observed_qos = _get_attr(qos_change, "observed_qos", {})
        guid = _get_attr(qos_change, "guid")
        participant = _get_attr(qos_change, "participant")

        # Identify modified attributes
        target_keys = ("reliability", "durability", "history", "depth")
        diff_keys = [
            key for key in target_keys
            if key in expected_qos and observed_qos.get(key) != expected_qos.get(key)
        ]
        if not diff_keys:
            diff_keys = [
                k for k in expected_qos if observed_qos.get(k) != expected_qos.get(k)
            ]

        properties_str = ", ".join(diff_keys) if diff_keys else "qos properties"
        msg = f"QoS mismatch on endpoint '{guid}' for topic '{topic}'. Modified properties: [{properties_str}]"

        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_qos_changes",
                message=msg,
                participant=participant,
                endpoint=guid,
                topic=topic,
                observed_qos=observed_qos if isinstance(observed_qos, dict) else {},
                expected_qos=expected_qos if isinstance(expected_qos, dict) else {},
            )
        )
    return alerts


def check_role_changes(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect role changes on existing GUIDs."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for rc in comparison.role_changes:
        topic = _get_attr(rc, "topic")
        severity = "CRITICAL" if topic in critical_set else "WARNING"
        expected_role = _get_attr(rc, "expected_role")
        observed_role = _get_attr(rc, "observed_role")
        guid = _get_attr(rc, "guid")
        participant = _get_attr(rc, "participant")

        msg = f"Role change on '{guid}' ({topic}): expected '{expected_role}', observed '{observed_role}'"
        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_role_changes",
                message=msg,
                participant=participant,
                endpoint=guid,
                topic=topic,
                role=observed_role if observed_role in ("publisher", "subscriber") else None,
            )
        )
    return alerts


def check_new_topics(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect new topics not registered in the baseline (skips critical topics)."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for topic in sorted(comparison.new_topics):
        if topic in critical_set:
            continue
        alerts.append(
            Alert.now(
                severity="INFO",
                rule="check_new_topics",
                message=f"New non-critical topic observed: '{topic}'",
                topic=topic,
            )
        )
    return alerts


def check_type_changes(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect message type changes on existing GUIDs."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for tc in comparison.type_changes:
        topic = _get_attr(tc, "topic")
        severity = "CRITICAL" if topic in critical_set else "WARNING"
        expected_type = _get_attr(tc, "expected_type")
        observed_type = _get_attr(tc, "observed_type")
        guid = _get_attr(tc, "guid")
        participant = _get_attr(tc, "participant")

        msg = f"Type change on '{guid}' ({topic}): expected '{expected_type}', observed '{observed_type}'"
        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_type_changes",
                message=msg,
                participant=participant,
                endpoint=guid,
                topic=topic,
            )
        )
    return alerts


# Registry of default active rules
RuleFunction = Callable[
    [Baseline, dict[str, Any], ComparisonResult, Iterable[str] | None],
    list[Alert],
]

DEFAULT_RULES: list[RuleFunction] = [
    check_unauthorized_critical_publishers,
    check_new_participants,
    check_new_endpoints,
    check_new_topics,
    check_qos_changes,
    check_role_changes,
    check_type_changes,
]


def evaluate_all_rules(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
    rules: Iterable[RuleFunction] | None = None,
) -> list[Alert]:
    """Run the rule suite and consolidate generated alerts.
    
    Args:
        baseline: Baseline instance.
        snapshot: Raw snapshot dictionary.
        comparison: ComparisonResult instance.
        critical_topics: Optional override list for critical topics.
        rules: Optional custom collection of rule functions to evaluate. Defaults to DEFAULT_RULES.
    """
    active_rules = rules if rules is not None else DEFAULT_RULES
    alerts: list[Alert] = []
    for rule in active_rules:
        alerts.extend(rule(baseline, snapshot, comparison, critical_topics))
    return alerts