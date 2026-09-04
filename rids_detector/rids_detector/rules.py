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

from collections.abc import Iterable
from typing import Any

from .compare import ComparisonResult
from .models import Alert, Baseline


def check_new_participants(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect participants not registered in the baseline."""
    alerts: list[Alert] = []

    for participant in sorted(comparison.new_participants):
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
        topic = ep.get("topic")
        role = ep.get("role")

        # Avoid duplicating alerts for unauthorized publishers on critical topics
        if role == "publisher" and topic in critical_set:
            continue

        participant = ep.get("participant") or ep.get("guid_prefix")
        guid = ep.get("guid")
        type_name = ep.get("type_name") or ep.get("type")
        qos = ep.get("qos", {})

        alerts.append(
            Alert.now(
                severity="WARNING",
                rule="check_new_endpoints",
                message=f"New endpoint '{guid}' detected on topic '{topic}' ({role}, {type_name})",
                participant=participant,
                endpoint=guid,
                topic=topic,
                role=role if role in ("publisher", "subscriber") else None,
                observed_qos=qos,
            )
        )
    return alerts


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
        topic = ep.get("topic")
        role = ep.get("role")

        if role == "publisher" and topic in critical_set:
            participant = ep.get("participant") or ep.get("guid_prefix")
            guid = ep.get("guid")
            qos = ep.get("qos", {})

            alerts.append(
                Alert.now(
                    severity="CRITICAL",
                    rule="check_unauthorized_critical_publishers",
                    message=f"CRITICAL: Unauthorized publisher on critical topic '{topic}' (GUID: '{guid}')",
                    participant=participant,
                    endpoint=guid,
                    topic=topic,
                    role="publisher",
                    observed_qos=qos,
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
        topic = qos_change.topic
        severity = "CRITICAL" if topic in critical_set else "WARNING"

        # Identify modified attributes
        target_keys = ("reliability", "durability", "history", "depth")
        diff_keys = [
            key for key in target_keys
            if key in qos_change.expected_qos
            and qos_change.observed_qos.get(key) != qos_change.expected_qos.get(key)
        ]
        if not diff_keys:
            diff_keys = [
                k for k in qos_change.expected_qos
                if qos_change.observed_qos.get(k) != qos_change.expected_qos.get(k)
            ]

        properties_str = ", ".join(diff_keys) if diff_keys else "qos properties"
        msg = f"QoS mismatch on endpoint '{qos_change.guid}' for topic '{topic}'. Modified properties: [{properties_str}]"

        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_qos_changes",
                message=msg,
                participant=qos_change.participant,
                endpoint=qos_change.guid,
                topic=topic,
                observed_qos=qos_change.observed_qos,
                expected_qos=qos_change.expected_qos,
            )
        )
    return alerts


def check_type_or_role_changes(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Detect role or message type changes on existing GUIDs."""
    critical_set = set(critical_topics) if critical_topics is not None else set(baseline.critical_topics)
    alerts: list[Alert] = []

    for rc in comparison.role_changes:
        severity = "CRITICAL" if rc.topic in critical_set else "WARNING"
        msg = f"Role change on '{rc.guid}' ({rc.topic}): expected '{rc.expected_role}', observed '{rc.observed_role}'"
        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_type_or_role_changes",
                message=msg,
                participant=rc.participant,
                endpoint=rc.guid,
                topic=rc.topic,
                role=rc.observed_role if rc.observed_role in ("publisher", "subscriber") else None,
            )
        )

    for tc in comparison.type_changes:
        severity = "CRITICAL" if tc.topic in critical_set else "WARNING"
        msg = f"Type change on '{tc.guid}' ({tc.topic}): expected '{tc.expected_type}', observed '{tc.observed_type}'"
        alerts.append(
            Alert.now(
                severity=severity,
                rule="check_type_or_role_changes",
                message=msg,
                participant=tc.participant,
                endpoint=tc.guid,
                topic=tc.topic,
            )
        )

    return alerts


def evaluate_all_rules(
    baseline: Baseline,
    snapshot: dict[str, Any],
    comparison: ComparisonResult,
    critical_topics: Iterable[str] | None = None,
) -> list[Alert]:
    """Run the complete rule suite and consolidate generated alerts."""
    rules = [
        check_unauthorized_critical_publishers,
        check_new_participants,
        check_new_endpoints,
        check_qos_changes,
        check_type_or_role_changes,
    ]
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(rule(baseline, snapshot, comparison, critical_topics))
    return alerts