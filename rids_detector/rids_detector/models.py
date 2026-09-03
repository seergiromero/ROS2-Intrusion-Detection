from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal


Severity = Literal["INFO", "WARNING", "CRITICAL"]
Role = Literal["publisher", "subscriber"]

@dataclass(frozen=True)
class Alert:
    timestamp: float
    severity: Severity
    rule: str
    message: str
    participant: str | None = None
    endpoint: str | None = None
    topic: str | None = None
    role: Role | None = None
    observed_qos: dict[str, str] | None = None
    expected_qos: dict[str, str] | None = None

    @classmethod
    def now(
        cls,
        severity: Severity,
        rule: str,
        message: str,
        **context: Any,
    ) -> "Alert":
        return cls(
            timestamp=datetime.now(timezone.utc).timestamp(),
            severity=severity,
            rule=rule,
            message=message,
            **context,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "rule": self.rule,
            "message": self.message,
            "participant": self.participant,
            "endpoint": self.endpoint,
            "topic": self.topic,
            "role": self.role,
            "observed_qos": self.observed_qos,
            "expected_qos": self.expected_qos,
        }


@dataclass(frozen=True)
class BaselineEndpoint:
    guid: str
    participant: str
    topic: str
    role: Role
    type_name: str
    qos: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "guid": self.guid,
            "participant": self.participant,
            "topic": self.topic,
            "role": self.role,
            "type_name": self.type_name,
            "qos": dict(self.qos),
        }


@dataclass(frozen=True)
class Baseline:
    version: int
    created_at: str
    source: str
    critical_topics: tuple[str, ...]
    participants: tuple[str, ...]
    endpoints: tuple[BaselineEndpoint, ...]

    def endpoint_guids(self) -> frozenset[str]:
        return frozenset(endpoint.guid for endpoint in self.endpoints)

    def participant_guids(self) -> frozenset[str]:
        return frozenset(self.participants)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "source": self.source,
            "critical_topics": list(self.critical_topics),
            "participants": list(self.participants),
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
        }
