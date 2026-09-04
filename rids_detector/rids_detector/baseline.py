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

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .models import Baseline, BaselineEndpoint


class BaselineValidationError(ValueError):
    """Raised when a baseline configuration file or dictionary fails validation."""

    pass


class BaselineLoader:
    """A loader class for reading, normalizing, and validating baseline configurations."""

    REQUIRED_ROOT_KEYS = {
        "version",
        "created_at",
        "source",
        "critical_topics",
        "participants",
        "endpoints",
    }

    def load(self, path: str | Path) -> Baseline:
        """Load a baseline from a YAML file."""
        baseline_path = Path(path)
        if not baseline_path.is_file():
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        with baseline_path.open("r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)

        return self.from_dict(data, source_path=baseline_path)

    def from_dict(self, data: Any, source_path: str | Path | None = None) -> Baseline:
        """Validate, normalize, and construct a Baseline from a dictionary."""
        location = f" in {source_path}" if source_path else ""
        if not isinstance(data, dict):
            raise BaselineValidationError(f"Baseline must be a mapping{location}")

        missing = self.REQUIRED_ROOT_KEYS - data.keys()
        if missing:
            names = ", ".join(sorted(missing))
            raise BaselineValidationError(
                f"Missing required baseline fields: {names}{location}"
            )

        version = data["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise BaselineValidationError("version must be a positive integer")

        created_at = self._validate_iso_timestamp(data["created_at"], "created_at")
        source = self._required_string(data, "source")
        critical_topics = self._topic_tuple(data, "critical_topics")
        participants = self._string_tuple(data, "participants")

        raw_endpoints = data["endpoints"]
        if not isinstance(raw_endpoints, list):
            raise BaselineValidationError("endpoints must be a list")

        endpoints = tuple(
            self._endpoint(item, index) for index, item in enumerate(raw_endpoints)
        )
        endpoint_guids = [endpoint.guid for endpoint in endpoints]
        if len(endpoint_guids) != len(set(endpoint_guids)):
            raise BaselineValidationError("endpoint GUIDs must be unique")

        unknown_participants = {
            endpoint.participant for endpoint in endpoints
        } - set(participants)
        if unknown_participants:
            raise BaselineValidationError(
                "endpoint participants are missing from participants: "
                + ", ".join(sorted(unknown_participants))
            )

        return Baseline(
            version=version,
            created_at=created_at,
            source=source,
            critical_topics=critical_topics,
            participants=participants,
            endpoints=endpoints,
        )

    @staticmethod
    def _validate_topic(topic: Any, context: str) -> str:
        """Normalize topic name ensuring non-empty string starting with '/'."""
        if not isinstance(topic, str) or not topic.strip():
            raise BaselineValidationError(f"{context} topic must be a non-empty string")
        
        normalized = topic.strip()
        if not normalized.startswith("/"):
            raise BaselineValidationError(
                f"{context} topic must start with '/': '{topic}'"
            )
        return normalized

    @staticmethod
    def _validate_iso_timestamp(value: Any, name: str) -> str:
        """Ensure created_at is a valid ISO 8601 date/time string."""
        if not isinstance(value, str) or not value.strip():
            raise BaselineValidationError(f"{name} must be a non-empty string")
        
        cleaned = value.strip()
        try:
            datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError:
            raise BaselineValidationError(
                f"{name} must be a valid ISO 8601 timestamp (e.g. '2026-09-04T10:00:00Z'), got '{value}'"
            )
        return cleaned

    @staticmethod
    def _required_string(data: dict[str, Any], name: str) -> str:
        """Ensure that a required field is a non-empty string."""
        value = data[name]
        if not isinstance(value, str) or not value.strip():
            raise BaselineValidationError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _string_tuple(data: dict[str, Any], name: str) -> tuple[str, ...]:
        """Ensure that a field is a list of non-empty strings and return it as a tuple."""
        value = data[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            raise BaselineValidationError(f"{name} must be a list of non-empty strings")
        
        cleaned = [item.strip() for item in value]
        if len(cleaned) != len(set(cleaned)):
            raise BaselineValidationError(f"{name} must not contain duplicates")
        return tuple(cleaned)

    @classmethod
    def _topic_tuple(cls, data: dict[str, Any], name: str) -> tuple[str, ...]:
        """Validate critical topics list against ROS naming rules (leading '/')."""
        value = data[name]
        if not isinstance(value, list):
            raise BaselineValidationError(f"{name} must be a list of topic strings")

        topics = [cls._validate_topic(item, f"{name}[{i}]") for i, item in enumerate(value)]
        if len(topics) != len(set(topics)):
            raise BaselineValidationError(f"{name} must not contain duplicates")
        return tuple(topics)

    @classmethod
    def _endpoint(cls, data: Any, index: int) -> BaselineEndpoint:
        """Validate and construct a normalized BaselineEndpoint from a dictionary."""
        if not isinstance(data, dict):
            raise BaselineValidationError(f"endpoints[{index}] must be a mapping")

        required = {"guid", "participant", "topic", "role", "type_name", "qos"}
        missing = required - data.keys()
        if missing:
            raise BaselineValidationError(
                f"endpoints[{index}] missing: {', '.join(sorted(missing))}"
            )

        for name in ("guid", "participant", "type_name"):
            if not isinstance(data[name], str) or not data[name].strip():
                raise BaselineValidationError(
                    f"endpoints[{index}].{name} must be a non-empty string"
                )

        topic = cls._validate_topic(data["topic"], f"endpoints[{index}]")
        role = str(data["role"]).strip().lower()
        if role not in {"publisher", "subscriber"}:
            raise BaselineValidationError(
                f"endpoints[{index}].role must be 'publisher' or 'subscriber'"
            )

        qos = data["qos"]
        if not isinstance(qos, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip()
            for k, v in qos.items()
        ):
            raise BaselineValidationError(
                f"endpoints[{index}].qos must be a mapping of non-empty strings"
            )

        normalized_qos = {k.strip(): v.strip() for k, v in qos.items()}

        return BaselineEndpoint(
            guid=data["guid"].strip(),
            participant=data["participant"].strip(),
            topic=topic,
            role=role,  # type: ignore[arg-type]
            type_name=data["type_name"].strip(),
            qos=normalized_qos,
        )