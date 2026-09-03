from pathlib import Path
from typing import Any

import yaml

from .models import Baseline, BaselineEndpoint, Role


class BaselineValidationError(ValueError):
    pass

"""
A class for loading and validating baseline configurations.
"""
class BaselineLoader:
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
        """Validate and construct a Baseline from a dictionary."""

        location = f" in {source_path}" if source_path else ""
        if not isinstance(data, dict):
            raise BaselineValidationError(f"Baseline must be a mapping{location}")

        missing = self.REQUIRED_ROOT_KEYS - data.keys()
        if missing:
            names = ", ".join(sorted(missing))
            raise BaselineValidationError(f"Missing required baseline fields: {names}{location}")

        version = data["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise BaselineValidationError("version must be a positive integer")

        created_at = self._required_string(data, "created_at")
        source = self._required_string(data, "source")
        critical_topics = self._string_tuple(data, "critical_topics")
        participants = self._string_tuple(data, "participants")

        raw_endpoints = data["endpoints"]
        if not isinstance(raw_endpoints, list):
            raise BaselineValidationError("endpoints must be a list")

        endpoints = tuple(self._endpoint(item, index) for index, item in enumerate(raw_endpoints))
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
    def _required_string(data: dict[str, Any], name: str) -> str:
        """Ensure that a required field is a non-empty string."""

        value = data[name]
        if not isinstance(value, str) or not value.strip():
            raise BaselineValidationError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _string_tuple(data: dict[str, Any], name: str) -> tuple[str, ...]:
        """Ensure that a field is a list of non-empty strings and return it as a tuple."""

        value = data[name]
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            raise BaselineValidationError(f"{name} must be a list of non-empty strings")
        if len(value) != len(set(value)):
            raise BaselineValidationError(f"{name} must not contain duplicates")
        return tuple(value)

    @staticmethod
    def _endpoint(data: Any, index: int) -> BaselineEndpoint:
        """Validate and construct a BaselineEndpoint from a dictionary."""

        if not isinstance(data, dict):
            raise BaselineValidationError(f"endpoints[{index}] must be a mapping")

        required = {"guid", "participant", "topic", "role", "type_name", "qos"}
        missing = required - data.keys()
        if missing:
            raise BaselineValidationError(
                f"endpoints[{index}] missing: {', '.join(sorted(missing))}"
            )

        for name in ("guid", "participant", "topic", "type_name"):
            if not isinstance(data[name], str) or not data[name].strip():
                raise BaselineValidationError(f"endpoints[{index}].{name} must be a non-empty string")

        role = data["role"]
        if role not in {"publisher", "subscriber"}:
            raise BaselineValidationError(
                f"endpoints[{index}].role must be 'publisher' or 'subscriber'"
            )

        qos = data["qos"]
        if not isinstance(qos, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in qos.items()
        ):
            raise BaselineValidationError(
                f"endpoints[{index}].qos must be a mapping of strings"
            )

        return BaselineEndpoint(
            guid=data["guid"],
            participant=data["participant"],
            topic=data["topic"],
            role=role,
            type_name=data["type_name"],
            qos=dict(qos),
        )
