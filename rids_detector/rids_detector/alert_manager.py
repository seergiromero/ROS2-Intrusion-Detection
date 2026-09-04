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
import logging
from pathlib import Path
from typing import Any, TextIO

from .models import Alert

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages alert output to structured logging and a JSONL file."""

    def __init__(
        self,
        output_path: str | Path = "alerts.jsonl",
        console_output: bool = True,
    ) -> None:
        self.output_path = Path(output_path)
        self.console_output = console_output
        self._file: TextIO | None = None
        self._closed = False

        if self.output_path.parent:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

        self._file = open(self.output_path, mode="a", encoding="utf-8")

    def emit(self, alert: Alert) -> dict[str, Any]:
        """Logs the alert and writes its JSON serialization to the JSONL file.

        Raises:
            RuntimeError: If called after the AlertManager has been closed.
        """
        if self._closed or (self._file and self._file.closed):
            raise RuntimeError("Cannot emit alert: AlertManager is closed.")

        record = alert.to_dict()

        if self.console_output:
            formatted_msg = self._format_console(alert)
            severity = str(getattr(alert, "severity", "WARNING")).upper()

            if severity == "CRITICAL":
                logger.critical(formatted_msg)
            elif severity == "WARNING":
                logger.warning(formatted_msg)
            else:
                logger.info(formatted_msg)

        if self._file:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()

        return record

    def _format_console(self, alert: Alert) -> str:
        """Generates formatted text with rule, message, timestamp, and context metadata."""
        severity = getattr(alert, "severity", "UNKNOWN")
        rule = getattr(alert, "rule", "unknown_rule")
        message = getattr(alert, "message", "")
        raw_ts = getattr(alert, "timestamp", None)

        # Standardized timestamp parsing (numeric epoch to UTC ISO string)
        if isinstance(raw_ts, (int, float)):
            time_str = datetime.fromtimestamp(raw_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif raw_ts:
            time_str = str(raw_ts)
        else:
            time_str = ""

        time_part = f"{time_str} - " if time_str else ""

        # Context extraction (topic, participant, endpoint)
        context_items = []
        topic = getattr(alert, "topic", None)
        participant = getattr(alert, "participant", None)
        endpoint = getattr(alert, "endpoint", None)

        if topic:
            context_items.append(f"Topic: {topic}")
        if participant:
            context_items.append(f"Participant: {participant}")
        if endpoint:
            context_items.append(f"Endpoint: {endpoint}")

        context_str = f" [{ ' | '.join(context_items) }]" if context_items else ""

        return f"[{severity}] {time_part}Rule: {rule} - Msg: {message}{context_str}"

    def close(self) -> None:
        """Safely closes the output alert file."""
        if self._file and not self._file.closed:
            self._file.close()
        self._closed = True

    def __enter__(self) -> "AlertManager":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()