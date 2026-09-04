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
from pathlib import Path
from typing import Any, TextIO

from .models import Alert


class AlertManager:
    """Manages alert output to the console and a JSONL file."""

    def __init__(
        self,
        output_path: str | Path = "alerts.jsonl",
        console_output: bool = True,
    ) -> None:
        self.output_path = Path(output_path)
        self.console_output = console_output
        self._file: TextIO | None = None

        if self.output_path.parent:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

        self._file = open(self.output_path, mode="a", encoding="utf-8")

    def emit(self, alert: Alert) -> dict[str, Any]:
        """Prints the alert to the terminal and writes it to the JSONL file."""

        if self.console_output:
            print(self._format_console(alert))

        record = alert.to_dict()

        if self._file and not self._file.closed:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()

        return record

    def _format_console(self, alert: Alert) -> str:
        """Generates a formatted, human-readable text for terminal display."""

        severity = getattr(alert, "severity", "UNKNOWN")
        rule = getattr(alert, "rule", "unknown_rule")
        message = getattr(alert, "message", "")
        timestamp = getattr(alert, "timestamp", None)

        time_part = f"{timestamp} - " if timestamp else ""
        return f"[{severity}] {time_part}Rule: {rule} - Msg: {message}"

    def close(self) -> None:
        """Safely closes the output alert file."""

        if self._file and not self._file.closed:
            self._file.close()