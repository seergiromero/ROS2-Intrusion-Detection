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
from unittest.mock import MagicMock
import pytest
from rids_detector.alert_manager import AlertManager


@pytest.fixture
def mock_alert():
    """Creates a mock Alert object with standard attributes and to_dict method."""
    alert = MagicMock()
    alert.severity = "WARNING"
    alert.rule = "check_new_participants"
    alert.message = "New participant detected"
    alert.timestamp = "2026-09-04T10:00:00"
    alert.to_dict.return_value = {
        "severity": "WARNING",
        "rule": "check_new_participants",
        "message": "New participant detected",
        "timestamp": "2026-09-04T10:00:00",
    }
    return alert


def test_init_creates_directories_and_opens_file(tmp_path):
    """Verifies that AlertManager creates nested directories and opens the file."""
    output_file = tmp_path / "nested_dir" / "alerts.jsonl"

    manager = AlertManager(output_path=output_file)

    assert output_file.exists()
    assert manager._file is not None
    assert not manager._file.closed

    manager.close()
    assert manager._file.closed


def test_emit_writes_jsonl_record(tmp_path, mock_alert):
    """Verifies that emit writes the formatted JSON record to the file."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file, console_output=False)

    record = manager.emit(mock_alert)
    manager.close()

    # Check returned dictionary
    assert record == mock_alert.to_dict.return_value

    # Check file content
    content = output_file.read_text(encoding="utf-8").strip()
    written_data = json.loads(content)

    assert written_data["severity"] == "WARNING"
    assert written_data["rule"] == "check_new_participants"
    assert written_data["message"] == "New participant detected"


def test_emit_console_output_enabled(tmp_path, mock_alert, capsys):
    """Verifies that output is printed to the terminal when console_output=True."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file, console_output=True)

    manager.emit(mock_alert)
    manager.close()

    captured = capsys.readouterr()
    expected_msg = "[WARNING] 2026-09-04T10:00:00 - Rule: check_new_participants - Msg: New participant detected\n"
    assert captured.out == expected_msg


def test_emit_console_output_disabled(tmp_path, mock_alert, capsys):
    """Verifies that nothing is printed to the terminal when console_output=False."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file, console_output=False)

    manager.emit(mock_alert)
    manager.close()

    captured = capsys.readouterr()
    assert captured.out == ""


def test_format_console_without_timestamp(tmp_path):
    """Verifies console formatting when alert timestamp is missing or None."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file)

    alert_no_time = MagicMock()
    alert_no_time.severity = "CRITICAL"
    alert_no_time.rule = "critical_rule"
    alert_no_time.message = "Critical alert fired"
    alert_no_time.timestamp = None

    formatted = manager._format_console(alert_no_time)
    manager.close()

    assert formatted == "[CRITICAL] Rule: critical_rule - Msg: Critical alert fired"


def test_close_handles_multiple_calls_safely(tmp_path):
    """Verifies that calling close() multiple times does not raise an exception."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file)

    manager.close()
    assert manager._file.closed

    # Second call should be safe
    manager.close()