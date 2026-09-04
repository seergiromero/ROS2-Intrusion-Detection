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
import logging
import pytest

from rids_detector.alert_manager import AlertManager, logger as alert_logger
from rids_detector.models import Alert


@pytest.fixture
def sample_alert() -> Alert:
    """Provides a realistic Alert instance with epoch timestamp and context."""
    return Alert(
        severity="WARNING",
        rule="check_new_participants",
        message="New participant detected",
        timestamp=1788516000.0,  # 2026-09-04T10:00:00Z
        participant="participant_A",
        endpoint="guid_123",
        topic="/chatter",
    )


# ------------------------------------------------------------------
# Tests: Lifecycle & File Management
# ------------------------------------------------------------------


def test_init_creates_directories_and_opens_file(tmp_path):
    """Verifies that AlertManager creates nested directories and opens the file."""
    output_file = tmp_path / "nested_dir" / "alerts.jsonl"

    manager = AlertManager(output_path=output_file)

    assert output_file.exists()
    assert manager._file is not None
    assert not manager._file.closed

    manager.close()
    assert manager._file.closed


def test_context_manager_usage(tmp_path, sample_alert: Alert):
    """Verifies that AlertManager can be used safely as a context manager."""
    output_file = tmp_path / "alerts.jsonl"

    with AlertManager(output_path=output_file, console_output=False) as manager:
        manager.emit(sample_alert)
        assert not manager._file.closed

    assert manager._file.closed


def test_close_handles_multiple_calls_safely(tmp_path):
    """Verifies that calling close() multiple times does not raise an exception."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file)

    manager.close()
    assert manager._file.closed

    # Second call should be safe
    manager.close()


def test_emit_after_close_raises_runtime_error(tmp_path, sample_alert: Alert):
    """Verifies that emitting an alert after closing the manager raises RuntimeError."""
    output_file = tmp_path / "alerts.jsonl"
    manager = AlertManager(output_path=output_file)
    manager.close()

    with pytest.raises(RuntimeError, match="AlertManager is closed"):
        manager.emit(sample_alert)


# ------------------------------------------------------------------
# Tests: Emission & JSONL Output
# ------------------------------------------------------------------


def test_emit_writes_jsonl_record(tmp_path, sample_alert: Alert):
    """Verifies that emit writes the formatted JSON record to the file."""
    output_file = tmp_path / "alerts.jsonl"

    with AlertManager(output_path=output_file, console_output=False) as manager:
        record = manager.emit(sample_alert)

    # Check returned dictionary
    assert record == sample_alert.to_dict()

    # Check file content
    content = output_file.read_text(encoding="utf-8").strip()
    written_data = json.loads(content)

    assert written_data["severity"] == "WARNING"
    assert written_data["rule"] == "check_new_participants"
    assert written_data["message"] == "New participant detected"
    assert written_data["participant"] == "participant_A"


# ------------------------------------------------------------------
# Tests: Logging & Console Formatting
# ------------------------------------------------------------------


def test_emit_logging_output_enabled(tmp_path, sample_alert: Alert, caplog):
    """Verifies that output is captured via logger when console_output=True."""
    alert_logger.propagate = True
    caplog.set_level(logging.WARNING, logger=alert_logger.name)

    output_file = tmp_path / "alerts.jsonl"

    with AlertManager(output_path=output_file, console_output=True) as manager:
        manager.emit(sample_alert)

    assert "check_new_participants" in caplog.text
    assert "New participant detected" in caplog.text
    assert "[Topic: /chatter | Participant: participant_A | Endpoint: guid_123]" in caplog.text


def test_emit_logging_output_disabled(tmp_path, sample_alert: Alert, caplog):
    """Verifies that nothing is logged when console_output=False."""
    alert_logger.propagate = True
    caplog.set_level(logging.INFO, logger=alert_logger.name)

    output_file = tmp_path / "alerts.jsonl"

    with AlertManager(output_path=output_file, console_output=False) as manager:
        manager.emit(sample_alert)

    assert caplog.text == ""


def test_format_console_with_context_and_formatted_timestamp(tmp_path):
    """Verifies console string formatting with timestamp conversion and metadata context."""
    output_file = tmp_path / "alerts.jsonl"
    alert = Alert(
        severity="CRITICAL",
        rule="check_unauthorized_critical_publishers",
        message="Critical publisher detected",
        timestamp=1788516000.0,
        topic="/cmd_vel",
        participant="bad_actor",
        endpoint="bad_actor.01",
    )

    with AlertManager(output_path=output_file) as manager:
        formatted = manager._format_console(alert)

    expected = (
        "[CRITICAL] 2026-09-04T10:00:00Z - "
        "Rule: check_unauthorized_critical_publishers - "
        "Msg: Critical publisher detected "
        "[Topic: /cmd_vel | Participant: bad_actor | Endpoint: bad_actor.01]"
    )
    assert formatted == expected


def test_format_console_without_timestamp_or_context(tmp_path):
    """Verifies console string formatting when optional context and timestamp are missing."""
    output_file = tmp_path / "alerts.jsonl"
    alert = Alert(
        severity="WARNING",
        rule="check_new_participants",
        message="Simple alert",
        timestamp=None,
    )

    with AlertManager(output_path=output_file) as manager:
        formatted = manager._format_console(alert)

    assert formatted == "[WARNING] Rule: check_new_participants - Msg: Simple alert"


def test_emit_info_alert_uses_info_logger(tmp_path, caplog):
    alert_logger.propagate = True
    caplog.set_level(logging.INFO, logger=alert_logger.name)
    alert = Alert(
        timestamp=1.0,
        severity="INFO",
        rule="check_new_topics",
        message="Nuevo tópico Ñandú",
        topic="/diagnóstico",
    )
    output_file = tmp_path / "alerts.jsonl"

    with AlertManager(output_path=output_file, console_output=True) as manager:
        manager.emit(alert)

    assert "check_new_topics" in caplog.text
    content = output_file.read_text(encoding="utf-8")
    assert "Ñandú" in content
    assert "diagnóstico" in content


def test_two_alerts_write_two_jsonl_lines(tmp_path, sample_alert: Alert):
    output_file = tmp_path / "alerts.jsonl"
    second = Alert(
        timestamp=2.0,
        severity="CRITICAL",
        rule="check_unauthorized_critical_publishers",
        message="Unauthorized publisher",
        topic="/cmd_vel",
    )

    with AlertManager(output_path=output_file, console_output=False) as manager:
        manager.emit(sample_alert)
        manager.emit(second)

    lines = output_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["rule"] == "check_new_participants"
    assert json.loads(lines[1])["severity"] == "CRITICAL"


def test_append_between_two_manager_instances(tmp_path, sample_alert: Alert):
    output_file = tmp_path / "alerts.jsonl"
    with AlertManager(output_path=output_file, console_output=False) as first:
        first.emit(sample_alert)
    with AlertManager(output_path=output_file, console_output=False) as second:
        second.emit(sample_alert)

    lines = [line for line in output_file.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2
