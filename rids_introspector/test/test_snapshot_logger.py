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

import pytest

import snapshot_logger
from graph_builder import GraphBuilder
from rtps_parser import EndpointDiscovered
from snapshot_logger import SnapshotLogger


def test_logger_writes_one_valid_jsonl_snapshot(tmp_path, monkeypatch):
    output_file = tmp_path / "nested" / "run" / "snapshots.jsonl"
    builder = GraphBuilder()
    builder.process_event(
        EndpointDiscovered("endpoint-guid", "participant-a", "/scan", "type", {}, "publisher")
    )
    logger = SnapshotLogger(builder, output_file=str(output_file), interval=0.01)

    def stop_after_one_snapshot(_interval):
        logger._running = False

    logger._running = True
    monkeypatch.setattr(snapshot_logger.time, "sleep", stop_after_one_snapshot)
    logger._run()

    lines = output_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["snapshot_id"] == 0
    assert record["graph"]["stats"]["num_edges"] == 1


def test_logger_appends_to_existing_jsonl_file(tmp_path, monkeypatch):
    output_file = tmp_path / "snapshots.jsonl"
    output_file.write_text('{"previous": true}\n', encoding="utf-8")
    logger = SnapshotLogger(GraphBuilder(), output_file=str(output_file), interval=1.0)

    monkeypatch.setattr(snapshot_logger.time, "sleep", lambda _interval: setattr(logger, "_running", False))
    logger._running = True
    logger._run()

    lines = output_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"previous": True}
    assert json.loads(lines[1])["snapshot_id"] == 0


def test_logger_rejects_non_positive_interval():
    with pytest.raises(ValueError):
        SnapshotLogger(GraphBuilder(), interval=0)