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

from rids_detector.detector import SnapshotReader


def test_missing_file_returns_empty(tmp_path):
    reader = SnapshotReader(tmp_path / "missing.jsonl")
    assert reader.read_new_snapshots() == []


def test_empty_lines_are_ignored(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    path.write_text("\n\n{\"id\": 1, \"participants\": {}, \"endpoints\": {}}\n\n", encoding="utf-8")

    snapshots = SnapshotReader(path).read_new_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0]["id"] == 1


def test_non_object_json_is_skipped(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    path.write_text("[1, 2]\n{\"id\": 2, \"participants\": {}, \"endpoints\": {}}\n", encoding="utf-8")

    snapshots = SnapshotReader(path).read_new_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0]["id"] == 2


def test_incomplete_line_is_completed_on_later_read(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    path.write_text('{"id": 1, "participants": {}, "endpoints": {}', encoding="utf-8")

    reader = SnapshotReader(path)
    assert reader.read_new_snapshots() == []

    with path.open("a", encoding="utf-8") as handle:
        handle.write("}\n")

    snapshots = reader.read_new_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0]["id"] == 1


def test_successive_reads_only_return_new_lines(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    reader = SnapshotReader(path)

    path.write_text('{"id": 1, "participants": {}, "endpoints": {}}\n', encoding="utf-8")
    first = reader.read_new_snapshots()
    second = reader.read_new_snapshots()

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"id": 2, "participants": {}, "endpoints": {}}\n')

    third = reader.read_new_snapshots()

    assert [item["id"] for item in first] == [1]
    assert second == []
    assert [item["id"] for item in third] == [2]


def test_truncated_file_resets_position(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    path.write_text(
        '{"id": 1, "participants": {}, "endpoints": {}}\n'
        '{"id": 2, "participants": {}, "endpoints": {}}\n',
        encoding="utf-8",
    )
    reader = SnapshotReader(path)
    assert len(reader.read_new_snapshots()) == 2

    path.write_text('{"id": 3, "participants": {}, "endpoints": {}}\n', encoding="utf-8")
    snapshots = reader.read_new_snapshots()
    assert [item["id"] for item in snapshots] == [3]


def test_malformed_json_is_skipped(tmp_path):
    path = tmp_path / "snapshots.jsonl"
    path.write_text(
        "{not json}\n{\"id\": 4, \"participants\": {}, \"endpoints\": {}}\n",
        encoding="utf-8",
    )
    snapshots = SnapshotReader(path).read_new_snapshots()
    assert [item["id"] for item in snapshots] == [4]


def test_reader_returns_duplicate_lines_for_detector_to_filter(tmp_path):
    record = {"id": "dup", "participants": {}, "endpoints": {}}
    path = tmp_path / "snapshots.jsonl"
    path.write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")

    snapshots = SnapshotReader(path).read_new_snapshots()
    assert len(snapshots) == 2
    assert snapshots[0]["id"] == snapshots[1]["id"] == "dup"
