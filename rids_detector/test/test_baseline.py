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

from pathlib import Path

import pytest

from rids_detector.baseline import BaselineLoader, BaselineValidationError


VALID_BASELINE = {
    "version": 1,
    "created_at": "2026-09-03T00:00:00Z",
    "source": "test",
    "critical_topics": ["/cmd_vel", "/scan"],
    "participants": ["participant-a"],
    "endpoints": [
        {
            "guid": "endpoint-a",
            "participant": "participant-a",
            "topic": "/scan",
            "role": "publisher",
            "type_name": "sensor_msgs/msg/LaserScan",
            "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
        }
    ],
}


class TestBaselineLoader:
    def test_loads_valid_yaml_file(self, tmp_path):
        path = tmp_path / "baseline.yaml"
        path.write_text(
            "version: 1\n"
            "created_at: '2026-09-03T00:00:00Z'\n"
            "source: test\n"
            "critical_topics: [/cmd_vel]\n"
            "participants: [participant-a]\n"
            "endpoints:\n"
            "  - guid: endpoint-a\n"
            "    participant: participant-a\n"
            "    topic: /cmd_vel\n"
            "    role: publisher\n"
            "    type_name: example/msg/Cmd\n"
            "    qos: {reliability: RELIABLE}\n",
            encoding="utf-8",
        )

        baseline = BaselineLoader().load(path)

        assert baseline.version == 1
        assert baseline.critical_topics == ("/cmd_vel",)
        assert baseline.endpoints[0].role == "publisher"
        assert baseline.endpoint_guids() == {"endpoint-a"}

    def test_missing_root_field_is_invalid(self):
        data = dict(VALID_BASELINE)
        del data["endpoints"]

        with pytest.raises(BaselineValidationError, match="endpoints"):
            BaselineLoader().from_dict(data)

    def test_non_mapping_baseline_is_invalid(self):
        with pytest.raises(BaselineValidationError, match="mapping"):
            BaselineLoader().from_dict(["not", "a", "mapping"])

    def test_invalid_endpoint_role_is_rejected(self):
        data = _copy_valid_baseline()
        data["endpoints"][0]["role"] = "unknown"

        with pytest.raises(BaselineValidationError, match="role"):
            BaselineLoader().from_dict(data)

    def test_duplicate_endpoint_guid_is_rejected(self):
        data = _copy_valid_baseline()
        data["endpoints"].append(dict(data["endpoints"][0]))

        with pytest.raises(BaselineValidationError, match="unique"):
            BaselineLoader().from_dict(data)

    def test_endpoint_must_reference_declared_participant(self):
        data = _copy_valid_baseline()
        data["endpoints"][0]["participant"] = "unknown-participant"

        with pytest.raises(BaselineValidationError, match="missing"):
            BaselineLoader().from_dict(data)

    def test_invalid_qos_is_rejected(self):
        data = _copy_valid_baseline()
        data["endpoints"][0]["qos"] = {"reliability": 1}

        with pytest.raises(BaselineValidationError, match="qos"):
            BaselineLoader().from_dict(data)

    def test_missing_file_is_reported(self, tmp_path):
        missing_path = Path(tmp_path) / "missing.yaml"

        with pytest.raises(FileNotFoundError):
            BaselineLoader().load(missing_path)

    def test_example_baseline_is_valid(self):
        path = Path(__file__).parents[1] / "config" / "baseline.yaml"

        baseline = BaselineLoader().load(path)

        assert "/cmd_vel" in baseline.critical_topics
        assert len(baseline.participants) == 2
        assert len(baseline.endpoints) == 2


def _copy_valid_baseline():
    return {
        **VALID_BASELINE,
        "critical_topics": list(VALID_BASELINE["critical_topics"]),
        "participants": list(VALID_BASELINE["participants"]),
        "endpoints": [dict(endpoint, qos=dict(endpoint["qos"])) for endpoint in VALID_BASELINE["endpoints"]],
    }
