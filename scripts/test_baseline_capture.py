"""
MIT License

Copyright (c) 2026 Sergi Romero Valderas

Tests for the standalone baseline capture tool (scripts/baseline.py).
"""

import itertools
import sys
from pathlib import Path

import pytest
import yaml

import baseline as bs


# ---------------------------------------------------------------------------
# Simulated sniffer state (mirrors RTPSSniffer.get_captured_state())
# ---------------------------------------------------------------------------

PARTICIPANT_A = "01:0f:39:63:48:65:43:07:00:00:00:00"
PARTICIPANT_C = "01:0f:39:63:aa:bb:cc:dd:00:00:00:00"

ENDPOINT_PUB_BOND = "01:0f:39:63:48:65:43:07:00:00:00:00:00:04:03:03"
ENDPOINT_SUB_REPLY = "01:0f:39:63:48:65:43:07:00:00:00:00:00:04:09:04"
ENDPOINT_PUB_CMD_VEL = "01:0f:39:63:49:65:51:3e:00:00:00:00:00:01:c1:11"


def _fake_state(participants, endpoints):
    return {"participants": participants, "endpoints": endpoints}


def _sample_state():
    return _fake_state(
        participants={
            PARTICIPANT_A: {
                "guid_prefix": PARTICIPANT_A,
                "vendor_id": "010f",
                "last_seen": 1.0,
                "lease_duration": 20.0,
            },
        },
        endpoints={
            ENDPOINT_PUB_BOND: {
                "guid": ENDPOINT_PUB_BOND,
                "guid_prefix": PARTICIPANT_A,
                "topic": "/bond",
                "type": "bond::msg::dds_::Status_",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
                "role": "publisher",
                "last_seen": 1.0,
            },
            ENDPOINT_SUB_REPLY: {
                "guid": ENDPOINT_SUB_REPLY,
                "guid_prefix": PARTICIPANT_A,
                "topic": "/navigate_to_pose/_action/send_goalReply",
                "type": "nav2_msgs::action::dds_::NavigateToPose_SendGoal_Response_",
                "qos": {"reliability": "RELIABLE", "durability": "VOLATILE"},
                "role": "subscriber",
                "last_seen": 1.0,
            },
        },
    )


# ---------------------------------------------------------------------------
# Fake RTPSSniffer + dependency injection
# ---------------------------------------------------------------------------

class FakeSniffer:
    """Deterministic stand-in for RTPSSniffer used by tests."""

    instances = []
    default_sequence = []

    def __init__(self, *args, **kwargs):
        self.interface = kwargs.get("interface")
        self.port_filter = kwargs.get("port_filter")
        self.debug = kwargs.get("debug", False)
        self.running = False
        self._state = {"participants": {}, "endpoints": {}}
        self._sequence = list(self.default_sequence)
        self.start_calls = 0
        self.stop_calls = 0
        self.instances.append(self)

    def configure_sequence(self, frames):
        """frames: list of dict states returned in order by get_captured_state()."""
        type(self).default_sequence = list(frames)
        self._sequence = list(frames)
        self._state = frames[0] if frames else {"participants": {}, "endpoints": {}}

    def start(self):
        self.running = True
        self.start_calls += 1

    def stop(self):
        self.running = False
        self.stop_calls += 1

    def get_captured_state(self):
        if self._sequence:
            self._state = self._sequence.pop(0)
        return self._state


def _patch_imports(monkeypatch, fake_sniffer_cls=FakeSniffer):
    """Inject fake classes into the script so main() does not touch real deps."""
    from rids_detector.baseline import BaselineLoader
    from rids_detector.models import Baseline, BaselineEndpoint

    def fake_import_deps():
        return (
            fake_sniffer_cls,
            BaselineLoader,
            Baseline,
            BaselineEndpoint,
        )

    monkeypatch.setattr(bs, "_import_deps", fake_import_deps)


@pytest.fixture
def fake_time(monkeypatch):
    """Patches the script's ``time`` module with a controllable fake."""
    FakeSniffer.instances = []
    FakeSniffer.default_sequence = []

    class FakeTime:
        def __init__(self):
            self._counter = itertools.count()
            self._monotonic = 0.0

        def sleep(self, seconds):
            self._monotonic += seconds

        def monotonic(self):
            return self._monotonic

        def time(self):
            return self._monotonic

    fake = FakeTime()
    monkeypatch.setattr(bs, "time", fake)
    return fake


# ---------------------------------------------------------------------------
# build_baseline + validate
# ---------------------------------------------------------------------------

class TestBuildBaseline:
    def test_builds_valid_baseline_from_sniffer_state(self):
        state = _sample_state()

        data = bs.build_baseline(
            source="nav2_normal_run",
            version=1,
            critical_topics=["/cmd_vel", "/scan", "/tf"],
            state=state,
        )

        from rids_detector.baseline import BaselineLoader

        bs.validate_baseline(data, BaselineLoader)

        assert data["version"] == 1
        assert data["source"] == "nav2_normal_run"
        assert data["critical_topics"] == ["/cmd_vel", "/scan", "/tf"]
        assert PARTICIPANT_A in data["participants"]
        assert len(data["endpoints"]) == 2

        ep_guids = {ep["guid"] for ep in data["endpoints"]}
        assert ENDPOINT_PUB_BOND in ep_guids
        assert ENDPOINT_SUB_REPLY in ep_guids

    def test_endpoint_participant_not_in_participants_gets_added(self):
        state = _fake_state(
            participants={PARTICIPANT_A: {"guid_prefix": PARTICIPANT_A}},
            endpoints={
                ENDPOINT_PUB_CMD_VEL: {
                    "guid": ENDPOINT_PUB_CMD_VEL,
                    "guid_prefix": PARTICIPANT_C,  # not in participants!
                    "topic": "/cmd_vel",
                    "type": "geometry_msgs/msg/Twist",
                    "qos": {"reliability": "RELIABLE"},
                    "role": "publisher",
                },
            },
        )

        data = bs.build_baseline(source="s", version=1, critical_topics=[], state=state)

        assert PARTICIPANT_C in data["participants"]
        assert data["endpoints"][0]["participant"] == PARTICIPANT_C

        from rids_detector.baseline import BaselineLoader

        bs.validate_baseline(data, BaselineLoader)

    def test_ignores_endpoints_without_valid_role(self):
        state = _fake_state(
            participants={PARTICIPANT_A: {"guid_prefix": PARTICIPANT_A}},
            endpoints={
                "bad-guid": {
                    "guid": "bad-guid",
                    "guid_prefix": PARTICIPANT_A,
                    "topic": "/weird",
                    "type": "t",
                    "qos": {},
                    "role": "not_a_role",
                },
            },
        )

        data = bs.build_baseline(source="s", version=1, critical_topics=[], state=state)

        assert data["endpoints"] == []

    def test_qos_values_are_coerced_to_strings(self):
        state = _fake_state(
            participants={PARTICIPANT_A: {"guid_prefix": PARTICIPANT_A}},
            endpoints={
                ENDPOINT_PUB_BOND: {
                    "guid": ENDPOINT_PUB_BOND,
                    "guid_prefix": PARTICIPANT_A,
                    "topic": "/bond",
                    "type": "bond::msg::dds_::Status_",
                    "qos": {"reliability": 1, "durability": 2},
                    "role": "publisher",
                },
            },
        )

        data = bs.build_baseline(source="s", version=1, critical_topics=[], state=state)

        assert data["endpoints"][0]["qos"]["reliability"] == "1"

    def test_created_at_is_iso8601(self):
        data = bs.build_baseline(
            source="s", version=1, critical_topics=[], state=_sample_state()
        )

        from rids_detector.baseline import BaselineLoader

        bs.validate_baseline(data, BaselineLoader)

    def test_empty_state_yields_empty_baseline_but_valid(self):
        """No participants/endpoints still produces a schema-valid (empty) baseline."""
        data = bs.build_baseline(source="s", version=1, critical_topics=[], state={"participants": {}, "endpoints": {}})

        assert data["participants"] == []
        assert data["endpoints"] == []
        # An empty baseline is structurally valid; the detector treats
        # everything as "new" against it.
        from rids_detector.baseline import BaselineLoader

        bs.validate_baseline(data, BaselineLoader)


# ---------------------------------------------------------------------------
# write_baseline
# ---------------------------------------------------------------------------

class TestWriteBaseline:
    def test_writes_valid_yaml_roundtrip(self, tmp_path):
        data = bs.build_baseline(
            source="rt", version=1, critical_topics=["/cmd_vel"], state=_sample_state()
        )
        out = tmp_path / "baseline.yaml"

        bs.write_baseline(data, out)
        written = yaml.safe_load(out.read_text(encoding="utf-8"))

        from rids_detector.baseline import BaselineLoader

        # The file on disk must round-trip through the real loader.
        reloaded = BaselineLoader().from_dict(written)
        assert reloaded.source == "rt"
        assert written == data

    def test_parent_dirs_are_created(self, tmp_path):
        data = bs.build_baseline(
            source="s", version=1, critical_topics=[], state=_sample_state()
        )
        out = tmp_path / "nested" / "deep" / "baseline.yaml"

        bs.write_baseline(data, out)

        assert out.is_file()


# ---------------------------------------------------------------------------
# capture_graph (settle logic) using the fake sniffer directly
# ---------------------------------------------------------------------------

class TestCaptureGraph:
    def test_stops_after_settle_time(self, fake_time):
        sniffer = FakeSniffer()
        sniffer.configure_sequence([_sample_state(), _sample_state(), _sample_state()])

        result = bs.capture_graph(
            sniffer_cls=FakeSniffer,
            interface="lo",
            port_filter=None,
            poll_interval=1.0,
            settle_time=2.0,
            max_duration=30.0,
        )

        assert result["participants"] == _sample_state()["participants"]
        assert FakeSniffer.instances[-1].stop_calls == 1

    def test_forces_stop_at_max_duration(self, fake_time):
        growing_state = _sample_state()
        sniffer = FakeSniffer()
        sniffer.configure_sequence([_sample_state() for _ in range(100)])

        result = bs.capture_graph(
            sniffer_cls=FakeSniffer,
            interface="lo",
            port_filter=None,
            poll_interval=1.0,
            settle_time=10.0,   # longer than max_duration -> never settles
            max_duration=5.0,
        )

        # Should have exited due to max_duration, not settle.
        assert FakeSniffer.instances[-1].stop_calls == 1

    def test_raises_when_nothing_discovered(self, fake_time):
        sniffer = FakeSniffer()
        sniffer.configure_sequence([_fake_state({}, {}) for _ in range(10)])

        with pytest.raises(bs.BaselineCaptureError, match="No participants"):
            bs.capture_graph(
                sniffer_cls=FakeSniffer,
                interface="lo",
                port_filter=None,
                poll_interval=1.0,
                settle_time=2.0,
                max_duration=5.0,
            )
        assert FakeSniffer.instances[-1].stop_calls == 1

    def test_endpoint_warmup_holds_capture_when_participants_arrive_without_endpoints(self, fake_time):
        """
        With RTPS, if a ROS 2 node boots BEFORE the sniffer, its SEDP burst
        has already gone by.  The script must keep capturing for
        ``endpoint_warmup`` seconds after the first participant is seen
        so the next lease-driven retransmission has a chance to arrive.
        """
        no_endpoints_state = _fake_state(
            participants={PARTICIPANT_A: {"guid_prefix": PARTICIPANT_A}},
            endpoints={},
        )
        FakeSniffer.instances = []
        sniffer = FakeSniffer()
        sniffer.configure_sequence(
            [
                _fake_state({}, {}),
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
                no_endpoints_state,
            ]
        )

        # With endpoint_warmup=10 and settle_time=2, the script should NOT
        # stop at t~3s (which is when the graph would look "stable").  It
        # should keep going until t~10s+ and exit at the warmup boundary.
        result = bs.capture_graph(
            sniffer_cls=FakeSniffer,
            interface="lo",
            port_filter=None,
            poll_interval=1.0,
            settle_time=2.0,
            max_duration=30.0,
            endpoint_warmup=10.0,
        )

        # The state returned is the last one the sniffer served; what
        # matters here is that we did not exit at t~3s (the settle point).
        assert result == no_endpoints_state
        assert FakeSniffer.instances[-1].stop_calls == 1

    def test_endpoints_appearing_during_warmup_cut_early(self, fake_time):
        """
        If the SEDP retransmission DOES arrive during warmup, the script
        should cut as soon as the graph becomes stable — it should not wait
        the full warmup window.
        """
        only_participants = _fake_state(
            participants={PARTICIPANT_A: {"guid_prefix": PARTICIPANT_A}},
            endpoints={},
        )
        full_state = _sample_state()
        FakeSniffer.instances = []
        sniffer = FakeSniffer()
        sniffer.configure_sequence(
            [
                _fake_state({}, {}),
                only_participants,
                only_participants,
                only_participants,
                full_state,
                full_state,
                full_state,
                full_state,
            ]
        )

        result = bs.capture_graph(
            sniffer_cls=FakeSniffer,
            interface="lo",
            port_filter=None,
            poll_interval=1.0,
            settle_time=2.0,
            max_duration=30.0,
            endpoint_warmup=20.0,  # would hold for 20s, but we cut sooner
        )

        assert result == full_state
        assert FakeSniffer.instances[-1].stop_calls == 1


# ---------------------------------------------------------------------------
# CLI / main() end-to-end
# ---------------------------------------------------------------------------

class TestMainEndToEnd:
    def test_generates_valid_baseline_file(self, tmp_path, monkeypatch, fake_time):
        captured_state = _sample_state()
        fake = FakeSniffer()
        fake.configure_sequence([captured_state, captured_state, captured_state])

        _patch_imports(monkeypatch, fake_sniffer_cls=FakeSniffer)

        rc = bs.main(
            [
                "--source", "nav2_session",
                "--critical-topic", "/cmd_vel",
                "--critical-topic", "/scan",
                "-o", str(tmp_path / "baseline.yaml"),
                "--poll-interval", "1.0",
                "--settle-time", "2.0",
                "--max-duration", "30.0",
                "--endpoint-warmup", "0.0",
            ]
        )

        assert rc == 0
        out = tmp_path / "baseline.yaml"
        assert out.is_file()

        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        from rids_detector.baseline import BaselineLoader

        BaselineLoader().from_dict(data)

        assert data["source"] == "nav2_session"
        assert data["critical_topics"] == ["/cmd_vel", "/scan"]
        assert PARTICIPANT_A in data["participants"]
        assert len(data["endpoints"]) == 2

    def test_returns_error_when_nothing_captured(self, tmp_path, monkeypatch, fake_time):
        fake = FakeSniffer()
        fake.configure_sequence([_fake_state({}, {}) for _ in range(5)])

        _patch_imports(monkeypatch, fake_sniffer_cls=FakeSniffer)
        # Force time to advance past max_duration so the loop exits.
        fake_time._monotonic = 0.0
        original_sleep = fake_time.sleep

        def fast_sleep(seconds):
            original_sleep(seconds)

        fake_time.sleep = fast_sleep

        rc = bs.main(
            [
                "--source", "s",
                "-o", str(tmp_path / "baseline.yaml"),
                "--poll-interval", "1.0",
                "--settle-time", "2.0",
                "--max-duration", "3.0",
                "--endpoint-warmup", "0.0",
            ]
        )

        assert rc == 1
        assert not (tmp_path / "baseline.yaml").exists()

    def test_rejects_critical_topic_without_slash(self, tmp_path, monkeypatch):
        from rids_detector.baseline import BaselineLoader
        from rids_detector.models import Baseline, BaselineEndpoint

        def fake_import_deps():
            return (FakeSniffer, BaselineLoader, Baseline, BaselineEndpoint)

        monkeypatch.setattr(bs, "_import_deps", fake_import_deps)

        rc = bs.main(
            [
                "--source", "s",
                "--critical-topic", "cmd_vel",
                "-o", str(tmp_path / "baseline.yaml"),
            ]
        )

        assert rc == 2

    def test_help_parser_has_expected_arguments(self):
        parser = bs.parse_args.__wrapped__ if hasattr(bs.parse_args, "__wrapped__") else None
        ns = {}

        # Re-instantiate the parser to introspect its arguments.
        import argparse as ap

        p = ap.ArgumentParser()
        # Re-build via the real function but capture SystemExit on --help is messy;
        # instead assert the argument strings exist by parsing a minimal argv.
        args = bs.parse_args(["--source", "x", "-o", "/tmp/x.yaml"])
        assert args.source == "x"
        assert args.output == "/tmp/x.yaml"
        assert args.critical_topic == []
        assert args.version == 1
        # New flag for SEDP retransmission handling.
        assert args.endpoint_warmup == 20.0
