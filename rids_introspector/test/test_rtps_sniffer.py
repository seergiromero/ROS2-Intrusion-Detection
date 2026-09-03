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

import time
from typing import ClassVar

import pytest
from scapy.all import IP, UDP, Raw

from rtps_fixtures import REAL_ENDPOINT_GUID, REAL_SEDP_SUBSCRIPTION_PACKET, REAL_TOPIC_NAME
from rtps_parser import EntityDisposed, EndpointDiscovered, ParticipantDiscovered
import rtps_sniffer
from rtps_sniffer import RTPSSniffer


def make_scapy_packet(raw_payload: bytes, sport: int = 60318, dport: int = 7416):
    """Wraps raw bytes in an in-memory IP/UDP scapy packet, as if captured on 'lo'."""
    return IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=sport, dport=dport) / Raw(load=raw_payload)


@pytest.fixture
def sniffer():
    s = RTPSSniffer(interface="lo", debug=False)
    s.running = True  # allow _lease_reaper_loop tests to run without calling start()
    return s


@pytest.fixture
def callback_log():
    events = []

    def cb(kind, ident):
        events.append((kind, ident))

    return events, cb


class FakeAsyncSniffer:
    instances: ClassVar[list["FakeAsyncSniffer"]] = []
    fail_on_start = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.start_calls = 0
        self.stop_calls = 0
        self.instances.append(self)

    def start(self):
        self.start_calls += 1
        if self.fail_on_start:
            raise PermissionError("capture permission denied")

    def stop(self):
        self.stop_calls += 1


@pytest.fixture
def fake_sniffer(monkeypatch):
    FakeAsyncSniffer.instances = []
    FakeAsyncSniffer.fail_on_start = False
    monkeypatch.setattr(rtps_sniffer, "AsyncSniffer", FakeAsyncSniffer)
    return FakeAsyncSniffer


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_start_creates_capture_and_reaper(self, fake_sniffer):
        sniffer = RTPSSniffer(interface="lo", port_filter=None)

        sniffer.start()

        assert sniffer.running is True
        assert len(fake_sniffer.instances) == 1
        assert fake_sniffer.instances[0].start_calls == 1
        assert sniffer._reaper_thread is not None
        assert sniffer._reaper_thread.is_alive()

        sniffer.stop()

    def test_start_is_idempotent_while_running(self, fake_sniffer):
        sniffer = RTPSSniffer(interface="lo")

        sniffer.start()
        sniffer.start()

        assert len(fake_sniffer.instances) == 1
        assert fake_sniffer.instances[0].start_calls == 1

        sniffer.stop()

    def test_stop_stops_capture_and_waits_for_reaper(self, fake_sniffer):
        sniffer = RTPSSniffer(interface="lo")
        sniffer.start()
        capture = fake_sniffer.instances[0]
        reaper_thread = sniffer._reaper_thread

        sniffer.stop()

        assert capture.stop_calls == 1
        assert sniffer.running is False
        assert not reaper_thread.is_alive()

    def test_stop_is_idempotent(self, fake_sniffer):
        sniffer = RTPSSniffer(interface="lo")
        sniffer.start()
        capture = fake_sniffer.instances[0]

        sniffer.stop()
        sniffer.stop()

        assert capture.stop_calls == 1

    def test_failed_start_resets_running_state(self, fake_sniffer):
        fake_sniffer.fail_on_start = True
        sniffer = RTPSSniffer(interface="lo")

        with pytest.raises(PermissionError):
            sniffer.start()

        assert sniffer.running is False
        assert sniffer._sniffer is None
        assert sniffer._reaper_thread is None

    def test_restart_clears_stop_event_and_starts_new_reaper(self, fake_sniffer):
        sniffer = RTPSSniffer(interface="lo")

        sniffer.start()
        first_reaper = sniffer._reaper_thread
        sniffer.stop()

        sniffer.start()
        second_reaper = sniffer._reaper_thread

        assert len(fake_sniffer.instances) == 2
        assert sniffer.running is True
        assert second_reaper is not first_reaper
        assert second_reaper.is_alive()

        sniffer.stop()


# ---------------------------------------------------------------------------
# _process_packet: real capture through the full pipeline
# ---------------------------------------------------------------------------

class TestProcessPacket:
    def test_real_capture_updates_discovered_endpoints(self, sniffer, callback_log):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        pkt = make_scapy_packet(REAL_SEDP_SUBSCRIPTION_PACKET)
        sniffer._process_packet(pkt)

        assert REAL_ENDPOINT_GUID in sniffer.discovered_endpoints
        assert sniffer.discovered_endpoints[REAL_ENDPOINT_GUID]["topic"] == REAL_TOPIC_NAME
        assert ("ENDPOINT_ADDED", REAL_ENDPOINT_GUID) in events

    def test_duplicate_packet_does_not_fire_callback_twice(self, sniffer, callback_log):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        pkt = make_scapy_packet(REAL_SEDP_SUBSCRIPTION_PACKET)
        sniffer._process_packet(pkt)
        sniffer._process_packet(pkt)  # same endpoint announced again

        added_events = [e for e in events if e[0] == "ENDPOINT_ADDED"]
        assert len(added_events) == 1  # only the first sighting is "new"
        assert len(sniffer.discovered_endpoints) == 1

    def test_duplicate_endpoint_updates_state_and_emits_update(self, sniffer, callback_log):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        first = EndpointDiscovered(
            guid="endpoint-guid",
            guid_prefix="participant-guid",
            topic="/scan",
            type_name="old_type",
            qos={"reliability": "BEST_EFFORT"},
            role="publisher",
        )
        updated = EndpointDiscovered(
            guid="endpoint-guid",
            guid_prefix="participant-guid",
            topic="/scan",
            type_name="new_type",
            qos={"reliability": "RELIABLE"},
            role="publisher",
        )

        sniffer._handle_event(first)
        sniffer._handle_event(updated)

        assert sniffer.discovered_endpoints["endpoint-guid"]["type"] == "new_type"
        assert sniffer.discovered_endpoints["endpoint-guid"]["qos"] == {"reliability": "RELIABLE"}
        assert ("ENDPOINT_UPDATED", "endpoint-guid") in events

    def test_duplicate_participant_renews_last_seen_and_emits_update(self, sniffer, callback_log, monkeypatch):
        events, cb = callback_log
        sniffer.on_update_callback = cb
        current_time = iter((100.0, 110.0))
        monkeypatch.setattr(rtps_sniffer.time, "time", lambda: next(current_time))

        participant = ParticipantDiscovered("participant-guid", "010f", lease_duration=20.0)
        sniffer._handle_event(participant)
        sniffer._handle_event(participant)

        assert sniffer.discovered_participants["participant-guid"]["last_seen"] == 110.0
        assert ("PARTICIPANT_UPDATED", "participant-guid") in events

    def test_non_udp_packet_is_ignored(self, sniffer, callback_log):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        pkt = IP(src="127.0.0.1", dst="127.0.0.1")  # no UDP layer
        sniffer._process_packet(pkt)

        assert sniffer.discovered_endpoints == {}
        assert sniffer.discovered_participants == {}
        assert events == []

    def test_malformed_payload_does_not_raise_or_change_state(self, sniffer):
        garbage_pkt = make_scapy_packet(b"not an rtps packet at all")
        sniffer._process_packet(garbage_pkt)  # must not raise
        assert sniffer.discovered_endpoints == {}
        assert sniffer.discovered_participants == {}


# ---------------------------------------------------------------------------
# Dispose handling — regression tests for the over-purge bug
# ---------------------------------------------------------------------------

class TestDisposeHandling:
    def test_endpoint_dispose_removes_only_the_target_endpoint(self, sniffer, callback_log):
        """
        Regression test for the bug where a single dispose message purged
        every endpoint belonging to the same guid_prefix. Two endpoints from
        the same participant are seeded; disposing one must leave the other
        untouched.
        """
        events, cb = callback_log
        sniffer.on_update_callback = cb

        prefix = "01:0f:39:63:48:65:43:07:00:00:00:00"
        sniffer.discovered_endpoints = {
            "guid-a": {"guid": "guid-a", "guid_prefix": prefix, "topic": "/scan", "type": "t", "qos": {}, "last_seen": time.time()},
            "guid-b": {"guid": "guid-b", "guid_prefix": prefix, "topic": "/cmd_vel", "type": "t", "qos": {}, "last_seen": time.time()},
        }

        dispose_event = EntityDisposed(
            guid_prefix=prefix, writer_id="00:00:04:c2", seq_num=1, disposed_guid="guid-a", is_participant=False
        )
        sniffer._handle_event(dispose_event)

        assert "guid-a" not in sniffer.discovered_endpoints
        assert "guid-b" in sniffer.discovered_endpoints  # <- the bug would have removed this too
        assert ("ENDPOINT_DISPOSED", "guid-a") in events

    def test_participant_dispose_cascades_to_its_endpoints_only(self, sniffer, callback_log):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        prefix_a = "aa:aa:aa:aa:aa:aa:aa:aa:00:00:00:00"
        prefix_b = "bb:bb:bb:bb:bb:bb:bb:bb:00:00:00:00"
        sniffer.discovered_participants = {
            prefix_a: {"guid_prefix": prefix_a, "vendor_id": "010f", "last_seen": time.time(), "lease_duration": 20.0},
            prefix_b: {"guid_prefix": prefix_b, "vendor_id": "010f", "last_seen": time.time(), "lease_duration": 20.0},
        }
        sniffer.discovered_endpoints = {
            "a1": {"guid": "a1", "guid_prefix": prefix_a, "topic": "/scan", "type": "t", "qos": {}, "last_seen": time.time()},
            "b1": {"guid": "b1", "guid_prefix": prefix_b, "topic": "/odom", "type": "t", "qos": {}, "last_seen": time.time()},
        }

        dispose_event = EntityDisposed(
            guid_prefix=prefix_a, writer_id="00:01:00:c2", seq_num=1, disposed_guid=prefix_a, is_participant=True
        )
        sniffer._handle_event(dispose_event)

        assert prefix_a not in sniffer.discovered_participants
        assert prefix_b in sniffer.discovered_participants
        assert "a1" not in sniffer.discovered_endpoints
        assert "b1" in sniffer.discovered_endpoints  # different participant, must survive
        assert ("PARTICIPANT_DISPOSED", prefix_a) in events
        assert ("ENDPOINT_DISPOSED", "a1") in events

    def test_dispose_with_undecodable_guid_purges_nothing(self, sniffer, callback_log):
        """
        Regression test for the "don't guess" fix: if the parser could not
        determine which entity a dispose message refers to, the sniffer must
        leave all existing state untouched rather than falling back to
        purging by guid_prefix.
        """
        events, cb = callback_log
        sniffer.on_update_callback = cb

        prefix = "01:0f:39:63:48:65:43:07:00:00:00:00"
        sniffer.discovered_endpoints = {
            "guid-a": {"guid": "guid-a", "guid_prefix": prefix, "topic": "/scan", "type": "t", "qos": {}, "last_seen": time.time()},
        }

        dispose_event = EntityDisposed(
            guid_prefix=prefix, writer_id="00:00:04:c2", seq_num=1, disposed_guid=None, is_participant=False
        )
        sniffer._handle_event(dispose_event)

        assert "guid-a" in sniffer.discovered_endpoints
        assert events == []


# ---------------------------------------------------------------------------
# Lease expiration (silent participants)
# ---------------------------------------------------------------------------

class TestLeaseReaper:
    def test_expires_participant_past_its_lease_duration(self, sniffer, callback_log, monkeypatch):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        stale_guid = "01:0f:39:63:d9:d9:a5:9f:00:00:00:00"
        sniffer.discovered_participants[stale_guid] = {
            "guid_prefix": stale_guid,
            "vendor_id": "010f",
            "last_seen": time.time() - 100,  # long silent
            "lease_duration": 5.0,
        }
        sniffer.discovered_endpoints["ep-1"] = {
            "guid": "ep-1", "guid_prefix": stale_guid, "topic": "/scan", "type": "t", "qos": {}, "last_seen": time.time(),
        }

        # Run exactly one reaper iteration: let the first wait continue and
        # make the next wait stop the loop.
        wait_calls = 0

        def fake_wait(_seconds):
            nonlocal wait_calls
            wait_calls += 1
            return wait_calls > 1

        monkeypatch.setattr(sniffer._stop_event, "wait", fake_wait)
        sniffer._lease_reaper_loop()

        assert stale_guid not in sniffer.discovered_participants
        assert "ep-1" not in sniffer.discovered_endpoints  # cascaded purge
        assert ("PARTICIPANT_EXPIRED", stale_guid) in events
        assert ("ENDPOINT_EXPIRED", "ep-1") in events

    def test_does_not_expire_recently_seen_participant(self, sniffer, callback_log, monkeypatch):
        events, cb = callback_log
        sniffer.on_update_callback = cb

        fresh_guid = "01:0f:39:63:aa:bb:cc:dd:00:00:00:00"
        sniffer.discovered_participants[fresh_guid] = {
            "guid_prefix": fresh_guid,
            "vendor_id": "010f",
            "last_seen": time.time(),  # just seen
            "lease_duration": 20.0,
        }

        monkeypatch.setattr(sniffer._stop_event, "wait", lambda _seconds: True)
        sniffer._lease_reaper_loop()

        assert fresh_guid in sniffer.discovered_participants
        assert events == []

    def test_expiration_propagates_to_graph(self, sniffer, monkeypatch):
        from graph_builder import GraphBuilder

        builder = GraphBuilder()
        sniffer.on_update_callback = builder.process_event
        prefix = "01:02:03:04:05:06:07:08:09:0a:0b:0c"
        sniffer.discovered_participants[prefix] = {
            "guid_prefix": prefix,
            "vendor_id": "010f",
            "last_seen": 0.0,
            "lease_duration": 1.0,
        }
        sniffer.discovered_endpoints["endpoint-guid"] = {
            "guid": "endpoint-guid",
            "guid_prefix": prefix,
            "topic": "/scan",
            "type": "type",
            "qos": {},
            "role": "publisher",
            "last_seen": 0.0,
        }
        builder.process_event(
            ParticipantDiscovered(prefix, "010f", lease_duration=1.0)
        )
        builder.process_event(
            EndpointDiscovered("endpoint-guid", prefix, "/scan", "type", {}, "publisher")
        )

        monkeypatch.setattr(rtps_sniffer.time, "time", lambda: 2.0)
        wait_calls = 0

        def fake_wait(_seconds):
            nonlocal wait_calls
            wait_calls += 1
            return wait_calls > 1

        monkeypatch.setattr(sniffer._stop_event, "wait", fake_wait)
        sniffer._lease_reaper_loop()

        assert not builder.graph.has_node(f"participant:{prefix}")
        assert not builder.graph.has_node("topic:/scan")


# ---------------------------------------------------------------------------
# get_captured_state
# ---------------------------------------------------------------------------

class TestGetCapturedState:
    def test_returns_independent_copy_not_live_references(self, sniffer):
        pkt = make_scapy_packet(REAL_SEDP_SUBSCRIPTION_PACKET)
        sniffer._process_packet(pkt)

        state = sniffer.get_captured_state()
        state["endpoints"].clear()  # mutate the returned copy

        # Internal state must be unaffected by mutating the snapshot.
        assert len(sniffer.discovered_endpoints) == 1