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

import pytest

from rtps_fixtures import (
    REAL_CAPTURES,
    REAL_SEDP_SUBSCRIPTION_PACKET,
    build_cdr_string,
    build_data_submessage,
    build_parameter_list,
    build_rtps_packet,
    build_u32,
    hex_entity_id,
)
from rtps_parser import (
    EndpointDiscovered,
    EntityDisposed,
    ParticipantDiscovered,
    PID_DURABILITY,
    PID_ENDPOINT_GUID,
    PID_PARTICIPANT_GUID,
    PID_RELIABILITY,
    PID_TOPIC_NAME,
    PID_TYPE_NAME,
    RTPSParser,
)

# Maps the string names used in rtps_fixtures.RealCapture.expected_event_type
# to the actual dataclasses, so fixtures.py doesn't need to import
# rtps_parser's event classes just to reference them by type.
_EVENT_TYPES_BY_NAME = {
    "ParticipantDiscovered": ParticipantDiscovered,
    "EndpointDiscovered": EndpointDiscovered,
    "EntityDisposed": EntityDisposed,
}

# Verified against Wireshark's own decode of real traffic — see the note in
# rtps_fixtures.py. If you rename the classification constants in
# rtps_parser.py, prefer importing and using them here instead of these
# literals, so there is a single source of truth.
SPDP_PARTICIPANT_WRITER_ID = hex_entity_id("00:01:00:c2")
SEDP_SUBSCRIPTIONS_WRITER_ID = hex_entity_id("00:00:04:c2")
UNKNOWN_USER_WRITER_ID = hex_entity_id("12:34:56:02")  # not a builtin entity


# ---------------------------------------------------------------------------
# Ground-truth regression test: real captured packet
# ---------------------------------------------------------------------------

class TestRealCaptures:
    """
    The single most valuable tests in this file: they replay bytes that
    genuinely went over the wire (captured with Wireshark) and check the
    parser reconstructs exactly what Wireshark's own dissector reported.

    Add more real captures by appending entries to REAL_CAPTURES in
    rtps_fixtures.py — no new test code needed here, this loop picks them up
    automatically. Empty `hex_payload` placeholders (not yet captured) are
    skipped rather than failed.
    """

    @pytest.mark.parametrize("capture", REAL_CAPTURES, ids=lambda c: c.name)
    def test_real_capture_matches_expected_fields(self, capture):
        if not capture.hex_payload:
            pytest.skip(f"No real capture recorded yet for '{capture.name}' — see TODO in rtps_fixtures.py")

        expected_type = _EVENT_TYPES_BY_NAME[capture.expected_event_type]
        events = [e for e in RTPSParser.parse_packet(capture.payload) if isinstance(e, expected_type)]

        assert len(events) == 1, (
            f"Expected exactly one {capture.expected_event_type} event for '{capture.name}', got {len(events)}"
        )
        event = events[0]
        for field, expected_value in capture.expected_fields.items():
            actual_value = getattr(event, field)
            assert actual_value == expected_value, (
                f"[{capture.name}] field '{field}': expected {expected_value!r}, got {actual_value!r}"
            )

    def test_only_the_data_submessage_produces_an_event(self):
        """
        The SEDP subscription frame also contains an INFO_TS submessage and a
        trailing vendor-specific submessage (id 0x80). Neither should produce
        an event — only the DATA(r) submessage should.
        """
        events = RTPSParser.parse_packet(REAL_SEDP_SUBSCRIPTION_PACKET)
        assert len(events) == 1

# ---------------------------------------------------------------------------
# Malformed / edge-case input
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_empty_payload_returns_no_events(self):
        assert RTPSParser.parse_packet(b"") == []

    def test_wrong_magic_returns_no_events(self):
        payload = b"XXXX" + b"\x00" * 20
        assert RTPSParser.parse_packet(payload) == []

    def test_too_short_payload_returns_no_events(self):
        payload = b"RTPS" + b"\x00" * 5  # less than the 20-byte header
        assert RTPSParser.parse_packet(payload) == []

    def test_truncated_submessage_does_not_raise(self):
        guid_prefix = b"\x01\x0f\x39\x63\x48\x65\x43\x07\x00\x00\x00\x00"
        # A DATA submessage header claiming more bytes than actually follow.
        header = b"RTPS" + b"\x02\x03" + b"\x01\x0f" + guid_prefix
        truncated_submsg = bytes([0x15, 0x05]) + b"\xff\xff"  # huge declared length, no payload
        payload = header + truncated_submsg
        # Should not raise — just yield no usable events.
        events = RTPSParser.parse_packet(payload)
        assert events == []


# ---------------------------------------------------------------------------
# Classification by writer entity ID
# ---------------------------------------------------------------------------

class TestEntityClassification:
    def _wrap(self, submsg: bytes) -> bytes:
        guid_prefix = b"\x01\x0f\x39\x63\x48\x65\x43\x07\x00\x00\x00\x00"
        return build_rtps_packet(guid_prefix, [submsg])

    def test_unknown_writer_entity_id_is_ignored(self):
        params = build_parameter_list([(PID_TOPIC_NAME, build_cdr_string("rt/scan"))])
        submsg = build_data_submessage(
            reader_id=b"\x00\x00\x00\x00",
            writer_id=UNKNOWN_USER_WRITER_ID,
            seq_num=1,
            flags=0x05,  # LE + D
            param_list_bytes=params,
        )
        events = RTPSParser.parse_packet(self._wrap(submsg))
        assert events == []

    def test_spdp_participant_guid_is_normalized_to_guid_prefix(self):
        participant_guid = (
            "01:0f:39:63:48:65:43:07:"
            "00:00:00:00:00:00:01:c1"
        )

        params = build_parameter_list(
            [
                (
                    PID_PARTICIPANT_GUID,
                    bytes.fromhex(participant_guid.replace(":", "")),
                )
            ]
        )

        submsg = build_data_submessage(
            reader_id=b"\x00\x00\x00\x00",
            writer_id=SPDP_PARTICIPANT_WRITER_ID,
            seq_num=1,
            flags=0x05,
            param_list_bytes=params,
        )

        guid_prefix = bytes.fromhex(
            "01:0f:39:63:48:65:43:07:00:00:00:00".replace(":", "")
        )

        events = RTPSParser.parse_packet(
            build_rtps_packet(guid_prefix, [submsg])
        )

        assert len(events) == 1
        assert events[0].guid_prefix == (
            "01:0f:39:63:48:65:43:07:00:00:00:00"
        )


# ---------------------------------------------------------------------------
# Parameter decoding
# ---------------------------------------------------------------------------

class TestParameterDecoding:
    def test_topic_name_rt_prefix_is_normalized(self):
        params = build_parameter_list(
            [
                (PID_TOPIC_NAME, build_cdr_string("rt/scan")),
                (PID_TYPE_NAME, build_cdr_string("sensor_msgs::msg::dds_::LaserScan_")),
            ]
        )
        submsg = build_data_submessage(
            reader_id=b"\x00\x00\x00\x00",
            writer_id=SEDP_SUBSCRIPTIONS_WRITER_ID,
            seq_num=1,
            flags=0x05,
            param_list_bytes=params,
        )
        guid_prefix = b"\x01\x0f\x39\x63\x48\x65\x43\x07\x00\x00\x00\x00"
        events = RTPSParser.parse_packet(build_rtps_packet(guid_prefix, [submsg]))

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, EndpointDiscovered)
        assert event.topic == "/scan"  # "rt/scan" -> "/scan"
        assert event.type_name == "sensor_msgs::msg::dds_::LaserScan_"

    def test_reliability_and_durability_decoding(self):
        params = build_parameter_list(
            [
                (PID_TOPIC_NAME, build_cdr_string("rt/cmd_vel")),
                (PID_RELIABILITY, build_u32(2) + b"\x00" * 8),  # kind=2 -> RELIABLE (+ max_blocking_time)
                (PID_DURABILITY, build_u32(1)),  # kind=1 -> TRANSIENT_LOCAL
            ]
        )
        submsg = build_data_submessage(
            reader_id=b"\x00\x00\x00\x00",
            writer_id=SEDP_SUBSCRIPTIONS_WRITER_ID,
            seq_num=1,
            flags=0x05,
            param_list_bytes=params,
        )
        guid_prefix = b"\x01\x0f\x39\x63\x48\x65\x43\x07\x00\x00\x00\x00"
        events = RTPSParser.parse_packet(build_rtps_packet(guid_prefix, [submsg]))

        event = events[0]
        assert event.qos["reliability"] == "RELIABLE"
        assert event.qos["durability"] == "TRANSIENT_LOCAL"

    def test_missing_qos_pids_default_to_unknown(self):
        params = build_parameter_list([(PID_TOPIC_NAME, build_cdr_string("rt/odom"))])
        submsg = build_data_submessage(
            reader_id=b"\x00\x00\x00\x00",
            writer_id=SEDP_SUBSCRIPTIONS_WRITER_ID,
            seq_num=1,
            flags=0x05,
            param_list_bytes=params,
        )
        guid_prefix = b"\x01\x0f\x39\x63\x48\x65\x43\x07\x00\x00\x00\x00"
        events = RTPSParser.parse_packet(build_rtps_packet(guid_prefix, [submsg]))

        event = events[0]
        assert event.qos["reliability"] == "UNKNOWN"
        assert event.qos["durability"] == "UNKNOWN"