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

import dataclasses
import struct
from typing import Any

from rtps_parser import PID_SENTINEL


def hex_to_bytes(colon_hex: str) -> bytes:
    """Converts a Wireshark-style 'aa:bb:cc:...' hex dump into raw bytes."""
    return bytes.fromhex(colon_hex.replace(":", ""))


@dataclasses.dataclass(frozen=True)
class RealCapture:
    """
    One real, Wireshark-captured RTPS frame, plus the ground truth to check
    the parser against. `expected_fields` is checked with getattr() against
    whichever event of `expected_event_type` the parser produces — you only
    need to list the fields you actually care about verifying, not every
    field on the dataclass.

    HOW TO ADD A NEW ONE:
    1. In Wireshark, find the frame (filter e.g. `rtps.sm.id == 0x15 &&
       rtps.sm.wrEntityId == 0x000100c2` for a DATA(p), or use the "Export
       Packet Dissections > As JSON" menu on a single selected frame and grab
       the `udp.payload` field, like the example below).
    2. Paste the colon-separated hex as a new `_XXX_HEX` string.
    3. Read off the ground-truth values from Wireshark's own decoded tree
       (guidPrefix, endpoint/participant GUID, topic name, type name, QoS...)
       and fill in `expected_fields`. Don't compute them from the parser
       itself — that would just be testing the parser against itself.
    4. Append a new `RealCapture(...)` entry to REAL_CAPTURES below.
    """

    name: str
    description: str
    hex_payload: str
    expected_event_type: Any  # ParticipantDiscovered | EndpointDiscovered | EntityDisposed
    expected_fields: dict[str, Any]

    @property
    def payload(self) -> bytes:
        return hex_to_bytes(self.hex_payload)


# --- Real capture #1: INFO_TS + DATA(r) for a Nav2 action reply subscription ---
# Source: Wireshark JSON export, single frame, udp.payload field.
_SEDP_SUBSCRIPTION_HEX = (
    "52:54:50:53:02:03:01:0f:01:0f:39:63:48:65:43:07:00:00:00:00:09:01:08:00:"
    "d5:e8:97:6a:c6:76:0b:a0:15:05:58:02:00:00:10:00:00:00:04:c7:00:00:04:c2:"
    "00:00:00:00:f7:01:00:00:00:03:00:00:5a:00:10:00:01:0f:39:63:48:65:43:07:"
    "00:00:00:00:00:04:09:04:07:80:04:00:01:00:00:00:2f:00:18:00:10:00:00:00:"
    "f7:1c:00:00:55:39:63:00:00:00:00:00:00:00:00:00:00:00:00:00:2f:00:18:00:"
    "01:00:00:00:f7:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:0e:"
    "2f:00:18:00:01:00:00:00:f7:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    "ac:12:00:01:43:00:04:00:00:00:00:00:50:00:10:00:01:0f:39:63:48:65:43:07:"
    "00:00:00:00:00:00:01:c1:05:00:30:00:2b:00:00:00:72:72:2f:6e:61:76:69:67:"
    "61:74:65:5f:74:6f:5f:70:6f:73:65:2f:5f:61:63:74:69:6f:6e:2f:73:65:6e:64:"
    "5f:67:6f:61:6c:52:65:70:6c:79:00:00:07:00:40:00:3b:00:00:00:6e:61:76:32:"
    "5f:6d:73:67:73:3a:3a:61:63:74:69:6f:6e:3a:3a:64:64:73:5f:3a:3a:4e:61:76:"
    "69:67:61:74:65:54:6f:50:6f:73:65:5f:53:65:6e:64:47:6f:61:6c:5f:52:65:73:"
    "70:6f:6e:73:65:5f:00:00:70:00:10:00:01:0f:39:63:48:65:43:07:00:00:00:00:"
    "00:04:09:04:15:00:04:00:02:03:00:00:16:00:04:00:01:0f:00:00:1d:00:04:00:"
    "00:00:00:00:1e:00:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:"
    "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:23:00:08:00:ff:ff:ff:7f:ff:ff:ff:ff:"
    "27:00:08:00:00:00:00:00:00:00:00:00:1b:00:0c:00:00:00:00:00:ff:ff:ff:7f:"
    "ff:ff:ff:ff:1a:00:0c:00:02:00:00:00:00:00:00:00:9a:99:99:19:2b:00:08:00:"
    "ff:ff:ff:7f:ff:ff:ff:ff:2c:00:58:00:51:00:00:00:74:79:70:65:68:61:73:68:"
    "3d:52:49:48:53:30:31:5f:39:39:66:39:37:66:63:62:62:30:37:64:61:66:30:32:"
    "34:64:66:34:62:38:63:33:66:30:32:66:31:39:63:65:37:66:61:33:31:38:33:66:"
    "63:65:64:66:62:37:36:62:38:37:37:32:61:36:31:61:33:37:31:61:35:35:66:61:"
    "3b:00:00:00:1f:00:04:00:00:00:00:00:25:00:04:00:00:00:00:00:21:00:08:00:"
    "00:00:00:00:00:00:00:00:29:00:04:00:00:00:00:00:2e:00:04:00:00:00:00:00:"
    "2d:00:04:00:00:00:00:00:73:00:08:00:01:00:00:00:00:00:00:00:74:00:08:00:"
    "01:00:01:01:00:00:00:00:01:00:00:00:80:01:38:00:01:00:00:00:f8:1c:00:00:"
    "00:00:00:00:00:00:00:00:00:00:00:00:7f:00:00:01:d5:e8:97:6a:1e:9a:13:a0:"
    "90:07:00:00:00:00:00:00:34:58:0c:00:00:00:00:00:00:00:00:00:00:00:00:00"
)

# --- Real capture #2: DATA(p) — participant announcement (SPDP) ---
_SPDP_PARTICIPANT_HEX = (
    "52:54:50:53:02:03:01:0f:01:0f:39:63:49:65:51:3e:00:00:00:00:09:01:08:00:"
    "cb:e8:97:6a:03:dc:f0:e7:15:05:e8:01:00:00:10:00:00:01:00:c7:00:01:00:c2:"
    "00:00:00:00:01:00:00:00:00:03:00:00:15:00:04:00:02:03:00:00:16:00:04:00:"
    "01:0f:00:00:50:00:10:00:01:0f:39:63:49:65:51:3e:00:00:00:00:00:00:01:c1:"
    "07:80:04:00:01:00:00:00:32:00:18:00:01:00:00:00:fe:1c:00:00:00:00:00:00:"
    "00:00:00:00:00:00:00:00:c0:a8:01:0e:32:00:18:00:01:00:00:00:fe:1c:00:00:"
    "00:00:00:00:00:00:00:00:00:00:00:00:ac:12:00:01:31:00:18:00:10:00:00:00:"
    "ff:1c:00:00:55:39:63:00:00:00:00:00:00:00:00:00:00:00:00:00:31:00:18:00:"
    "01:00:00:00:ff:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:0e:"
    "31:00:18:00:01:00:00:00:ff:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    "ac:12:00:01:02:00:08:00:14:00:00:00:00:00:00:00:58:00:04:00:3f:0c:0f:00:"
    "62:00:08:00:02:00:00:00:2f:00:00:00:2c:00:10:00:0b:00:00:00:65:6e:63:6c:"
    "61:76:65:3d:2f:3b:00:00:59:00:dc:00:04:00:00:00:11:00:00:00:50:41:52:54:"
    "49:43:49:50:41:4e:54:5f:54:59:50:45:00:00:00:00:07:00:00:00:53:49:4d:50:"
    "4c:45:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:"
    "5f:64:61:74:61:2e:68:6f:73:74:00:00:32:00:00:00:73:65:72:67:69:2d:52:4f:"
    "47:2d:53:74:72:69:78:2d:47:35:31:33:49:43:2d:47:35:31:33:49:43:3a:38:33:"
    "35:37:38:39:30:38:34:30:34:37:35:38:36:30:39:39:32:00:00:00:1b:00:00:00:"
    "66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:75:73:"
    "65:72:00:00:06:00:00:00:73:65:72:67:69:00:00:00:1e:00:00:00:66:61:73:74:"
    "64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:70:72:6f:63:65:73:"
    "73:00:00:00:06:00:00:00:32:35:39:32:39:00:00:00:01:00:00:00:80:01:38:00:"
    "01:00:00:00:fa:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:7f:00:00:01:"
    "d5:e8:97:6a:6a:fe:5b:68:4e:02:00:00:00:00:00:00:20:aa:03:00:00:00:00:00:"
    "00:00:00:00:00:00:00:00"
)

# --- Real capture #3: DATA(w) — publisher announcement (SEDP) ---
_SEDP_PUBLICATION_HEX = (
    "52:54:50:53:02:03:01:0f:01:0f:39:63:48:65:43:07:00:00:00:00:09:01:08:00:"
    "d5:e8:97:6a:ee:c1:0a:80:15:05:14:02:00:00:10:00:00:00:03:c7:00:00:03:c2:"
    "00:00:00:00:15:02:00:00:00:03:00:00:5a:00:10:00:01:0f:39:63:48:65:43:07:"
    "00:00:00:00:00:04:03:03:07:80:04:00:01:00:00:00:2f:00:18:00:10:00:00:00:"
    "f7:1c:00:00:55:39:63:00:00:00:00:00:00:00:00:00:00:00:00:00:2f:00:18:00:"
    "01:00:00:00:f7:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:0e:"
    "2f:00:18:00:01:00:00:00:f7:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    "ac:12:00:01:50:00:10:00:01:0f:39:63:48:65:43:07:00:00:00:00:00:00:01:c1:"
    "05:00:0c:00:08:00:00:00:72:74:2f:62:6f:6e:64:00:07:00:20:00:19:00:00:00:"
    "62:6f:6e:64:3a:3a:6d:73:67:3a:3a:64:64:73:5f:3a:3a:53:74:61:74:75:73:5f:"
    "00:00:00:00:70:00:10:00:01:0f:39:63:48:65:43:07:00:00:00:00:00:04:03:03:"
    "60:00:04:00:2c:00:00:00:15:00:04:00:02:03:00:00:16:00:04:00:01:0f:00:00:"
    "1d:00:04:00:00:00:00:00:1e:00:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    "01:00:00:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:23:00:08:00:ff:ff:ff:7f:"
    "ff:ff:ff:ff:27:00:08:00:00:00:00:00:00:00:00:00:1b:00:0c:00:00:00:00:00:"
    "ff:ff:ff:7f:ff:ff:ff:ff:1a:00:0c:00:02:00:00:00:00:00:00:00:9a:99:99:19:"
    "2b:00:08:00:ff:ff:ff:7f:ff:ff:ff:ff:2c:00:58:00:51:00:00:00:74:79:70:65:"
    "68:61:73:68:3d:52:49:48:53:30:31:5f:38:37:65:61:63:63:66:66:61:32:35:34:"
    "66:66:66:66:61:64:63:30:62:36:31:36:30:30:34:35:32:65:38:32:35:31:37:34:"
    "30:66:30:36:63:32:35:36:35:39:61:32:64:62:64:61:34:39:32:37:66:64:62:31:"
    "66:37:30:61:3b:00:00:00:04:00:08:00:00:00:00:00:00:00:00:00:1f:00:04:00:"
    "00:00:00:00:25:00:04:00:00:00:00:00:21:00:08:00:00:00:00:00:00:00:00:00:"
    "29:00:04:00:00:00:00:00:2e:00:04:00:00:00:00:00:2d:00:04:00:00:00:00:00:"
    "73:00:08:00:01:00:00:00:00:00:00:00:01:00:00:00:80:01:38:00:01:00:00:00:"
    "fc:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:7f:00:00:01:d5:e8:97:6a:"
    "f4:4f:15:80:84:07:00:00:00:00:00:00:fc:47:0c:00:00:00:00:00:00:00:00:00:"
    "00:00:00:00"
)

# --- Real capture #4: dispose/unregister (Key flag set, Data flag unset) ---
# TODO: harder to capture on demand — happens when a node shuts down
# cleanly. Try `ros2 topic pub ...` then Ctrl+C it while Wireshark is
# running, and filter for rtps.flag.data_present == 0.
_DISPOSE_HEX = (
    "52:54:50:53:02:03:01:0f:01:0f:39:63:e3:0f:8a:c4:00:00:00:00:09:01:08:00:"
    "40:03:98:6a:04:dd:9a:ef:15:03:34:00:00:00:10:00:00:00:04:c7:00:00:04:c2:"
    "00:00:00:00:14:02:00:00:70:00:10:00:01:0f:39:63:e3:0f:8a:c4:00:00:00:00:"
    "00:04:09:04:71:00:04:00:00:00:00:03:01:00:00:00:80:01:38:00:01:00:00:00:"
    "f2:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:7f:00:00:01:40:03:98:6a:"
    "ef:6a:9f:ef:d9:07:00:00:00:00:00:00:4c:9b:0c:00:00:00:00:00:00:00:00:00:"
    "00:00:00:00"
)


REAL_CAPTURES: list[RealCapture] = [
    RealCapture(
        name="sedp_subscription_nav2_reply",
        description="DATA(r): Nav2 action reply subscription (rr/navigate_to_pose/.../send_goalReply)",
        hex_payload=_SEDP_SUBSCRIPTION_HEX,
        expected_event_type="EndpointDiscovered",
        expected_fields={
            "guid": "01:0f:39:63:48:65:43:07:00:00:00:00:00:04:09:04",
            "guid_prefix": "01:0f:39:63:48:65:43:07:00:00:00:00",
            "topic": "/navigate_to_pose/_action/send_goalReply",
            "type_name": "nav2_msgs::action::dds_::NavigateToPose_SendGoal_Response_",
            "qos": {
                "reliability": "RELIABLE",
                "durability": "VOLATILE",
            },
        },
    ),
    RealCapture(
        name="sedp_publication_bond_status",
        description="DATA(w): Bond status publication (rt/bond)",
        hex_payload=_SEDP_PUBLICATION_HEX,
        expected_event_type="EndpointDiscovered",
        expected_fields={
            "guid": "01:0f:39:63:48:65:43:07:00:00:00:00:00:04:03:03",
            "guid_prefix": "01:0f:39:63:48:65:43:07:00:00:00:00",
            "topic": "/bond",
            "type_name": "bond::msg::dds_::Status_",
            "qos": {
                "reliability": "RELIABLE",
                "durability": "VOLATILE",
            },
        },
    ),
    RealCapture(
        name="spdp_participant_discovery",
        description="DATA(p): SPDP participant discovery",
        hex_payload=_SPDP_PARTICIPANT_HEX,
        expected_event_type="ParticipantDiscovered",
        expected_fields={
            "guid_prefix": "01:0f:39:63:49:65:51:3e:00:00:00:00:00:00:01:c1",
            "vendor_id": "010f",
            "lease_duration": 20.0,
        },
    ),
    RealCapture(
        name="sedp_dispose_subscription",
        description="DATA(r[UD]): Disposed subscription endpoint",
        hex_payload=_DISPOSE_HEX,
        expected_event_type="EntityDisposed",
        expected_fields={
            "guid_prefix": "01:0f:39:63:e3:0f:8a:c4:00:00:00:00",
            "writer_id": "00:00:04:c2",
            "seq_num": 532,
            "disposed_guid": "01:0f:39:63:e3:0f:8a:c4:00:00:00:00:00:04:09:04",
            "is_participant": False,
        },
    ),
]

# Kept for backwards compatibility with earlier tests / notebook exploration.
REAL_SEDP_SUBSCRIPTION_PACKET = REAL_CAPTURES[0].payload
REAL_GUID_PREFIX = REAL_CAPTURES[0].expected_fields["guid_prefix"]
REAL_ENDPOINT_GUID = REAL_CAPTURES[0].expected_fields["guid"]
REAL_TOPIC_NAME = REAL_CAPTURES[0].expected_fields["topic"]
REAL_TYPE_NAME = REAL_CAPTURES[0].expected_fields["type_name"]
REAL_VENDOR_ID = "010f"


# --- Synthetic packet builders ---

def build_parameter(pid: int, value: bytes, endian: str = "<") -> bytes:
    """Encodes a single (PID, length, value) entry with RTPS 4-byte alignment padding."""
    length = len(value)
    padding = (4 - (length % 4)) % 4
    return struct.pack(f"{endian}HH", pid, length) + value + b"\x00" * padding


def build_parameter_list(params: list[tuple[int, bytes]], endian: str = "<") -> bytes:
    """Encodes a full ParameterList (entries + PID_SENTINEL terminator)."""
    body = b"".join(build_parameter(pid, value, endian) for pid, value in params)
    sentinel = struct.pack(f"{endian}HH", PID_SENTINEL, 0)
    return body + sentinel


def build_cdr_string(value: str, endian: str = "<") -> bytes:
    """Encodes a string the way DDS ParameterList string fields expect: 4-byte
    length prefix (including the trailing null) + bytes + null terminator."""
    raw = value.encode("utf-8") + b"\x00"
    return struct.pack(f"{endian}I", len(raw)) + raw


def build_u32(value: int, endian: str = "<") -> bytes:
    return struct.pack(f"{endian}I", value)


def build_data_submessage(
    reader_id: bytes,
    writer_id: bytes,
    seq_num: int,
    flags: int,
    param_list_bytes: bytes | None,
    endian: str = "<",
) -> bytes:
    """
    Builds a full DATA submessage (submessage header + fixed DATA header +
    optional encapsulation header + parameter list), matching the layout
    `RTPSParser._parse_data_submsg` expects.

    `flags` controls D (0x04, data present) and K (0x08, key present) —
    pass 0x05 for a normal discovery announcement (LE + D), 0x09 for a
    dispose/unregister-only message (LE + K, no D).
    """
    extra_flags = b"\x00\x00"
    octets_to_inline_qos = struct.pack(f"{endian}H", 16)
    seq_bytes = struct.pack(f"{endian}iI", 0, seq_num)
    fixed = extra_flags + octets_to_inline_qos + reader_id + writer_id + seq_bytes

    if param_list_bytes is not None:
        # PL_CDR_LE / PL_CDR_BE encapsulation header: [0x00, kind, 0x00, 0x00]
        encap = b"\x00\x03\x00\x00" if endian == "<" else b"\x00\x02\x00\x00"
        payload = fixed + encap + param_list_bytes
    else:
        payload = fixed

    header = bytes([0x15, flags]) + struct.pack(f"{endian}H", len(payload))
    return header + payload


def build_rtps_packet(guid_prefix: bytes, submessages: list[bytes], vendor_id: bytes = b"\x01\x0f") -> bytes:
    """Builds a full RTPS packet: magic + version + vendorId + guidPrefix + submessages."""
    assert len(guid_prefix) == 12, "guidPrefix must be exactly 12 bytes"
    header = b"RTPS" + b"\x02\x03" + vendor_id + guid_prefix
    return header + b"".join(submessages)


def hex_entity_id(colon_hex: str) -> bytes:
    """Converts an entity ID string like '00:00:04:c2' into 4 raw bytes."""
    return hex_to_bytes(colon_hex)