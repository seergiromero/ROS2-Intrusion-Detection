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
import logging
import struct
from typing import Any, Optional

# Constants
PID_PAD = 0x0000
PID_SENTINEL = 0x0001
PID_PARTICIPANT_LEASE_DURATION = 0x0002
PID_TOPIC_NAME = 0x0005
PID_TYPE_NAME = 0x0007
PID_PROTOCOL_VERSION = 0x0015
PID_VENDOR_ID = 0x0016
PID_RELIABILITY = 0x001A
PID_DURABILITY = 0x001D
PID_PARTICIPANT_GUID = 0x0050
PID_ENDPOINT_GUID = 0x005A
PID_KEY_HASH = 0x0070
PID_STATUS_INFO = 0x0071

SPDP_WRITER_ENTITY_IDS = {"00:00:01:c1", "00:01:00:c2"}  # DATA(p) - Participant
SEDP_PUB_WRITER_ID = "00:00:03:c2"  # DATA(w) - Publications / Writers
SEDP_SUB_WRITER_ID = "00:00:04:c2"  # DATA(r) - Subscriptions / Readers
SEDP_TOPIC_WRITER_ID = "00:00:02:c2"  # DATA(t) - Topics

# Known RTPS Submessage ID Mapping for Detailed Debugging
SUBMSG_NAME_MAP = {
    0x01: "PAD",
    0x06: "ACKNACK",
    0x07: "HEARTBEAT",
    0x08: "GAP",
    0x09: "INFO_TS",
    0x0C: "INFO_SRC",
    0x0D: "INFO_REPLY",
    0x0E: "INFO_DST",
    0x15: "DATA",
    0x16: "DATA_FRAG",
}

# Known Builtin Entity IDs for Detailed Wireshark Cross-Referencing
ENTITY_ID_MAP = {
    "00:00:00:00": "ENTITYID_UNKNOWN",
    "00:00:01:c1": "SPDP_BUILTIN_PARTICIPANT_ANNOUNCER",
    "00:00:02:c2": "SEDP_BUILTIN_PUBLICATIONS_ANNOUNCER",
    "00:00:02:c7": "SEDP_BUILTIN_PUBLICATIONS_DETECTOR",
    "00:00:03:c2": "SEDP_BUILTIN_SUBSCRIPTIONS_ANNOUNCER",
    "00:00:03:c7": "SEDP_BUILTIN_SUBSCRIPTIONS_DETECTOR",
    "00:01:00:c2": "SEDP_BUILTIN_TOPICS_ANNOUNCER",
    "00:01:00:c7": "SEDP_BUILTIN_TOPICS_DETECTOR",
}


@dataclasses.dataclass
class ParticipantDiscovered:
    guid_prefix: str
    vendor_id: str
    lease_duration: float = 20.0  # Default 20s if not present


@dataclasses.dataclass
class EndpointDiscovered:
    guid: str
    guid_prefix: str
    topic: str
    type_name: str
    qos: dict[str, str]


@dataclasses.dataclass
class EntityDisposed:
    guid_prefix: str
    writer_id: str
    seq_num: int
    disposed_guid: Optional[str] = None
    is_participant: bool = False


class RTPSParser:

    @staticmethod
    def parse_packet(payload: bytes, debug: bool = False, logger: Optional[logging.Logger] = None) -> list[Any]:
        """Parses an RTPS UDP payload and returns identified events."""

        if len(payload) < 20 or payload[0:4] != b"RTPS":  # RTPS = 52 54 50 53
            return []

        proto_version = f"{payload[4]}.{payload[5]}"
        vendor_id = payload[6:8].hex()
        guid_prefix = ":".join(f"{b:02x}" for b in payload[8:20])

        if debug and logger:
            logger.debug(f"[RTPS HEADER ] Version: {proto_version} | Vendor ID: 0x{vendor_id} | GUID Prefix: {guid_prefix}")
            logger.debug("--------------------------------------------------------------------------------")

        events = []
        offset = 20
        submsg_index = 0

        while offset + 4 <= len(payload):
            submsg_id = payload[offset]
            flags = payload[offset + 1]
            little_endian = bool(flags & 0x01)
            endian_str = "<" if little_endian else ">"

            submsg_len = struct.unpack(f"{endian_str}H", payload[offset + 2 : offset + 4])[0]
            if submsg_len == 0 and offset + 4 < len(payload):
                submsg_len = len(payload) - (offset + 4)

            submsg_payload = payload[offset + 4 : offset + 4 + submsg_len]
            submsg_name = SUBMSG_NAME_MAP.get(submsg_id, f"CUSTOM(0x{submsg_id:02x})")

            if debug and logger:
                logger.debug(
                    f"  [SUBMSG #{submsg_index}] ID: 0x{submsg_id:02x} ({submsg_name}) | "
                    f"Flags: 0x{flags:02x} (Endian: {'LE' if little_endian else 'BE'}) | Len: {submsg_len}B"
                )

            # DATA Submessage (0x15)
            if submsg_id == 0x15 and len(submsg_payload) >= 20:
                event = RTPSParser._parse_data_submsg(
                    guid_prefix, vendor_id, submsg_payload, endian_str, flags, debug=debug, logger=logger
                )
                if event:
                    events.append(event)

            offset += 4 + submsg_len
            submsg_index += 1

        return events

    @staticmethod
    def _parse_data_submsg(
        guid_prefix: str,
        vendor_id: str,
        payload: bytes,
        endian_str: str,
        flags: int,
        debug: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> Optional[Any]:
        reader_id_hex = ":".join(f"{b:02x}" for b in payload[4:8])
        writer_id_hex = ":".join(f"{b:02x}" for b in payload[8:12])
        sn_high, sn_low = struct.unpack(f"{endian_str}iI", payload[12:20])
        seq_num = (sn_high << 32) + sn_low

        reader_entity = ENTITY_ID_MAP.get(reader_id_hex, reader_id_hex)
        writer_entity = ENTITY_ID_MAP.get(writer_id_hex, writer_id_hex)

        has_inline_qos = bool(flags & 0x02)
        has_data = bool(flags & 0x04)
        has_key = bool(flags & 0x08)

        all_params = {}
        offset = 20

        # 1. Parse Inline QoS parameters if present (starts directly at byte 20, no PL_CDR header)
        if has_inline_qos and len(payload) >= 20:
            inline_params, consumed = RTPSParser._parse_parameter_list(payload[offset:], endian_str)
            all_params.update(inline_params)
            offset += consumed

        # 2. Parse payload parameters if Data or Key is present
        if (has_data or has_key) and offset < len(payload):
            encap_endian = endian_str
            if offset + 4 <= len(payload):
                encap = payload[offset : offset + 4]
                if encap[0] == 0x00 and encap[1] in (0x02, 0x03):
                    encap_endian = "<" if encap[1] == 0x03 else ">"
                    offset += 4

            body_params, _ = RTPSParser._parse_parameter_list(payload[offset:], encap_endian)
            for k, v in body_params.items():
                all_params.setdefault(k, v)

        status_info = all_params.get(PID_STATUS_INFO, 0)
        is_disposed = (status_info & 0x03) != 0 or (not has_data and (has_key or has_inline_qos))

        # 3. Handle DISPOSE / UNREGISTER
        if is_disposed:
            disposed_guid = (
                all_params.get(PID_KEY_HASH)
                or all_params.get(PID_ENDPOINT_GUID)
                or all_params.get(PID_PARTICIPANT_GUID)
            )
            is_participant = writer_id_hex in SPDP_WRITER_ENTITY_IDS

            if debug and logger:
                logger.debug(
                    f"    ├── [DATA SUBMSG] Reader: {reader_entity} | Writer: {writer_entity} | "
                    f"SeqNum: {seq_num} | Status: DISPOSED / UNREGISTERED "
                    f"(StatusInfo: 0x{status_info:08x}, Target GUID: {disposed_guid})"
                )

            return EntityDisposed(
                guid_prefix=guid_prefix,
                writer_id=writer_id_hex,
                seq_num=seq_num,
                disposed_guid=disposed_guid,
                is_participant=is_participant,
            )

        if not has_data or len(payload) < 24:
            if debug and logger:
                logger.debug(
                    f"    ├── [DATA SUBMSG] Reader: {reader_entity} | Writer: {writer_entity} | "
                    f"SeqNum: {seq_num} | Status: NO DATA PAYLOAD"
                )
            return None

        # Determine Encapsulation Name for Debug Output
        encap_name = "PL_CDR_LE" if endian_str == "<" else "PL_CDR_BE"
        if len(payload) >= 24:
            encapsulation = payload[20:24]
            encap_id = encapsulation[0:2].hex()
            encap_name = "PL_CDR_LE" if encapsulation[1] == 0x03 else ("PL_CDR_BE" if encapsulation[1] == 0x02 else f"0x{encap_id}")

        if debug and logger:
            logger.debug(
                f"    ├── [DATA SUBMSG DETAILS]\n"
                f"    │   ├── Reader Entity ID : {reader_id_hex} ({reader_entity})\n"
                f"    │   ├── Writer Entity ID : {writer_id_hex} ({writer_entity})\n"
                f"    │   ├── Sequence Number  : {seq_num}\n"
                f"    │   ├── Encapsulation    : {encap_name}\n"
                f"    │   └── Total Parameters : {len(all_params)}"
            )

        # 4. Routing based ONLY on Writer Entity ID
        if writer_id_hex in SPDP_WRITER_ENTITY_IDS:
            part_guid = all_params.get(PID_PARTICIPANT_GUID, guid_prefix)
            lease_sec = all_params.get(PID_PARTICIPANT_LEASE_DURATION, 20.0)

            if debug and logger:
                logger.debug(
                    f"    │   └── [SPDP PARTICIPANT DISCOVERY]\n"
                    f"    │       ├── GUID          : {part_guid}\n"
                    f"    │       └── Vendor ID     : 0x{vendor_id}"
                )

            return ParticipantDiscovered(guid_prefix=part_guid, vendor_id=vendor_id, lease_duration=lease_sec)

        elif writer_id_hex in (SEDP_PUB_WRITER_ID, SEDP_SUB_WRITER_ID):
            raw_topic = all_params.get(PID_TOPIC_NAME, "unknown_topic")
            topic_name = raw_topic[2:] if raw_topic.startswith(("rt/", "rr/")) else raw_topic
            type_name = all_params.get(PID_TYPE_NAME, "unknown_type")
            endpoint_guid = all_params.get(PID_ENDPOINT_GUID, f"{guid_prefix}:{writer_id_hex}")
            reliability = all_params.get(PID_RELIABILITY, "UNKNOWN")
            durability = all_params.get(PID_DURABILITY, "UNKNOWN")

            if debug and logger:
                logger.debug(
                    f"    │   └── [SEDP ENDPOINT DISCOVERY]\n"
                    f"    │       ├── Endpoint GUID : {endpoint_guid}\n"
                    f"    │       ├── Topic Name    : '{topic_name}' (Raw: '{raw_topic}')\n"
                    f"    │       ├── Type Name     : '{type_name}'\n"
                    f"    │       ├── QoS Settings  : Reliability={reliability} | Durability={durability}\n"
                    f"    │       └── Origin Prefix : {guid_prefix}"
                )

            return EndpointDiscovered(
                guid=endpoint_guid,
                guid_prefix=guid_prefix,
                topic=topic_name,
                type_name=type_name,
                qos={
                    "reliability": reliability,
                    "durability": durability,
                },
            )

        return None

    @staticmethod
    def _parse_parameter_list(data: bytes, endian_str: str) -> tuple[dict[int, Any], int]:
        params = {}
        offset = 0

        while offset + 4 <= len(data):
            pid, length = struct.unpack(f"{endian_str}HH", data[offset : offset + 4])
            offset += 4

            if pid == PID_SENTINEL or offset + length > len(data):
                break

            val = data[offset : offset + length]

            if pid in (PID_TOPIC_NAME, PID_TYPE_NAME):
                if len(val) > 4:
                    str_len = struct.unpack(f"{endian_str}I", val[0:4])[0]
                    params[pid] = val[4 : 4 + str_len - 1].decode("utf-8", errors="ignore")
            elif pid in (PID_ENDPOINT_GUID, PID_PARTICIPANT_GUID, PID_KEY_HASH):
                params[pid] = ":".join(f"{b:02x}" for b in val[:16])
            elif pid == PID_STATUS_INFO and len(val) >= 4:
                params[pid] = struct.unpack(f"{endian_str}I", val[0:4])[0]
            elif pid == PID_RELIABILITY:
                kind = struct.unpack(f"{endian_str}I", val[0:4])[0] if len(val) >= 4 else 0
                params[pid] = "RELIABLE" if kind == 2 else "BEST_EFFORT"
            elif pid == PID_DURABILITY:
                kind = struct.unpack(f"{endian_str}I", val[0:4])[0] if len(val) >= 4 else 0
                params[pid] = "TRANSIENT_LOCAL" if kind == 1 else "VOLATILE"
            elif pid == PID_PARTICIPANT_LEASE_DURATION and len(val) >= 8:
                sec, frac = struct.unpack(f"{endian_str}iI", val[0:8])
                params[pid] = float(sec) + (frac / 4294967296.0)

            padding = (4 - (length % 4)) % 4
            offset += length + padding

        return params, offset