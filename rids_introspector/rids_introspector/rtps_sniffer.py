from collections.abc import Callable
import logging
import struct
import threading
from typing import Any, Optional

from scapy.all import IP, UDP, Packet, sniff

# Relevant RTPS ParameterList PIDs (Hexadecimal)
PID_PAD = 0x0000
PID_SENTINEL = 0x0001
PID_TOPIC_NAME = 0x0005
PID_TYPE_NAME = 0x0007
PID_PROTOCOL_VERSION = 0x0015
PID_VENDOR_ID = 0x0016
PID_RELIABILITY = 0x001A
PID_DURABILITY = 0x001D
PID_PARTICIPANT_GUID = 0x0050
PID_ENDPOINT_GUID = 0x005A
SPDP_WRITER_ENTITY_ID = "00:01:00:c2"
SEDP_PUB_WRITER_ID = "00:00:02:c2"
SEDP_SUB_WRITER_ID = "00:00:03:c2"

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


class RTPSSniffer:
    """
    Passive network-level RTPS packet sniffer.
    Extracts participants (SPDP) and endpoints (SEDP) without interacting with ROS 2 API.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        on_update_callback: Optional[Callable] = None,
        debug: bool = False,
    ):
        self.interface = interface
        self.on_update_callback = on_update_callback
        self.debug = debug

        # Logger configuration supporting debug mode
        self.logger = logging.getLogger("RTPSSniffer")
        log_level = logging.DEBUG if self.debug else logging.INFO
        self.logger.setLevel(log_level)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [RIDS] %(message)s", "%H:%M:%S")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # Threading lock (mutex) to prevent race conditions when accessing shared dicts
        # between the background sniffer thread and the main ROS 2 thread.
        self._lock = threading.Lock()
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # In-memory graph state extracted from network
        self.discovered_participants: dict[str, dict[str, Any]] = {}
        self.discovered_endpoints: dict[str, dict[str, Any]] = {}

    def start(self) -> None:
        """Starts packet capture in a non-blocking background thread."""

        with self._lock:
            if self.running:
                self.logger.warning("Sniffer is already running.")
                return
            self.running = True
            self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
            self._thread.start()
            self.logger.info("RTPS sniffer started in background.")

    def stop(self) -> None:
        """Stops the capture loop."""

        with self._lock:
            self.running = False
            self.logger.info("Stopping RTPS sniffer...")

    def _sniff_loop(self) -> None:
        """Main Scapy sniffing loop filtered by DDS ports (7400-7600)."""

        bpf_filter = "udp portrange 7400-7600"
        self.logger.debug(
            f"Starting packet capture on interface '{self.interface or 'default'}' using filter '{bpf_filter}'"
        )
        try:
            # Use Scapy's sniff function to capture packets on the specified interface with the BPF filter
            sniff(
                filter=bpf_filter,  # BPF filter for DDS/RTPS UDP ports
                prn=self._process_packet,  # Callback function to process captured packets
                iface=self.interface,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            self.logger.error(f"Network capture error: {e}")

    def _process_packet(self, packet: Packet) -> None:
        """Parses RTPS header and routes submessages."""

        if not packet.haslayer(UDP):
            return

        payload = bytes(packet[UDP].payload)
        if len(payload) < 20 or payload[0:4] != b"RTPS":
            return  # Not a valid RTPS packet

        # Extract Network Metadata
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        # Parse RTPS Header (20 bytes)
        # Header: Magic(4B) + Version(2B) + VendorId(2B) + GuidPrefix(12B)
        proto_version = f"{payload[4]}.{payload[5]}"
        vendor_id = payload[6:8].hex()
        guid_prefix_raw = payload[8:20]
        guid_prefix = ":".join(f"{b:02x}" for b in guid_prefix_raw)

        if self.debug:
            self.logger.debug("================================================================================")
            self.logger.debug(f"[FRAME CAPTURE] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Payload Length: {len(payload)}B")
            self.logger.debug(f"[RTPS HEADER ] Version: {proto_version} | Vendor ID: 0x{vendor_id} | GUID Prefix: {guid_prefix}")
            self.logger.debug("--------------------------------------------------------------------------------")

        # Iterate over submessages starting from byte 20
        offset = 20
        submsg_index = 0

        while offset < len(payload):
            if offset + 4 > len(payload):
                break

            submessage_id = payload[offset]
            flags = payload[offset + 1]
            little_endian = bool(flags & 0x01)
            endian_str = "<" if little_endian else ">"

            submessage_len = struct.unpack(f"{endian_str}H", payload[offset + 2 : offset + 4])[0]

            # If octetsToNextHeader is 0, submessage extends to the end of packet
            if submessage_len == 0 and offset + 4 < len(payload):
                submessage_len = len(payload) - (offset + 4)

            submsg_payload = payload[offset + 4 : offset + 4 + submessage_len]
            submsg_name = SUBMSG_NAME_MAP.get(submessage_id, f"CUSTOM(0x{submessage_id:02x})")

            if self.debug:
                self.logger.debug(
                    f"  [SUBMSG #{submsg_index}] ID: 0x{submessage_id:02x} ({submsg_name}) | "
                    f"Flags: 0x{flags:02x} (Endian: {'LE' if little_endian else 'BE'}) | Len: {submessage_len}B"
                )

            # 0x15 = DATA Submessage
            if submessage_id == 0x15 and len(submsg_payload) > 12:
                self._parse_data_submessage(guid_prefix, vendor_id, submsg_payload, endian_str, flags)

            offset += 4 + submessage_len
            submsg_index += 1

        if self.debug:
            self.logger.debug("================================================================================\n")

    def _parse_data_submessage(
        self, guid_prefix: str, vendor_id: str, payload: bytes, endian_str: str, submsg_flags: int
    ) -> None:
        """Parses DATA submessages looking for ParameterList (SPDP/SEDP)."""

        # DATA Submessage header fixed length is 20 bytes
        # extraFlags(2B) + octetsToInlineQos(2B) + readerId(4B) + writerId(4B) + writerSN(8B)
        if len(payload) < 20:
            return

        reader_id_hex = ":".join(f"{b:02x}" for b in payload[4:8])
        writer_id_hex = ":".join(f"{b:02x}" for b in payload[8:12])
        
        # Sequence Number parsing (8 Bytes: High 4B + Low 4B)
        sn_high, sn_low = struct.unpack(f"{endian_str}iI", payload[12:20])
        writer_seq_num = (sn_high << 32) + sn_low

        reader_entity = ENTITY_ID_MAP.get(reader_id_hex, reader_id_hex)
        writer_entity = ENTITY_ID_MAP.get(writer_id_hex, writer_id_hex)

        param_offset = 20

        # Check if Data or Key Flag is set (bits 2 or 3)
        has_data = bool(submsg_flags & 0x04) or bool(submsg_flags & 0x08)
        if not has_data or len(payload) < param_offset + 4:
            if self.debug:
                self.logger.debug(
                    f"    ├── [DATA SUBMSG] Reader: {reader_entity} | Writer: {writer_entity} | "
                    f"SeqNum: {writer_seq_num} | Status: NO DATA PAYLOAD"
                )
            return

        # Skip 4-byte Representation Header (Encapsulation Header e.g. PL_CDR_LE / PL_CDR_BE)
        encapsulation = payload[param_offset : param_offset + 4]
        encap_id = encapsulation[0:2].hex()
        encap_name = "PL_CDR_LE" if encapsulation[1] == 0x03 else ("PL_CDR_BE" if encapsulation[1] == 0x02 else f"0x{encap_id}")
        param_offset += 4

        # Dynamically set parameter endianness from encapsulation header (0x0003 = LE, 0x0002 = BE)
        if len(encapsulation) >= 2:
            if encapsulation[1] == 0x03:
                endian_str = "<"
            elif encapsulation[1] == 0x02:
                endian_str = ">"

        params = self._parse_parameter_list(payload[param_offset:], endian_str)

        if self.debug:
            self.logger.debug(
                f"    ├── [DATA SUBMSG DETAILS]\n"
                f"    │   ├── Reader Entity ID : {reader_id_hex} ({reader_entity})\n"
                f"    │   ├── Writer Entity ID : {writer_id_hex} ({writer_entity})\n"
                f"    │   ├── Sequence Number  : {writer_seq_num}\n"
                f"    │   ├── Encapsulation    : {encap_name}\n"
                f"    │   └── Total Parameters : {len(params)}"
            )

        if not params:
            return

        # 1. SPDP: Participant Discovery (DATA(p))
        if writer_id_hex == SPDP_WRITER_ENTITY_ID:
            part_guid = params.get(PID_PARTICIPANT_GUID, guid_prefix)
            with self._lock:
                is_new = part_guid not in self.discovered_participants
                self.discovered_participants[part_guid] = {
                    "guid_prefix": part_guid,
                    "vendor_id": vendor_id,
                    "source": "RTPS_SPDP",
                }

            if is_new or self.debug:
                self.logger.debug(
                    f"    │   └── [SPDP PARTICIPANT DISCOVERY]\n"
                    f"    │       ├── GUID      : {part_guid}\n"
                    f"    │       └── Vendor ID : 0x{vendor_id}"
                )

            if self.on_update_callback:
                self.on_update_callback("PARTICIPANT", part_guid)

        # 2. SEDP: Endpoint Discovery (DATA(w) / DATA(r))
        elif writer_id_hex in (SEDP_PUB_WRITER_ID, SEDP_SUB_WRITER_ID):
            raw_topic = params[PID_TOPIC_NAME]
            # ROS 2 prepends "rt/" in DDS for standard topics
            topic_name = raw_topic.replace("rt/", "/", 1) if raw_topic.startswith("rt/") else raw_topic
            type_name = params.get(PID_TYPE_NAME, "unknown")
            endpoint_guid = params.get(PID_ENDPOINT_GUID, f"{guid_prefix}:unknown")
            reliability = params.get(PID_RELIABILITY, "UNKNOWN")
            durability = params.get(PID_DURABILITY, "UNKNOWN")

            endpoint_data = {
                "guid": endpoint_guid,
                "guid_prefix": guid_prefix,
                "topic": topic_name,
                "type": type_name,
                "qos": {"reliability": reliability, "durability": durability},
                "source": "RTPS_SEDP",
            }

            with self._lock:
                is_new = endpoint_guid not in self.discovered_endpoints
                self.discovered_endpoints[endpoint_guid] = endpoint_data

            if is_new or self.debug:
                self.logger.debug(
                    f"    │   └── [SEDP ENDPOINT DISCOVERY]\n"
                    f"    │       ├── Endpoint GUID : {endpoint_guid}\n"
                    f"    │       ├── Topic Name    : '{topic_name}' (Raw: '{raw_topic}')\n"
                    f"    │       ├── Type Name     : '{type_name}'\n"
                    f"    │       ├── QoS Settings  : Reliability={reliability} | Durability={durability}\n"
                    f"    │       └── Origin Prefix : {guid_prefix}"
                )

            if self.on_update_callback:
                self.on_update_callback("ENDPOINT", endpoint_data)

    def _parse_parameter_list(self, data: bytes, endian_str: str) -> dict[int, Any]:
        """Parses PID/Length/Value pairs from a DDS ParameterList block."""

        params = {}
        offset = 0

        while offset + 4 <= len(data):
            pid, length = struct.unpack(f"{endian_str}HH", data[offset : offset + 4])
            offset += 4

            if pid == PID_SENTINEL:
                break

            if offset + length > len(data):
                break

            value_bytes = data[offset : offset + length]

            # Decode key PIDs
            if pid == PID_TOPIC_NAME or pid == PID_TYPE_NAME:
                # DDS strings are prefixed with length (4 bytes) and end with NULL
                if len(value_bytes) > 4:
                    str_len = struct.unpack(f"{endian_str}I", value_bytes[0:4])[0]
                    params[pid] = value_bytes[4 : 4 + str_len - 1].decode("utf-8", errors="ignore")
            elif pid == PID_ENDPOINT_GUID or pid == PID_PARTICIPANT_GUID:
                params[pid] = ":".join(f"{b:02x}" for b in value_bytes[:16])
            elif pid == PID_RELIABILITY:
                # 0x01 = BEST_EFFORT, 0x02 = RELIABLE
                kind = struct.unpack(f"{endian_str}I", value_bytes[0:4])[0] if len(value_bytes) >= 4 else 0
                params[pid] = "RELIABLE" if kind == 2 else "BEST_EFFORT"
            elif pid == PID_DURABILITY:
                # 0x00 = VOLATILE, 0x01 = TRANSIENT_LOCAL
                kind = struct.unpack(f"{endian_str}I", value_bytes[0:4])[0] if len(value_bytes) >= 4 else 0
                params[pid] = "TRANSIENT_LOCAL" if kind == 1 else "VOLATILE"
            else:
                params[pid] = value_bytes.hex()

            # 4-byte parameter alignment in RTPS
            padding = (4 - (length % 4)) % 4
            offset += length + padding

        return params

    def get_captured_state(self) -> dict[str, Any]:
        """Returns a thread-safe copy of the state captured from the network."""

        with self._lock:
            return {
                "participants": dict(self.discovered_participants),
                "endpoints": dict(self.discovered_endpoints),
            }


if __name__ == "__main__":
    import time

    # Example standalone test with debug mode enabled
    sniffer = RTPSSniffer(interface="lo", debug=True)
    sniffer.start()

    try:
        print("Listening for ROS 2 network traffic... Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping test...")
        sniffer.stop()