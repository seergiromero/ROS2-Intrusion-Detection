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


from collections.abc import Callable
import inspect
import logging
import threading
import time
from typing import Any, Optional
import copy
from scapy.all import AsyncSniffer, IP, UDP, Packet

if __package__:
    from .rtps_parser import EndpointDiscovered, EntityDisposed, ParticipantDiscovered, RTPSParser
else:
    from rtps_parser import EndpointDiscovered, EntityDisposed, ParticipantDiscovered, RTPSParser


class RTPSSniffer:
    """
    Robust RTPS network sniffer.
    Requires root/CAP_NET_RAW permissions to capture raw sockets.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        port_filter: Optional[str] = "udp portrange 7400-7600",
        on_update_callback: Optional[Callable] = None,
        debug: bool = False,
    ):
        self.interface = interface
        self.port_filter = port_filter
        self.on_update_callback = on_update_callback
        self.debug = debug

        self.logger = logging.getLogger("RTPSSniffer")
        self.logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [RIDS] %(message)s", "%H:%M:%S"))
            self.logger.addHandler(handler)

        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._reaper_thread: Optional[threading.Thread] = None
        self.running = False
        self._stop_event = threading.Event()

        self.discovered_participants: dict[str, dict[str, Any]] = {}
        self.discovered_endpoints: dict[str, dict[str, Any]] = {}

    def start(self) -> None:
        with self._lock:
            if self.running:
                self.logger.warning("Sniffer is already running.")
                return
            self._stop_event.clear()
            self.running = True

            # AsyncSniffer handles background thread and immediate stop() natively
            self._sniffer = AsyncSniffer(
                filter=self.port_filter,
                prn=self._process_packet,
                iface=self.interface,
                store=False,
            )
            try:
                self._sniffer.start()
            except Exception:
                self.running = False
                self._sniffer = None
                raise

            # Background thread to clean expired leaseDurations
            self._reaper_thread = threading.Thread(target=self._lease_reaper_loop, daemon=True)
            self._reaper_thread.start()

            self.logger.info("RTPS Sniffer successfully started.")

    def stop(self) -> None:
        with self._lock:
            if not self.running:
                return
            self.running = False
            self._stop_event.set()
            sniffer = self._sniffer
            reaper_thread = self._reaper_thread

        # Stop external/background components outside the state lock. Scapy
        # may wait for an in-flight packet callback to finish.
        if sniffer:
            sniffer.stop()
        if reaper_thread and reaper_thread is not threading.current_thread():
            reaper_thread.join(timeout=3.0)

        self.logger.info("RTPS Sniffer stopped cleanly.")

    def _process_packet(self, packet: Packet) -> None:
        """Exception-safe packet wrapper preventing thread crashes."""

        try:
            if not packet.haslayer(UDP):
                return

            payload = bytes(packet[UDP].payload)

            if self.debug and len(payload) >= 20 and payload[0:4] == b"RTPS":
                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.logger.debug("================================================================================")
                self.logger.debug(f"[FRAME CAPTURE] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Payload Length: {len(payload)}B")

            events = RTPSParser.parse_packet(payload, debug=self.debug, logger=self.logger)

            for event in events:
                self._handle_event(event)

            if self.debug and len(payload) >= 20 and payload[0:4] == b"RTPS":
                self.logger.debug("================================================================================\n")

        except Exception as e:
            self.logger.debug(f"Skipped malformed packet: {e}")

    def _handle_event(self, event: Any) -> None:
        now = time.time()

        if isinstance(event, ParticipantDiscovered):
            with self._lock:
                is_new = event.guid_prefix not in self.discovered_participants
                self.discovered_participants[event.guid_prefix] = {
                    "guid_prefix": event.guid_prefix,
                    "vendor_id": event.vendor_id,
                    "last_seen": now,
                    "lease_duration": event.lease_duration,
                }
            self._notify(
                "PARTICIPANT_ADDED" if is_new else "PARTICIPANT_UPDATED",
                event.guid_prefix,
                event,
            )

        elif isinstance(event, EndpointDiscovered):
            with self._lock:
                is_new = event.guid not in self.discovered_endpoints
                self.discovered_endpoints[event.guid] = {
                    "guid": event.guid,
                    "guid_prefix": event.guid_prefix,
                    "topic": event.topic,
                    "type": event.type_name,
                    "qos": event.qos,
                    "role": event.role,
                    "last_seen": now,
                }
            self._notify(
                "ENDPOINT_ADDED" if is_new else "ENDPOINT_UPDATED",
                event.guid,
                event,
            )

        elif isinstance(event, EntityDisposed):
            if event.disposed_guid is None:
                return

            notifications: list[tuple[str, str, Any]] = []
            with self._lock:
                if event.is_participant:
                    participant_removed = event.disposed_guid in self.discovered_participants
                    self.discovered_participants.pop(event.disposed_guid, None)
                    removed = [k for k, v in self.discovered_endpoints.items() if v["guid_prefix"] == event.disposed_guid]
                    for k in removed:
                        self.discovered_endpoints.pop(k, None)
                    if participant_removed:
                        notifications.append(("PARTICIPANT_DISPOSED", event.disposed_guid, event))
                    for endpoint_guid in removed:
                        notifications.append((
                            "ENDPOINT_DISPOSED",
                            endpoint_guid,
                            EntityDisposed(
                                guid_prefix=event.guid_prefix,
                                writer_id=event.writer_id,
                                seq_num=event.seq_num,
                                disposed_guid=endpoint_guid,
                                is_participant=False,
                            ),
                        ))
                else:
                    endpoint_removed = event.disposed_guid in self.discovered_endpoints
                    self.discovered_endpoints.pop(event.disposed_guid, None)
                    if endpoint_removed:
                        notifications.append(("ENDPOINT_DISPOSED", event.disposed_guid, event))

            for kind, identifier, notification_event in notifications:
                self._notify(kind, identifier, notification_event)

    def _notify(self, kind: str, identifier: str, event: Any) -> None:
        """Supports the current event callback and the legacy two-argument form."""
        callback = self.on_update_callback
        if callback is None:
            return

        try:
            parameters = inspect.signature(callback).parameters.values()
            accepts_two_arguments = len(parameters) >= 2 or any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL for parameter in parameters
            )
        except (TypeError, ValueError):
            accepts_two_arguments = False

        try:
            if accepts_two_arguments:
                callback(kind, identifier)
            else:
                callback(event)
        except Exception:
            self.logger.exception("Update callback failed")

    def _lease_reaper_loop(self) -> None:
        """Periodically removes silent nodes whose leaseDuration has expired."""

        while not self._stop_event.wait(2.0):
            now = time.time()
            expired_events: list[tuple[str, str, EntityDisposed]] = []

            with self._lock:
                expired_participants = [
                    guid for guid, data in self.discovered_participants.items()
                    if now - data["last_seen"] > data["lease_duration"]
                ]

                for guid in expired_participants:

                    del self.discovered_participants[guid]
                    endpoints_to_remove = [
                        e_guid for e_guid, e in self.discovered_endpoints.items() 
                        if e["guid_prefix"] == guid
                    ]
                    
                    for e_guid in endpoints_to_remove:
                        del self.discovered_endpoints[e_guid]
                        expired_events.append((
                            "ENDPOINT_EXPIRED",
                            e_guid,
                            EntityDisposed(
                                disposed_guid=e_guid,
                                guid_prefix=guid,
                                writer_id="unknown",
                                seq_num=0,
                                is_participant=False,
                            ),
                        ))
                    self.logger.warning(f"Participant {guid} expired (leaseDuration timeout). Purged from state.")
                    expired_events.append((
                        "PARTICIPANT_EXPIRED",
                        guid,
                        EntityDisposed(
                            disposed_guid=guid,
                            guid_prefix=guid,
                            writer_id="unknown",
                            seq_num=0,
                            is_participant=True,
                        ),
                    ))

            for kind, identifier, event in expired_events:
                self._notify(kind, identifier, event)
    
    def get_captured_state(self) -> dict[str, dict[str, Any]]:
        """Returns a thread-safe copy of the captured state."""

        with self._lock:
            return {
                "participants": copy.deepcopy(self.discovered_participants),
                "endpoints": copy.deepcopy(self.discovered_endpoints),
            }
                
if __name__ == "__main__":
    sniffer = RTPSSniffer(interface="lo", debug=True)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()