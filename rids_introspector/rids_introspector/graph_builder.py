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
import threading
import networkx as nx
from rids_introspector.rtps_parser import ParticipantDiscovered, EndpointDiscovered, EntityDisposed

class GraphBuilder:
    def __init__(self, debug: bool = False):
        self.graph = nx.DiGraph()
        self.debug = debug
        self._lock = threading.Lock()

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"[GRAPH_BUILDER] {message}")

    def process_event(self, event):
        with self._lock:
            now = time.time()
            
            if isinstance(event, ParticipantDiscovered):
                self._log(f"Participant Discovered: GUID Prefix = {event.guid_prefix} | Vendor ID = {event.vendor_id}")
                self.graph.add_node(
                    event.guid_prefix,
                    node_type="participant",
                    vendor_id=event.vendor_id,
                    last_seen=now,
                    lease_duration=event.lease_duration
                )
                self._log(f"Added/Updated participant node: '{event.guid_prefix}'")

            elif isinstance(event, EndpointDiscovered):
                self._log(f"Endpoint Discovered: GUID = {event.guid} | Topic = {event.topic} | Type = {event.type_name}")
                
                # Ensure participant node exists
                if not self.graph.has_node(event.guid_prefix):
                    self._log(f"Participant '{event.guid_prefix}' not found in graph. Creating implicit participant node.")
                    self.graph.add_node(event.guid_prefix, node_type="participant", last_seen=now)
                
                # Ensure topic node exists
                if not self.graph.has_node(event.topic):
                    self._log(f"Creating new topic node: '{event.topic}'")
                self.graph.add_node(event.topic, node_type="topic", type_name=event.type_name)

                # Determine direction
                is_writer = getattr(event, 'is_writer', True)
                role = "publisher" if is_writer else "subscriber"
                src, dst = (event.guid_prefix, event.topic) if is_writer else (event.topic, event.guid_prefix)

                self.graph.add_edge(
                    src, 
                    dst, 
                    guid=event.guid, 
                    qos=event.qos, 
                    role=role,
                    last_seen=now
                )
                self._log(f"Added edge [{role.upper()}]: {src} -> {dst}")

            elif isinstance(event, EntityDisposed):
                self._log(f"Entity Disposed Event: Prefix = {event.guid_prefix} | Disposed GUID = {event.disposed_guid} | Is Participant = {event.is_participant}")
                self._handle_disposal(event)

            else:
                self._log(f"Ignored unknown event type: {type(event).__name__}")

            self._log(f"Current Graph Summary -> Nodes: {self.graph.number_of_nodes()}, Edges: {self.graph.number_of_edges()}\n")

    def _handle_disposal(self, event):
        if event.is_participant:
            if self.graph.has_node(event.guid_prefix):
                self.graph.remove_node(event.guid_prefix)
                self._log(f"Removed participant node '{event.guid_prefix}' and all connected edges.")
            else:
                self._log(f"Cannot remove participant '{event.guid_prefix}': Not found in graph.")
        else:
            if event.disposed_guid is None:
                self._log("Disposed GUID is None for endpoint disposal. Skipping.")
                return

            if self.graph.has_node(event.guid_prefix):
                edges_to_remove = [
                    (u, v) for u, v, data in self.graph.edges(event.guid_prefix, data=True)
                    if data.get('guid') == event.disposed_guid
                ] + [
                    (u, v) for u, v, data in self.graph.in_edges(event.guid_prefix, data=True)
                    if data.get('guid') == event.disposed_guid
                ]
                
                if edges_to_remove:
                    self.graph.remove_edges_from(edges_to_remove)
                    self._log(f"Removed {len(edges_to_remove)} edge(s) matching endpoint GUID '{event.disposed_guid}'.")
                else:
                    self._log(f"No matching edge found for disposed endpoint GUID '{event.disposed_guid}'.")

        # Purge orphan topics
        topics_to_remove = [
            n for n, d in self.graph.nodes(data=True)
            if d.get('node_type') == 'topic' and self.graph.degree(n) == 0
        ]
        if topics_to_remove:
            self.graph.remove_nodes_from(topics_to_remove)
            self._log(f"Purged {len(topics_to_remove)} orphan topic node(s): {topics_to_remove}")

    def get_snapshot_dict(self) -> dict:
        return {
            "stats": {
                "num_participants": sum(1 for _, d in self.graph.nodes(data=True) if d.get("node_type") == "participant"),
                "num_topics": sum(1 for _, d in self.graph.nodes(data=True) if d.get("node_type") == "topic"),
                "num_edges": self.graph.number_of_edges(),
            },
            "nodes": [
                {"id": n, **d} for n, d in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **d} for u, v, d in self.graph.edges(data=True)
            ]
        }

    def get_graph_copy(self) -> nx.DiGraph:
        """Returns a thread-safe copy of the graph for the visualizer."""

        with self._lock:
            return self.graph.copy()