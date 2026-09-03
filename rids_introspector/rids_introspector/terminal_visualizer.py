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

import sys
import threading
import time
from typing import TextIO


class TerminalVisualizer:
    _MIN_TABLE_WIDTH = 60

    def __init__(
        self,
        graph_builder,
        interval: float = 1.0,
        output: TextIO | None = None,
        table_width: int = 150,
    ):
        if interval <= 0:
            raise ValueError("Terminal refresh interval must be greater than zero")
        if table_width < self._MIN_TABLE_WIDTH:
            raise ValueError(f"Table width must be at least {self._MIN_TABLE_WIDTH}")

        self.graph_builder = graph_builder
        self.interval = interval
        self.output = output or sys.stdout
        self.table_width = table_width
        available_width = table_width - 9  # three separators: " | "
        participant_width = available_width * 25 // 100
        topic_width = available_width * 25 // 100
        type_width = available_width * 30 // 100
        self.column_widths = (
            participant_width,
            topic_width,
            type_width,
            available_width - participant_width - topic_width - type_width,
        )

    def run(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            self.render()
            stop_event.wait(self.interval)

    def render(self) -> None:
        snapshot = self.graph_builder.get_snapshot_dict()
        stats = snapshot["stats"]
        edges = snapshot["edges"]

        if self.output.isatty():
            self.output.write("\033[2J\033[H")

        self.output.write("=" * self.table_width + "\n")
        self.output.write(
            f"RIDS RTPS monitor | scan={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        )
        self.output.write("=" * self.table_width + "\n")
        self.output.write(
            f"Participants: {stats['num_participants']} | "
            f"Topics: {stats['num_topics']} | "
            f"Endpoints: {stats['num_edges']}\n\n"
        )

        self._render_endpoints(edges, "publisher")
        self._render_endpoints(edges, "subscriber")
        self.output.flush()

    def _render_endpoints(self, edges: list[dict], role: str) -> None:
        matching_edges = [edge for edge in edges if edge.get("role") == role]
        title = "PUBLISHERS" if role == "publisher" else "SUBSCRIBERS"
        self.output.write(f"{title} ({len(matching_edges)})\n")
        self.output.write(self._format_row("Participant", "Topic", "Type", "QoS") + "\n")
        self.output.write("-" * self.table_width + "\n")

        if not matching_edges:
            self.output.write("(none)\n\n")
            return

        for edge in matching_edges:
            participant = edge["source"] if role == "publisher" else edge["target"]
            topic = edge["target"] if role == "publisher" else edge["source"]
            qos = self._format_qos(edge.get("qos", {}))
            self.output.write(self._format_row(
                participant,
                topic,
                edge.get("type_name", "unknown_type"),
                qos,
            ) + "\n")
        self.output.write("\n")

    def _format_row(self, participant, topic, type_name, qos):
        values = (participant, topic, type_name, qos)
        cells = []

        for value, width in zip(values, self.column_widths):
            value = str(value)
            if len(value) > width:
                value = value[: width - 3] + "..."
            cells.append(value.ljust(width))

        return " | ".join(cells)

    @staticmethod
    def _format_qos(qos: dict) -> str:
        if not qos:
            return "unknown"
        return ", ".join(f"{name}={value}" for name, value in sorted(qos.items()))
