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

from io import StringIO

from graph_builder import EndpointDiscovered, GraphBuilder
from terminal_visualizer import TerminalVisualizer


def test_render_shows_publishers_subscribers_and_qos():
    builder = GraphBuilder()
    builder.process_event(
        EndpointDiscovered(
            "publisher-guid",
            "participant-pub",
            "/scan",
            "sensor_msgs/msg/LaserScan",
            {"reliability": "RELIABLE"},
            "publisher",
        )
    )
    builder.process_event(
        EndpointDiscovered(
            "subscriber-guid",
            "participant-sub",
            "/scan",
            "sensor_msgs/msg/LaserScan",
            {"reliability": "BEST_EFFORT"},
            "subscriber",
        )
    )
    output = StringIO()

    TerminalVisualizer(builder, output=output, table_width=100).render()

    rendered = output.getvalue()
    assert "Participants: 2 | Topics: 1 | Endpoints: 2" in rendered
    assert "PUBLISHERS" in rendered
    assert "PUBLISHERS (1)" in rendered
    assert "SUBSCRIBERS (1)" in rendered
    assert rendered.count("=" * 100) == 2
    assert "participant:participant-pub | topic:/scan" in rendered
    assert "topic:/scan | participant:participant-sub" in rendered
    assert "reliability=RELIABLE" in rendered
    assert "reliability=BEST_EFFORT" in rendered


def test_render_handles_empty_graph():
    output = StringIO()

    TerminalVisualizer(GraphBuilder(), output=output, table_width=100).render()

    rendered = output.getvalue()
    assert "Participants: 0 | Topics: 0 | Endpoints: 0" in rendered
    assert rendered.count("(none)") == 2
