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

import json
import networkx as nx
import threading

from graph_builder import EntityDisposed, EndpointDiscovered, GraphBuilder, ParticipantDiscovered


def test_publisher_and_subscriber_have_opposite_edge_directions():
    builder = GraphBuilder()

    builder.process_event(
        EndpointDiscovered(
            guid="publisher-guid",
            guid_prefix="participant-pub",
            topic="/scan",
            type_name="sensor_msgs/msg/LaserScan",
            qos={"reliability": "RELIABLE", "durability": "VOLATILE"},
            role="publisher",
        )
    )
    builder.process_event(
        EndpointDiscovered(
            guid="subscriber-guid",
            guid_prefix="participant-sub",
            topic="/scan",
            type_name="sensor_msgs/msg/LaserScan",
            qos={"reliability": "BEST_EFFORT", "durability": "VOLATILE"},
            role="subscriber",
        )
    )

    assert isinstance(builder.graph, nx.DiGraph)
    assert builder.graph.has_edge("participant:participant-pub", "topic:/scan")
    assert builder.graph.has_edge("topic:/scan", "participant:participant-sub")
    assert (
        builder.graph["participant:participant-pub"]["topic:/scan"]["publisher-guid"]["role"]
        == "publisher"
    )
    assert (
        builder.graph["topic:/scan"]["participant:participant-sub"]["subscriber-guid"]["role"]
        == "subscriber"
    )
    assert builder.graph.number_of_edges() == 2
    assert builder.graph.number_of_edges("participant:participant-pub", "topic:/scan") == 1


def test_disposal_translates_raw_prefix_to_participant_node_id():
    builder = GraphBuilder()
    participant_prefix = "01:02:03:04:05:06:07:08:09:0a:0b:0c"

    builder.process_event(ParticipantDiscovered(participant_prefix, "010f"))
    builder.process_event(
        EndpointDiscovered(
            guid="endpoint-guid",
            guid_prefix=participant_prefix,
            topic="/scan",
            type_name="sensor_msgs/msg/LaserScan",
            qos={},
            role="publisher",
        )
    )
    builder.process_event(
        EntityDisposed(
            guid_prefix=participant_prefix,
            writer_id="00:00:04:c2",
            seq_num=1,
            disposed_guid="endpoint-guid",
        )
    )

    assert builder.graph.has_node(f"participant:{participant_prefix}")
    assert builder.graph.number_of_edges() == 0

    builder.process_event(
        EntityDisposed(
            guid_prefix=participant_prefix,
            writer_id="00:01:00:c2",
            seq_num=2,
            disposed_guid=participant_prefix,
            is_participant=True,
        )
    )

    assert not builder.graph.has_node(f"participant:{participant_prefix}")


def test_repeated_endpoint_updates_the_existing_edge():
    builder = GraphBuilder()
    event = EndpointDiscovered(
        guid="endpoint-guid",
        guid_prefix="participant-a",
        topic="/scan",
        type_name="old_type",
        qos={"reliability": "BEST_EFFORT"},
        role="publisher",
    )
    builder.process_event(event)

    updated_event = EndpointDiscovered(
        guid="endpoint-guid",
        guid_prefix="participant-a",
        topic="/scan",
        type_name="new_type",
        qos={"reliability": "RELIABLE"},
        role="publisher",
    )
    builder.process_event(updated_event)

    edge = builder.graph["participant:participant-a"]["topic:/scan"]["endpoint-guid"]
    assert builder.graph.number_of_edges() == 1
    assert edge["type_name"] == "new_type"
    assert edge["qos"] == {"reliability": "RELIABLE"}


def test_shared_topic_survives_until_its_last_endpoint_is_removed():
    builder = GraphBuilder()
    for participant, endpoint in (("participant-a", "endpoint-a"), ("participant-b", "endpoint-b")):
        builder.process_event(
            EndpointDiscovered(
                guid=endpoint,
                guid_prefix=participant,
                topic="/shared",
                type_name="example/msg/Data",
                qos={},
                role="publisher",
            )
        )

    builder.process_event(EntityDisposed("participant-a", "writer", 1, "endpoint-a"))
    assert builder.graph.has_node("topic:/shared")
    assert builder.graph.has_edge("participant:participant-b", "topic:/shared", "endpoint-b")

    builder.process_event(EntityDisposed("participant-b", "writer", 2, "endpoint-b"))
    assert not builder.graph.has_node("topic:/shared")


def test_snapshot_is_json_serializable_and_contains_edge_keys():
    builder = GraphBuilder()
    builder.process_event(
        EndpointDiscovered("endpoint-guid", "participant-a", "/scan", "type", {}, "publisher")
    )

    snapshot = builder.get_snapshot_dict()
    json.dumps(snapshot)

    assert snapshot["edges"][0]["key"] == "endpoint-guid"
    assert snapshot["edges"][0]["guid"] == "endpoint-guid"


def test_snapshot_can_run_while_events_are_processed():
    builder = GraphBuilder()
    errors = []
    snapshots = []

    def add_events():
        try:
            for index in range(100):
                builder.process_event(
                    EndpointDiscovered(
                        guid=f"endpoint-{index}",
                        guid_prefix=f"participant-{index}",
                        topic=f"/topic-{index}",
                        type_name="example/msg/Data",
                        qos={},
                        role="publisher",
                    )
                )
        except Exception as error:
            errors.append(error)

    def read_snapshots():
        try:
            for _ in range(100):
                snapshot = builder.get_snapshot_dict()
                json.dumps(snapshot)
                snapshots.append(snapshot)
        except Exception as error:
            errors.append(error)

    event_thread = threading.Thread(target=add_events)
    snapshot_thread = threading.Thread(target=read_snapshots)
    event_thread.start()
    snapshot_thread.start()
    event_thread.join()
    snapshot_thread.join()

    assert errors == []
    assert len(snapshots) == 100