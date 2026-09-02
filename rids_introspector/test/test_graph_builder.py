import networkx as nx

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