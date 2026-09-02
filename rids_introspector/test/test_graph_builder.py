import networkx as nx

from graph_builder import EndpointDiscovered, GraphBuilder


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
    assert builder.graph.has_edge("participant-pub", "/scan")
    assert builder.graph.has_edge("/scan", "participant-sub")
    assert builder.graph["participant-pub"]["/scan"]["role"] == "publisher"
    assert builder.graph["/scan"]["participant-sub"]["role"] == "subscriber"