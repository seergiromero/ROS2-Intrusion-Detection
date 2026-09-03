from graph_builder import GraphBuilder
from rtps_fixtures import (
    REAL_CAPTURES,
    REAL_SEDP_SUBSCRIPTION_PACKET,
    _SEDP_PUBLICATION_HEX,
    hex_to_bytes,
)
from rtps_sniffer import RTPSSniffer


def test_real_rtps_packets_update_sniffer_and_graph():
    builder = GraphBuilder()
    sniffer = RTPSSniffer(
        interface="lo",
        on_update_callback=builder.process_event,
    )

    sniffer._process_packet(
        _make_packet(REAL_SEDP_SUBSCRIPTION_PACKET)
    )
    sniffer._process_packet(
        _make_packet(hex_to_bytes(_SEDP_PUBLICATION_HEX))
    )

    snapshot = builder.get_snapshot_dict()
    assert snapshot["stats"]["num_topics"] == 2
    assert snapshot["stats"]["num_edges"] == 2
    assert {edge["role"] for edge in snapshot["edges"]} == {
        "publisher",
        "subscriber",
    }
    assert {edge["guid"] for edge in snapshot["edges"]} == {
        REAL_CAPTURES[0].expected_fields["guid"],
        REAL_CAPTURES[1].expected_fields["guid"],
    }


def _make_packet(payload: bytes):
    from scapy.all import IP, UDP, Raw

    return IP(src="127.0.0.1", dst="127.0.0.1") / UDP(
        sport=60318,
        dport=7416,
    ) / Raw(load=payload)