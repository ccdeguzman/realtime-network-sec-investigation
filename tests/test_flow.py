import pytest

from net_sec_investigation.models import Flow, FlowMismatchError, PacketInfo, TCPFlag

CLIENT = ("10.0.0.5", 51000)
SERVER = ("93.184.216.34", 443)


def pkt(src, dst, ts=0.0, length=60, flags=TCPFlag(0), protocol="TCP"):
    return PacketInfo(
        timestamp=ts,
        protocol=protocol,
        src_ip=src[0],
        src_port=src[1],
        dst_ip=dst[0],
        dst_port=dst[1],
        length=length,
        tcp_flags=flags,
    )


def test_single_packet_flow_has_zero_duration():
    flow = Flow.from_first_packet(pkt(CLIENT, SERVER, ts=100.0))

    assert flow.duration == 0.0
    assert (flow.orig_pkts, flow.resp_pkts) == (1, 0)


def test_counts_accumulate_per_direction():
    flow = Flow.from_first_packet(pkt(CLIENT, SERVER, ts=1.0, length=100))
    flow.add_packet(pkt(SERVER, CLIENT, ts=1.2, length=1500))
    flow.add_packet(pkt(SERVER, CLIENT, ts=1.3, length=1500))

    assert (flow.orig_pkts, flow.orig_bytes) == (1, 100)
    assert (flow.resp_pkts, flow.resp_bytes) == (2, 3000)
    # approx: 1.3 - 1.0 is 0.30000000000000004 in floating point
    assert flow.duration == pytest.approx(0.3)


def test_closed_port_rst_is_attributed_to_responder():
    flow = Flow.from_first_packet(pkt(CLIENT, SERVER, flags=TCPFlag.SYN))
    flow.add_packet(pkt(SERVER, CLIENT, flags=TCPFlag.RST | TCPFlag.ACK))

    assert TCPFlag.RST in flow.resp_flags
    assert TCPFlag.RST not in flow.orig_flags


def test_loopback_direction_is_decided_by_port():
    a, b = ("127.0.0.1", 5000), ("127.0.0.1", 5001)
    flow = Flow.from_first_packet(pkt(a, b))
    flow.add_packet(pkt(b, a))

    assert (flow.orig_pkts, flow.resp_pkts) == (1, 1)


def test_packet_from_another_flow_is_rejected():
    flow = Flow.from_first_packet(pkt(CLIENT, SERVER))

    with pytest.raises(FlowMismatchError):
        flow.add_packet(pkt(CLIENT, ("93.184.216.34", 80)))