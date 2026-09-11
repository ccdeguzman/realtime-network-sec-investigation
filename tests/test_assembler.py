from net_sec_investigation.assembler import FlowAssembler, canonical_key
from net_sec_investigation.models import EndReason, PacketInfo, TCPFlag

SYN, ACK, FIN, RST = TCPFlag.SYN, TCPFlag.ACK, TCPFlag.FIN, TCPFlag.RST


CLIENT = ("10.0.0.5", 51000)
SERVER = ("93.184.216.34", 443)


# Duplicated from test_flow.py for now; we'll move shared helpers later.
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


# Exercise 1
def test_both_directions_share_a_key():
    assert canonical_key(pkt(CLIENT, SERVER)) == canonical_key(pkt(SERVER, CLIENT))


def test_different_server_port_is_a_different_key():
    other = ("93.184.216.34", 80)
    assert canonical_key(pkt(CLIENT, SERVER)) != canonical_key(pkt(CLIENT, other))


def test_protocol_is_part_of_the_key():
    tcp = canonical_key(pkt(CLIENT, SERVER, protocol="TCP"))
    udp = canonical_key(pkt(CLIENT, SERVER, protocol="UDP"))
    assert tcp != udp


# Exercise 2
def test_reply_joins_the_existing_flow():
    asm = FlowAssembler()
    asm.process(pkt(CLIENT, SERVER, ts=1.0))
    assert asm.process(pkt(SERVER, CLIENT, ts=1.1)) == []
    # asm.process(pkt(SERVER, CLIENT, ts=1.1))

    flows = asm.flush()

    assert len(flows) == 1
    assert (flows[0].orig_pkts, flows[0].resp_pkts) == (1, 1)


def test_port_scan_creates_one_flow_per_port():
    asm = FlowAssembler()
    for port in range(1, 101):
        asm.process(pkt(CLIENT, ("10.0.0.9", port), flags=TCPFlag.SYN))

    assert len(asm.flush()) == 100


def test_closed_port_rst_closes_the_flow():
    asm = FlowAssembler()
    asm.process(pkt(CLIENT, SERVER, flags=SYN))
    finished = asm.process(pkt(SERVER, CLIENT, flags=RST | ACK))

    assert len(finished) == 1
    assert finished[0].end_reason is EndReason.RST
    assert asm.flush() == []  # closed flows must not linger in _active


def test_open_port_scan_rst_from_originator_closes_the_flow():
    asm = FlowAssembler()
    asm.process(pkt(CLIENT, SERVER, flags=SYN))
    asm.process(pkt(SERVER, CLIENT, flags=SYN | ACK))
    finished = asm.process(pkt(CLIENT, SERVER, flags=RST))

    assert len(finished) == 1
    assert RST in finished[0].orig_flags


def test_graceful_close_waits_for_final_ack():
    asm = FlowAssembler()
    assert asm.process(pkt(CLIENT, SERVER, flags=FIN | ACK)) == []
    assert asm.process(pkt(SERVER, CLIENT, flags=FIN | ACK)) == []  # not yet
    finished = asm.process(pkt(CLIENT, SERVER, flags=ACK))

    assert len(finished) == 1
    assert finished[0].end_reason is EndReason.FIN
    assert (finished[0].orig_pkts, finished[0].resp_pkts) == (2, 1)
    assert asm.flush() == []  # no ghost flow from the final ACK


def test_half_close_stays_open():
    # Client finished sending, but the server may still be sending data.
    asm = FlowAssembler()
    asm.process(pkt(CLIENT, SERVER, flags=FIN | ACK))

    flows = asm.flush()
    assert len(flows) == 1
    assert flows[0].is_open


def test_lone_rst_is_its_own_closed_flow():
    # A RST with no prior conversation, e.g. backscatter from a spoofed attack.
    asm = FlowAssembler()
    finished = asm.process(pkt(SERVER, CLIENT, flags=RST))

    assert len(finished) == 1
    assert finished[0].orig_ip == SERVER[0]


def test_new_connection_after_close_starts_a_fresh_flow():
    asm = FlowAssembler()
    asm.process(pkt(CLIENT, SERVER, flags=SYN))
    asm.process(pkt(SERVER, CLIENT, flags=RST | ACK))
    # Same ports again: a retry, or the OS reusing the source port.
    assert asm.process(pkt(CLIENT, SERVER, flags=SYN)) == []

    flows = asm.flush()
    assert len(flows) == 1
    assert flows[0].orig_pkts == 1


def test_udp_ignores_tcp_flags():
    # Capture should never set flags on UDP, but the rule shouldn't rely on that.
    asm = FlowAssembler()
    assert asm.process(pkt(CLIENT, SERVER, flags=RST, protocol="UDP")) == []
    assert len(asm.flush()) == 1
