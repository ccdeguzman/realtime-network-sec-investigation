from net_sec_investigation.assembler import FlowAssembler, canonical_key
from net_sec_investigation.models import PacketInfo, TCPFlag

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
