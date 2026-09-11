"""
Flow assembly: turns a stream of PacketInfo into Flows.

Flow counts ONE conversation. The assembler tracks ALL of them: which
flow each packet belongs to, and (in later sessions) when a flow ends.
"""

from __future__ import annotations

from net_sec_investigation.models import EndReason, Flow, PacketInfo, TCPFlag

Endpoint = tuple[str, int]  # (ip, port)
FlowKey = tuple[str, Endpoint, Endpoint]  # (protocol, first endpoint, second endpoint)


def canonical_key(pkt: PacketInfo) -> FlowKey:
    """
    Return a key that is identical for both directions of a conversation.

    10.0.0.5:51000 -> 1.2.3.4:443
        and
    1.2.3.4:443 -> 10.0.0.5:51000
    must produce the same key, or a reply would start a new flow.
    """
    src: Endpoint = (pkt.src_ip, pkt.src_port)
    dst: Endpoint = (pkt.dst_ip, pkt.dst_port)

    # When 10.0.0.5:51000 -> 1.2.3.4:443 is reversed 1.2.3.4:443 -> 10.0.0.5:51000,
    # min and max put them in the same order making Packet 1 key == Packet 2 key
    first = min(src, dst)
    second = max(src, dst)

    return (pkt.protocol, first, second)


class FlowAssembler:
    def __init__(self, idle_timeout: float = 60.0) -> None:
        self.idle_timeout = idle_timeout
        self._active: dict[FlowKey, Flow] = {}

    def process(self, pkt: PacketInfo) -> list[Flow]:
        """
        Feed in one packet; get back any flows that finished because of it.

        Returning finished flows, instead of collecting them in a list here,
        means the assembler only ever holds OPEN flows in memory, however
        large the pcap is.
        """
        finished = self._expire_idle(now=pkt.timestamp)  # Session 3

        key = canonical_key(pkt)

        # If self._active has no flow for this key, start one with Flow.from_first_packet(pkt)
        # and store it under the key.
        # Otherwise, add the packet to the flow that's already there.
        if key not in self._active:
            flow = Flow.from_first_packet(pkt)
            self._active[key] = flow
        else:
            flow = self._active[key]
            flow.add_packet(pkt)

        reason = tcp_end_reason(flow, pkt)

        if reason is not None:
            flow.close(reason)
            del self._active[key]  # only OPEN flows stay in the dictionary
            finished.append(flow)

        return finished

    def flush(self) -> list[Flow]:
        """
        Hand back every still-open flow, e.g. when the pcap ends.

        These are deliberately NOT closed. The capture ended, not the
        conversation, so none of the EndReasons would be true.
        """
        flows = list(self._active.values())
        self._active.clear()
        return flows

    def _expire_idle(self, now: float) -> list[Flow]:
        """Session 3: close and return flows idle longer than idle_timeout."""
        return []


def tcp_end_reason(flow: Flow, pkt: PacketInfo) -> EndReason | None:
    """
    Decide whether `pkt` ended the TCP conversation in `flow`.

    Called AFTER pkt has been added to flow, so flow's flags include pkt's.
    Returns None if the flow should stay open.
    """
    if pkt.protocol != "TCP":
        return None  # None (UDP has no teardown)
    if TCPFlag.RST in pkt.tcp_flags:
        return EndReason.RST

    # Both sides said "done sending". Wait for the packet AFTER the second
    # FIN (the final ACK) so that ACK joins this flow instead of starting a
    # ghost one-packet flow of its own.
    both_finned = TCPFlag.FIN in flow.orig_flags and TCPFlag.FIN in flow.resp_flags
    if both_finned and TCPFlag.FIN not in pkt.tcp_flags:
        return EndReason.FIN
    return None
