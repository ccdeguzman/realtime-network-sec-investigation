"""
    Packet and flow models

Taking individual packets and grouping them into
conversations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntFlag


class TCPFlag(IntFlag):
    # TCP header flag bits, with their on-the-wire values.

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class EndReason(Enum):
    # This determines why the flow ended
    FIN = "fin"
    RST = "rst"
    IDLE_TIMEOUT = "idle_timeout"
    ACTIVE_TIMEOUT = "active_timeout"


class FlowMismatchError(ValueError):
    """A packet was added to a flow it doesn't belong to."""


# Represents one packet
@dataclass(frozen=True, slots=True)
class PacketInfo:
    timestamp: float  # from packet.time, converted to float in capture
    protocol: str  # TCP, UDP, ICMP
    src_ip: str
    dst_ip: str
    src_port: int | None  # None for ICMP; 0 is a suspicious port
    dst_port: int | None
    length: int  # IP-layer, headers included
    tcp_flags: TCPFlag = TCPFlag(0)


@dataclass(slots=True)
class Flow:
    """
    Summarized conversation between two endpoints
    """

    protocol: str
    orig_ip: str
    orig_port: int | None
    resp_ip: str
    resp_port: int | None
    start_time: float
    last_seen: float
    orig_pkts: int = 0
    orig_bytes: int = 0
    resp_pkts: int = 0
    resp_bytes: int = 0
    """
    One bitmask per direction: fixed size however long the flow runs, and
    it keeps WHO sent each flag. A closed port (responder RSTs) and a SYN
    scan hitting an open port (originator RSTs) differ only in that.
    """
    orig_flags: TCPFlag = TCPFlag(0)
    resp_flags: TCPFlag = TCPFlag(0)
    """
    None = still open. An enum rather than a bool because detection needs
    to tell "rejected" (RST) from "never answered" (IDLE_TIMEOUT).
    """
    end_reason: EndReason | None = None

    @classmethod
    def from_first_packet(cls, pkt: PacketInfo) -> Flow:
        # The first packet defines the originator, so it builds the flow
        flow = cls(
            protocol=pkt.protocol,
            orig_ip=pkt.src_ip,
            orig_port=pkt.src_port,
            resp_ip=pkt.dst_ip,
            resp_port=pkt.dst_port,
            start_time=pkt.timestamp,
            last_seen=pkt.timestamp,
        )
        flow.add_packet(pkt)  # immediately add the first packet to the counters
        return flow

    @property
    def duration(self) -> float:
        # Derived and not stored. A stored copy could disagree with timestamps
        return self.last_seen - self.start_time

    @property
    def is_open(self) -> bool:
        return self.end_reason is None

    def add_packet(self, pkt: PacketInfo) -> None:
        """
        It takes one packet and adds it to the flow.
        Count a packet, working out its direction from our own endpoints.
        The flow decides direction, not the caller, because the flow already
        holds the originator. A buggy caller can't record a packet backwards.
        """
        if not self.is_open:
            raise FlowMismatchError("cannot add a packet to a closed flow")
        if pkt.protocol != self.protocol:
            raise FlowMismatchError(f"protocol {pkt.protocol} != {self.protocol}")

        # Comparing IP addresses and ports
        src = (pkt.src_ip, pkt.src_port)
        dst = (pkt.dst_ip, pkt.dst_port)
        orig = (self.orig_ip, self.orig_port)
        resp = (self.resp_ip, self.resp_port)

        # This is to check if packet is traveling in the original direction.
        # If so, then update the originator's statistics
        if (src, dst) == (orig, resp):
            self.orig_pkts += 1
            self.orig_bytes += pkt.length
            self.orig_flags |= pkt.tcp_flags
        # This is to check if the packet is traveling from responder back to originator.
        elif (src, dst) == (resp, orig):
            self.resp_pkts += 1
            self.resp_bytes += pkt.length
            self.resp_flags |= pkt.tcp_flags
        else:
            raise FlowMismatchError(f"{src}->{dst} is not part of {orig}<->{resp}")

        # max() so an out-of-order packet can't pull last_seen
        # backwards and make duration shrink or go negative.
        self.last_seen = max(self.last_seen, pkt.timestamp)

    def close(self, reason: EndReason) -> None:
        # The assembler decides WHEN a flow ends; the flow just records why
        if not self.is_open:
            raise FlowMismatchError(f"flow already closed ({self.end_reason})")
        self.end_reason = reason
