"""
packet_parser.py - Parse raw network packets.
Python equivalent of packet_parser.h + packet_parser.cpp
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from pcap_reader import RawPacket


# ============================================================================
# EtherType constants
# ============================================================================
class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP  = 0x0806


# ============================================================================
# Protocol numbers
# ============================================================================
class Protocol:
    ICMP = 1
    TCP  = 6
    UDP  = 17


# ============================================================================
# TCP Flag constants
# ============================================================================
class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


# ============================================================================
# Parsed Packet
# ============================================================================
@dataclass
class ParsedPacket:
    # Timestamps
    timestamp_sec:  int = 0
    timestamp_usec: int = 0

    # Ethernet layer
    src_mac:    str = ""
    dest_mac:   str = ""
    ether_type: int = 0

    # IP layer (if present)
    has_ip:     bool = False
    ip_version: int  = 0
    src_ip:     str  = ""
    dest_ip:    str  = ""
    protocol:   int  = 0   # TCP=6, UDP=17, ICMP=1
    ttl:        int  = 0

    # Transport layer (if present)
    has_tcp: bool = False
    has_udp: bool = False
    src_port:  int = 0
    dest_port: int = 0

    # TCP-specific
    tcp_flags:  int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Payload
    payload_length: int   = 0
    payload_data:   bytes = b""   # slice of original


# ============================================================================
# Packet Parser
# ============================================================================
class PacketParser:

    @staticmethod
    def parse(raw: RawPacket, parsed: ParsedPacket) -> bool:
        """Parse raw packet, fill parsed. Returns True on success."""
        # Reset
        parsed.__init__()
        parsed.timestamp_sec  = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data   = raw.data
        length = len(data)
        offset = [0]  # use list for mutability in nested calls

        if not PacketParser._parse_ethernet(data, length, parsed, offset):
            return False

        if parsed.ether_type == EtherType.IPv4:
            if not PacketParser._parse_ipv4(data, length, parsed, offset):
                return False

            if parsed.protocol == Protocol.TCP:
                if not PacketParser._parse_tcp(data, length, parsed, offset):
                    return False
            elif parsed.protocol == Protocol.UDP:
                if not PacketParser._parse_udp(data, length, parsed, offset):
                    return False

        off = offset[0]
        if off < length:
            parsed.payload_length = length - off
            parsed.payload_data   = data[off:]
        else:
            parsed.payload_length = 0
            parsed.payload_data   = b""

        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_ethernet(data: bytes, length: int, parsed: ParsedPacket, offset: list) -> bool:
        ETH_HEADER_LEN = 14
        if length < ETH_HEADER_LEN:
            return False

        parsed.dest_mac  = PacketParser.mac_to_string(data[0:6])
        parsed.src_mac   = PacketParser.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack_from(">H", data, 12)[0]
        offset[0] = ETH_HEADER_LEN
        return True

    @staticmethod
    def _parse_ipv4(data: bytes, length: int, parsed: ParsedPacket, offset: list) -> bool:
        off = offset[0]
        MIN_IP_HDR = 20
        if length < off + MIN_IP_HDR:
            return False

        version_ihl = data[off]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False

        ip_hdr_len = ihl * 4
        if ip_hdr_len < MIN_IP_HDR or length < off + ip_hdr_len:
            return False

        parsed.ttl      = data[off + 8]
        parsed.protocol = data[off + 9]

        src_ip_bytes  = data[off + 12:off + 16]
        dst_ip_bytes  = data[off + 16:off + 20]
        parsed.src_ip  = f"{src_ip_bytes[0]}.{src_ip_bytes[1]}.{src_ip_bytes[2]}.{src_ip_bytes[3]}"
        parsed.dest_ip = f"{dst_ip_bytes[0]}.{dst_ip_bytes[1]}.{dst_ip_bytes[2]}.{dst_ip_bytes[3]}"

        parsed.has_ip = True
        offset[0] = off + ip_hdr_len
        return True

    @staticmethod
    def _parse_tcp(data: bytes, length: int, parsed: ParsedPacket, offset: list) -> bool:
        off = offset[0]
        MIN_TCP_HDR = 20
        if length < off + MIN_TCP_HDR:
            return False

        parsed.src_port  = struct.unpack_from(">H", data, off)[0]
        parsed.dest_port = struct.unpack_from(">H", data, off + 2)[0]
        parsed.seq_number = struct.unpack_from(">I", data, off + 4)[0]
        parsed.ack_number = struct.unpack_from(">I", data, off + 8)[0]

        data_offset  = (data[off + 12] >> 4) & 0x0F
        tcp_hdr_len  = data_offset * 4
        parsed.tcp_flags = data[off + 13]

        if tcp_hdr_len < MIN_TCP_HDR or length < off + tcp_hdr_len:
            return False

        parsed.has_tcp = True
        offset[0] = off + tcp_hdr_len
        return True

    @staticmethod
    def _parse_udp(data: bytes, length: int, parsed: ParsedPacket, offset: list) -> bool:
        off = offset[0]
        UDP_HDR_LEN = 8
        if length < off + UDP_HDR_LEN:
            return False

        parsed.src_port  = struct.unpack_from(">H", data, off)[0]
        parsed.dest_port = struct.unpack_from(">H", data, off + 2)[0]

        parsed.has_udp = True
        offset[0] = off + UDP_HDR_LEN
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac[:6])

    @staticmethod
    def ip_to_string(ip: int) -> str:
        """Convert uint32 (little-endian byte order as stored) to dotted-decimal."""
        return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return mapping.get(protocol, f"Unknown({protocol})")

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN: parts.append("SYN")
        if flags & TCPFlags.ACK: parts.append("ACK")
        if flags & TCPFlags.FIN: parts.append("FIN")
        if flags & TCPFlags.RST: parts.append("RST")
        if flags & TCPFlags.PSH: parts.append("PSH")
        if flags & TCPFlags.URG: parts.append("URG")
        return " ".join(parts) if parts else "none"
