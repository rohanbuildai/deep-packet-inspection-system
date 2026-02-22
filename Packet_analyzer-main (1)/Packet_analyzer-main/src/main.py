#!/usr/bin/env python3
"""
main.py - Simple Packet Analyzer
Python equivalent of src/main.cpp
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "include"))

import time
from datetime import datetime

from pcap_reader import PcapReader, RawPacket
from packet_parser import PacketParser, ParsedPacket, EtherType, TCPFlags


def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    # Format timestamp
    dt = datetime.fromtimestamp(pkt.timestamp_sec)
    ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {ts_str}.{pkt.timestamp_usec:06d}")

    # Ethernet layer
    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")

    eth_name = ""
    if pkt.ether_type == EtherType.IPv4:
        eth_name = " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        eth_name = " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        eth_name = " (ARP)"
    print(f"  EtherType:       0x{pkt.ether_type:04x}{eth_name}")

    # IP layer
    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")

    # TCP layer
    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")

    # UDP layer
    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    # Payload
    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview_len = min(pkt.payload_length, 32)
        hex_preview = " ".join(f"{b:02x}" for b in pkt.payload_data[:preview_len])
        suffix = " ..." if pkt.payload_length > 32 else ""
        print(f"  Preview: {hex_preview}{suffix}")


def print_usage(program_name: str) -> None:
    print(f"Usage: {program_name} <pcap_file> [max_packets]")
    print("\nArguments:")
    print("  pcap_file   - Path to a .pcap file captured by Wireshark")
    print("  max_packets - (Optional) Maximum number of packets to display")
    print("\nExample:")
    print(f"  {program_name} capture.pcap")
    print(f"  {program_name} capture.pcap 10")


def main():
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    if len(sys.argv) < 2:
        print_usage(sys.argv[0])
        return 1

    filename    = sys.argv[1]
    max_packets = int(sys.argv[2]) if len(sys.argv) >= 3 else -1

    reader = PcapReader()
    if not reader.open(filename):
        return 1

    print("\n--- Reading packets ---")

    packet_count = 0
    parse_errors = 0
    parsed       = ParsedPacket()

    raw = reader.read_next_packet()
    while raw is not None:
        packet_count += 1

        if PacketParser.parse(raw, parsed):
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

        raw = reader.read_next_packet()

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
