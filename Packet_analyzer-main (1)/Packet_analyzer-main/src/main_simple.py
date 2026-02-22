#!/usr/bin/env python3
"""
main_simple.py - Simple single-threaded test version.
Python equivalent of src/main_simple.cpp
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "include"))

from pcap_reader import PcapReader
from packet_parser import PacketParser, ParsedPacket
from sni_extractor import SNIExtractor


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>", file=sys.stderr)
        return 1

    reader = PcapReader()
    if not reader.open(sys.argv[1]):
        return 1

    parsed = ParsedPacket()
    count  = 0
    tls_count = 0

    print("Processing packets...")

    raw = reader.read_next_packet()
    while raw is not None:
        count += 1
        if not PacketParser.parse(raw, parsed):
            raw = reader.read_next_packet()
            continue

        if not parsed.has_ip:
            raw = reader.read_next_packet()
            continue

        line = f"Packet {count}: {parsed.src_ip}:{parsed.src_port} -> {parsed.dest_ip}:{parsed.dest_port}"

        # Try SNI extraction for HTTPS packets
        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            data = raw.data
            payload_offset = 14  # Ethernet
            if len(data) > 14:
                ip_ihl = data[14] & 0x0F
                payload_offset += ip_ihl * 4

                if payload_offset + 12 < len(data):
                    tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_offset * 4

                    if payload_offset < len(data):
                        payload_len = len(data) - payload_offset
                        sni = SNIExtractor.extract(data[payload_offset:], payload_len)
                        if sni:
                            line += f" [SNI: {sni}]"
                            tls_count += 1

        print(line)
        raw = reader.read_next_packet()

    print(f"\nTotal packets: {count}")
    print(f"SNI extracted: {tls_count}")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
