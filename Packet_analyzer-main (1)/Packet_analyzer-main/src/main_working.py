#!/usr/bin/env python3
"""
main_working.py - Working DPI Engine (single-threaded).
Python equivalent of src/main_working.cpp
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "include"))

import struct
from collections import defaultdict
from typing import Dict, Set

from pcap_reader import PcapReader, PcapPacketHeader
from packet_parser import PacketParser, ParsedPacket
from sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi_types import AppType, FiveTuple, app_type_to_string, sni_to_app_type


def _parse_ip(ip_str: str) -> int:
    parts = [int(p) for p in ip_str.split(".")]
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)


# ============================================================================
# Flow entry
# ============================================================================
class Flow:
    def __init__(self):
        self.tuple:    FiveTuple = None
        self.app_type: AppType   = AppType.UNKNOWN
        self.sni:      str       = ""
        self.packets:  int       = 0
        self.bytes:    int       = 0
        self.blocked:  bool      = False


# ============================================================================
# Blocking rules (simple set-based)
# ============================================================================
class BlockingRules:
    def __init__(self):
        self.blocked_ips:     Set[int]     = set()
        self.blocked_apps:    Set[AppType] = set()
        self.blocked_domains: list         = []

    def block_ip(self, ip: str) -> None:
        addr = _parse_ip(ip)
        self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        for at in AppType:
            if app_type_to_string(at) == app:
                self.blocked_apps.add(at)
                print(f"[Rules] Blocked app: {app}")
                return
        print(f"[Rules] Unknown app: {app}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for dom in self.blocked_domains:
            if dom in sni:
                return True
        return False


def print_usage(prog: str) -> None:
    print(f"""
DPI Engine - Deep Packet Inspection System
==========================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main():
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        return 1

    input_file  = sys.argv[1]
    output_file = sys.argv[2]

    rules = BlockingRules()

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1; rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1; rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1; rules.block_domain(sys.argv[i])
        i += 1

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader()
    if not reader.open(input_file):
        return 1

    try:
        out_file = open(output_file, "wb")
    except OSError as e:
        print(f"Error: Cannot open output file: {e}", file=sys.stderr)
        return 1

    # Write PCAP global header
    gh = reader.global_header
    out_file.write(gh.raw_bytes)

    # Flow table
    flows: Dict[FiveTuple, Flow] = {}

    # Stats
    total_packets = 0
    forwarded     = 0
    dropped       = 0
    app_stats: Dict[AppType, int] = defaultdict(int)

    parsed = ParsedPacket()

    print("[DPI] Processing packets...")

    raw = reader.read_next_packet()
    while raw is not None:
        total_packets += 1

        if not PacketParser.parse(raw, parsed) or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            raw = reader.read_next_packet()
            continue

        # Build five-tuple
        tuple_ = FiveTuple(
            src_ip   = _parse_ip(parsed.src_ip),
            dst_ip   = _parse_ip(parsed.dest_ip),
            src_port = parsed.src_port,
            dst_port = parsed.dest_port,
            protocol = parsed.protocol,
        )

        flow = flows.setdefault(tuple_, Flow())
        if flow.packets == 0:
            flow.tuple = tuple_
        flow.packets += 1
        flow.bytes   += len(raw.data)

        data = raw.data

        # Try SNI extraction for HTTPS
        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS) and
                not flow.sni and parsed.has_tcp and parsed.dest_port == 443):
            payload_offset = 14
            if len(data) > 14:
                ip_ihl = data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if payload_offset + 12 < len(data):
                    tcp_off = (data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                    if payload_offset < len(data):
                        payload_len = len(data) - payload_offset
                        if payload_len > 5:
                            sni = SNIExtractor.extract(data[payload_offset:], payload_len)
                            if sni:
                                flow.sni      = sni
                                flow.app_type = sni_to_app_type(sni)

        # HTTP Host extraction
        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP) and
                not flow.sni and parsed.has_tcp and parsed.dest_port == 80):
            payload_offset = 14
            if len(data) > 14:
                ip_ihl = data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if payload_offset + 12 < len(data):
                    tcp_off = (data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                    if payload_offset < len(data):
                        payload_len = len(data) - payload_offset
                        host = HTTPHostExtractor.extract(data[payload_offset:], payload_len)
                        if host:
                            flow.sni      = host
                            flow.app_type = sni_to_app_type(host)

        # DNS classification
        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS

        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # Check blocking rules
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                app_str = app_type_to_string(flow.app_type)
                sni_str = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_str}{sni_str})")

        app_stats[flow.app_type] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            # Write packet to output
            pkt_hdr = struct.pack("<IIII",
                                  raw.header.ts_sec,
                                  raw.header.ts_usec,
                                  len(raw.data),
                                  len(raw.data))
            out_file.write(pkt_hdr)
            out_file.write(raw.data)

        raw = reader.read_next_packet()

    reader.close()
    out_file.close()

    # Print report
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:>10}                             ║")
    print(f"║ Forwarded:          {forwarded:>10}                             ║")
    print(f"║ Dropped:            {dropped:>10}                             ║")
    print(f"║ Active Flows:       {len(flows):>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct     = 100.0 * count / total_packets if total_packets else 0
        bar_len = int(pct / 5)
        bar     = "#" * bar_len
        name    = app_type_to_string(app)
        print(f"║ {name:<15}{count:>8} {pct:5.1f}% {bar:<20}  ║")

    print("╚══════════════════════════════════════════════════════════════╝")

    # List unique SNIs
    print("\n[Detected Applications/Domains]")
    unique_snis = {flow.sni: flow.app_type for flow in flows.values() if flow.sni}
    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
