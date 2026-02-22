#!/usr/bin/env python3
"""
dpi_mt.py - Multi-threaded DPI Engine.
Python equivalent of src/dpi_mt.cpp

Architecture: Reader -> LB threads -> FP threads -> Output
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "include"))

import struct
import threading
import time
from collections import defaultdict
from typing import Dict, List, Set, Optional
from dataclasses import dataclass

from pcap_reader import PcapReader, RawPacket
from packet_parser import PacketParser, ParsedPacket
from sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi_types import AppType, FiveTuple, PacketAction, app_type_to_string, sni_to_app_type
from thread_safe_queue import ThreadSafeQueue


# ============================================================================
# Internal Packet structure (self-contained, no pointers)
# ============================================================================
@dataclass
class Packet:
    id:             int       = 0
    ts_sec:         int       = 0
    ts_usec:        int       = 0
    tuple:          FiveTuple = None
    data:           bytes     = b""
    tcp_flags:      int       = 0
    payload_offset: int       = 0
    payload_length: int       = 0


# ============================================================================
# Flow entry
# ============================================================================
@dataclass
class FlowEntry:
    tuple:      FiveTuple = None
    app_type:   AppType   = AppType.UNKNOWN
    sni:        str       = ""
    packets:    int       = 0
    bytes:      int       = 0
    blocked:    bool      = False
    classified: bool      = False


# ============================================================================
# Blocking rules (thread-safe)
# ============================================================================
def _parse_ip(ip_str: str) -> int:
    parts = [int(p) for p in ip_str.split(".")]
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)


class Rules:
    def __init__(self):
        self._lock           = threading.Lock()
        self._blocked_ips:    Set[int]     = set()
        self._blocked_apps:   Set[AppType] = set()
        self._blocked_domains: List[str]  = []

    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(_parse_ip(ip))
            print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        for at in AppType:
            if app_type_to_string(at) == app:
                with self._lock:
                    self._blocked_apps.add(at)
                print(f"[Rules] Blocked app: {app}")
                return
        print(f"[Rules] Unknown app: {app}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        with self._lock:
            self._blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            for dom in self._blocked_domains:
                if dom in sni:
                    return True
        return False


# ============================================================================
# Statistics (thread-safe)
# ============================================================================
class Stats:
    def __init__(self):
        self._lock        = threading.Lock()
        self.total_packets = 0
        self.total_bytes   = 0
        self.forwarded     = 0
        self.dropped       = 0
        self.tcp_packets   = 0
        self.udp_packets   = 0
        self.app_counts:  Dict[AppType, int] = defaultdict(int)
        self.detected_snis: Dict[str, AppType] = {}

    def inc(self, field: str, value: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field) + value)

    def record_app(self, app: AppType, sni: str) -> None:
        with self._lock:
            self.app_counts[app] += 1
            if sni:
                self.detected_snis[sni] = app


# ============================================================================
# Fast Path Processor (one per FP thread)
# ============================================================================
class FastPath:
    def __init__(self, id_: int, rules: Rules, stats: Stats,
                 output_queue: ThreadSafeQueue):
        self._id           = id_
        self._rules        = rules
        self._stats        = stats
        self._output_queue = output_queue
        self._input_queue  = ThreadSafeQueue()
        self._flows:       Dict[FiveTuple, FlowEntry] = {}
        self._running      = False
        self._thread:      Optional[threading.Thread] = None
        self._processed    = 0

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    @property
    def queue(self) -> ThreadSafeQueue:
        return self._input_queue

    @property
    def processed(self) -> int:
        return self._processed

    def _run(self) -> None:
        while self._running:
            pkt = self._input_queue.pop_with_timeout(100)
            if pkt is None:
                continue

            self._processed += 1

            flow = self._flows.setdefault(pkt.tuple, FlowEntry(tuple=pkt.tuple))
            flow.packets += 1
            flow.bytes   += len(pkt.data)

            if not flow.classified:
                self._classify_flow(pkt, flow)

            if not flow.blocked:
                flow.blocked = self._rules.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni)

            self._stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self._stats.inc("dropped")
            else:
                self._stats.inc("forwarded")
                self._output_queue.push(pkt)

    def _classify_flow(self, pkt: Packet, flow: FlowEntry) -> None:
        if pkt.tuple.dst_port == 443 and pkt.payload_length > 5:
            payload = pkt.data[pkt.payload_offset:]
            sni     = SNIExtractor.extract(payload, len(payload))
            if sni:
                flow.sni        = sni
                flow.app_type   = sni_to_app_type(sni)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 80 and pkt.payload_length > 10:
            payload = pkt.data[pkt.payload_offset:]
            host    = HTTPHostExtractor.extract(payload, len(payload))
            if host:
                flow.sni        = host
                flow.app_type   = sni_to_app_type(host)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type   = AppType.DNS
            flow.classified = True
            return

        # Port-based fallback (don't mark classified)
        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


# ============================================================================
# Load Balancer (one per LB thread)
# ============================================================================
class LoadBalancer:
    def __init__(self, id_: int, fps: List[FastPath]):
        self._id          = id_
        self._fps         = fps
        self._num_fps     = len(fps)
        self._input_queue = ThreadSafeQueue()
        self._running     = False
        self._thread:     Optional[threading.Thread] = None
        self._dispatched  = 0

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    @property
    def queue(self) -> ThreadSafeQueue:
        return self._input_queue

    @property
    def dispatched(self) -> int:
        return self._dispatched

    def _run(self) -> None:
        while self._running:
            pkt = self._input_queue.pop_with_timeout(100)
            if pkt is None:
                continue
            fp_idx = hash(pkt.tuple) % self._num_fps
            self._fps[fp_idx].queue.push(pkt)
            self._dispatched += 1


# ============================================================================
# DPI Engine (main class)
# ============================================================================
class DPIEngine:

    class Config:
        def __init__(self, num_lbs: int = 2, fps_per_lb: int = 2):
            self.num_lbs   = num_lbs
            self.fps_per_lb = fps_per_lb

    def __init__(self, cfg: "DPIEngine.Config"):
        self._config = cfg
        total_fps    = cfg.num_lbs * cfg.fps_per_lb

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║              DPI ENGINE v2.0 (Multi-threaded)                 ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {cfg.num_lbs:>2}    FPs per LB: {cfg.fps_per_lb:>2}    Total FPs: {total_fps:>2}     ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        self._rules        = Rules()
        self._stats        = Stats()
        self._output_queue = ThreadSafeQueue()

        # Create FP threads
        self._fps: List[FastPath] = [
            FastPath(i, self._rules, self._stats, self._output_queue)
            for i in range(total_fps)
        ]

        # Create LB threads, each managing a subset of FPs
        self._lbs: List[LoadBalancer] = []
        for lb in range(cfg.num_lbs):
            start  = lb * cfg.fps_per_lb
            lb_fps = self._fps[start: start + cfg.fps_per_lb]
            self._lbs.append(LoadBalancer(lb, lb_fps))

    def block_ip(self, ip: str) -> None:
        self._rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self._rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self._rules.block_domain(domain)

    def process(self, input_file: str, output_file: str) -> bool:
        # Open input
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        # Open output
        try:
            out = open(output_file, "wb")
        except OSError as e:
            print(f"Cannot open output file: {e}", file=sys.stderr)
            return False

        # Write PCAP global header
        gh = reader.global_header
        out.write(gh.raw_bytes)

        # Start all threads
        for fp in self._fps:
            fp.start()
        for lb in self._lbs:
            lb.start()

        # Output writer thread
        output_running = True

        def output_thread_func():
            while output_running or not self._output_queue.empty():
                pkt = self._output_queue.pop_with_timeout(50)
                if pkt is None:
                    continue
                phdr = struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec,
                                   len(pkt.data), len(pkt.data))
                out.write(phdr)
                out.write(pkt.data)

        out_thread = threading.Thread(target=output_thread_func, daemon=True)
        out_thread.start()

        # Read and dispatch packets
        print("[Reader] Processing packets...")
        parsed    = ParsedPacket()
        pkt_id    = 0

        raw = reader.read_next_packet()
        while raw is not None:
            if not PacketParser.parse(raw, parsed) or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                raw = reader.read_next_packet()
                continue

            pkt = Packet()
            pkt.id       = pkt_id
            pkt_id      += 1
            pkt.ts_sec   = raw.header.ts_sec
            pkt.ts_usec  = raw.header.ts_usec
            pkt.tcp_flags = parsed.tcp_flags
            pkt.data     = raw.data

            # Parse five-tuple
            def _p(s): 
                p = [int(x) for x in s.split(".")]
                return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)

            pkt.tuple = FiveTuple(
                src_ip   = _p(parsed.src_ip),
                dst_ip   = _p(parsed.dest_ip),
                src_port = parsed.src_port,
                dst_port = parsed.dest_port,
                protocol = parsed.protocol,
            )

            # Calculate payload offset
            data           = raw.data
            payload_offset = 14  # Ethernet header
            if len(data) > 14:
                ip_ihl = data[14] & 0x0F
                payload_offset += ip_ihl * 4

                if parsed.has_tcp and payload_offset + 12 < len(data):
                    tcp_off = (data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                elif parsed.has_udp:
                    payload_offset += 8

                pkt.payload_offset = payload_offset
                pkt.payload_length = max(0, len(data) - payload_offset)

            # Update stats
            self._stats.inc("total_packets")
            self._stats.inc("total_bytes", len(pkt.data))
            if parsed.has_tcp:
                self._stats.inc("tcp_packets")
            elif parsed.has_udp:
                self._stats.inc("udp_packets")

            # Dispatch to LB
            lb_idx = hash(pkt.tuple) % len(self._lbs)
            self._lbs[lb_idx].queue.push(pkt)

            raw = reader.read_next_packet()

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        # Wait for queues to drain
        time.sleep(0.5)

        # Stop threads
        for lb in self._lbs:
            lb.stop()
        for fp in self._fps:
            fp.stop()

        output_running = False
        self._output_queue.shutdown()
        out_thread.join(timeout=5)

        out.close()
        self._print_report()

        return True

    def _print_report(self) -> None:
        s = self._stats
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {s.total_packets:>12}                           ║")
        print(f"║ Total Bytes:        {s.total_bytes:>12}                           ║")
        print(f"║ TCP Packets:        {s.tcp_packets:>12}                           ║")
        print(f"║ UDP Packets:        {s.udp_packets:>12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {s.forwarded:>12}                           ║")
        print(f"║ Dropped:            {s.dropped:>12}                           ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                             ║")
        for i, lb in enumerate(self._lbs):
            print(f"║   LB{i} dispatched:   {lb.dispatched:>12}                           ║")
        for i, fp in enumerate(self._fps):
            print(f"║   FP{i} processed:    {fp.processed:>12}                           ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        sorted_apps = sorted(s.app_counts.items(), key=lambda x: x[1], reverse=True)
        total = s.total_packets
        for app, count in sorted_apps:
            pct     = 100.0 * count / total if total else 0
            bar_len = int(pct / 5)
            bar     = "#" * bar_len
            name    = app_type_to_string(app)
            print(f"║ {name:<15}{count:>8} {pct:5.1f}% {bar:<20}  ║")

        print("╚══════════════════════════════════════════════════════════════╝")

        if s.detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in s.detected_snis.items():
                print(f"  - {sni} -> {app_type_to_string(app)}")


# ============================================================================
# Main
# ============================================================================
def print_usage(prog: str) -> None:
    print(f"""
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main():
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        return 1

    input_file  = sys.argv[1]
    output_file = sys.argv[2]

    cfg         = DPIEngine.Config()
    block_ips:    List[str] = []
    block_apps:   List[str] = []
    block_domains: List[str] = []

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1; block_ips.append(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1; block_apps.append(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1; block_domains.append(sys.argv[i])
        elif arg == "--lbs" and i + 1 < len(sys.argv):
            i += 1; cfg.num_lbs = int(sys.argv[i])
        elif arg == "--fps" and i + 1 < len(sys.argv):
            i += 1; cfg.fps_per_lb = int(sys.argv[i])
        i += 1

    engine = DPIEngine(cfg)

    for ip  in block_ips:    engine.block_ip(ip)
    for app in block_apps:   engine.block_app(app)
    for dom in block_domains: engine.block_domain(dom)

    if not engine.process(input_file, output_file):
        return 1

    print(f"\nOutput written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
