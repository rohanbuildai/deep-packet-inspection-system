"""
dpi_engine.py - Main DPI Engine orchestrator.
Python equivalent of dpi_engine.h + dpi_engine.cpp
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from pcap_reader import PcapReader
from packet_parser import PacketParser, ParsedPacket
from dpi_types import (
    AppType, FiveTuple, PacketJob, PacketAction,
    DPIStats, app_type_to_string, sni_to_app_type
)
from rule_manager import RuleManager
from thread_safe_queue import ThreadSafeQueue
from fast_path import FPManager
from load_balancer import LBManager
from connection_tracker import GlobalConnectionTable


def _parse_ip(ip_str: str) -> int:
    parts = [int(p) for p in ip_str.split(".")]
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)


# ============================================================================
# DPIEngine
# ============================================================================
class DPIEngine:

    @dataclass
    class Config:
        num_load_balancers: int  = 2
        fps_per_lb:         int  = 2
        queue_size:         int  = 10000
        rules_file:         str  = ""
        verbose:            bool = False

    def __init__(self, config: "DPIEngine.Config"):
        self._config = config

        total_fps = config.num_load_balancers * config.fps_per_lb

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0                            ║")
        print("║               Deep Packet Inspection System                   ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ Configuration:                                                ║")
        print(f"║   Load Balancers:    {config.num_load_balancers:>3}                                       ║")
        print(f"║   FPs per LB:        {config.fps_per_lb:>3}                                       ║")
        print(f"║   Total FP threads:  {total_fps:>3}                                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")

        self._rule_manager:      Optional[RuleManager]          = None
        self._global_conn_table: Optional[GlobalConnectionTable] = None
        self._fp_manager:        Optional[FPManager]            = None
        self._lb_manager:        Optional[LBManager]            = None

        self._output_queue      = ThreadSafeQueue(10000)
        self._output_thread:    Optional[threading.Thread] = None
        self._output_file:      Optional[object] = None
        self._output_mutex      = threading.Lock()

        self._stats             = DPIStats()
        self._running           = False
        self._processing_complete = False
        self._reader_thread:    Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    def initialize(self) -> bool:
        self._rule_manager = RuleManager()

        if self._config.rules_file:
            self._rule_manager.load_rules(self._config.rules_file)

        def output_cb(job: PacketJob, action: PacketAction):
            self._handle_output(job, action)

        total_fps = self._config.num_load_balancers * self._config.fps_per_lb

        self._fp_manager = FPManager(total_fps, self._rule_manager, output_cb)
        self._lb_manager = LBManager(
            self._config.num_load_balancers,
            self._config.fps_per_lb,
            self._fp_manager.get_queue_ptrs(),
        )

        self._global_conn_table = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self._global_conn_table.register_tracker(
                i, self._fp_manager.get_fp(i).connection_tracker
            )

        print("[DPIEngine] Initialized successfully")
        return True

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running             = True
        self._processing_complete = False

        self._output_thread = threading.Thread(target=self._output_thread_func, daemon=True)
        self._output_thread.start()

        self._fp_manager.start_all()
        self._lb_manager.start_all()

        print("[DPIEngine] All threads started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        self._lb_manager.stop_all()
        self._fp_manager.stop_all()

        self._output_queue.shutdown()
        if self._output_thread and self._output_thread.is_alive():
            self._output_thread.join(timeout=5)

        print("[DPIEngine] All threads stopped")

    def wait_for_completion(self) -> None:
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join()
        time.sleep(0.5)
        self._processing_complete = True

    # ------------------------------------------------------------------
    def process_file(self, input_file: str, output_file: str) -> bool:
        print(f"\n[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}\n")

        if not self._rule_manager:
            if not self.initialize():
                return False

        try:
            self._output_file = open(output_file, "wb")
        except OSError as e:
            print(f"[DPIEngine] Error: Cannot open output file: {e}", file=sys.stderr)
            return False

        self.start()

        self._reader_thread = threading.Thread(
            target=self._reader_thread_func, args=(input_file,), daemon=True
        )
        self._reader_thread.start()

        self.wait_for_completion()
        time.sleep(0.2)
        self.stop()

        if self._output_file:
            self._output_file.close()
            self._output_file = None

        print(self.generate_report())
        print(self._fp_manager.generate_classification_report())

        return True

    # ------------------------------------------------------------------
    def _reader_thread_func(self, input_file: str) -> None:
        reader = PcapReader()
        if not reader.open(input_file):
            print("[Reader] Error: Cannot open input file", file=sys.stderr)
            return

        self._write_output_header(reader.global_header)

        parsed    = ParsedPacket()
        packet_id = 0

        print("[Reader] Starting packet processing...")

        raw = reader.read_next_packet()
        while raw is not None:
            if not PacketParser.parse(raw, parsed):
                raw = reader.read_next_packet()
                continue
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                raw = reader.read_next_packet()
                continue

            job = self._create_packet_job(raw, parsed, packet_id)
            packet_id += 1

            self._stats.add("total_packets")
            self._stats.add("total_bytes", len(raw.data))
            if parsed.has_tcp:
                self._stats.add("tcp_packets")
            elif parsed.has_udp:
                self._stats.add("udp_packets")

            lb = self._lb_manager.get_lb_for_packet(job.tuple)
            lb.input_queue.push(job)

            raw = reader.read_next_packet()

        print(f"[Reader] Finished reading {packet_id} packets")
        reader.close()

    def _create_packet_job(self, raw, parsed: ParsedPacket, packet_id: int) -> PacketJob:
        job = PacketJob()
        job.packet_id = packet_id
        job.ts_sec    = raw.header.ts_sec
        job.ts_usec   = raw.header.ts_usec

        job.tuple = FiveTuple(
            src_ip   = _parse_ip(parsed.src_ip),
            dst_ip   = _parse_ip(parsed.dest_ip),
            src_port = parsed.src_port,
            dst_port = parsed.dest_port,
            protocol = parsed.protocol,
        )
        job.tcp_flags = parsed.tcp_flags
        job.data      = raw.data

        job.eth_offset = 0
        job.ip_offset  = 14

        data = raw.data
        if len(data) > 14:
            ip_ihl        = data[14] & 0x0F
            ip_hdr_len    = ip_ihl * 4
            job.transport_offset = 14 + ip_hdr_len

            if parsed.has_tcp and len(data) > job.transport_offset:
                tcp_data_off     = (data[job.transport_offset + 12] >> 4) & 0x0F
                tcp_hdr_len      = tcp_data_off * 4
                job.payload_offset = job.transport_offset + tcp_hdr_len
            elif parsed.has_udp:
                job.payload_offset = job.transport_offset + 8

            if job.payload_offset < len(data):
                job.payload_length = len(data) - job.payload_offset

        return job

    def _output_thread_func(self) -> None:
        while self._running or not self._output_queue.empty():
            job = self._output_queue.pop_with_timeout(100)
            if job is not None:
                self._write_output_packet(job)

    def _handle_output(self, job: PacketJob, action: PacketAction) -> None:
        if action == PacketAction.DROP:
            self._stats.add("dropped_packets")
            return
        self._stats.add("forwarded_packets")
        self._output_queue.push(job)

    def _write_output_header(self, header) -> bool:
        with self._output_mutex:
            if not self._output_file:
                return False
            self._output_file.write(header.raw_bytes)
            return True

    def _write_output_packet(self, job: PacketJob) -> None:
        with self._output_mutex:
            if not self._output_file:
                return
            phdr = struct.pack("<IIII", job.ts_sec, job.ts_usec,
                               len(job.data), len(job.data))
            self._output_file.write(phdr)
            self._output_file.write(job.data)

    # ------------------------------------------------------------------
    # Rule management API
    # ------------------------------------------------------------------
    def block_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_ip(ip)

    def block_app(self, app) -> None:
        if not self._rule_manager:
            return
        if isinstance(app, str):
            for at in AppType:
                if app_type_to_string(at) == app:
                    self._rule_manager.block_app(at)
                    return
            print(f"[DPIEngine] Unknown app: {app}", file=sys.stderr)
        else:
            self._rule_manager.block_app(app)

    def unblock_app(self, app) -> None:
        if not self._rule_manager:
            return
        if isinstance(app, str):
            for at in AppType:
                if app_type_to_string(at) == app:
                    self._rule_manager.unblock_app(at)
                    return
        else:
            self._rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_domain(domain)

    def load_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.load_rules(filename)
        return False

    def save_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.save_rules(filename)
        return False

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def generate_report(self) -> str:
        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║                    DPI ENGINE STATISTICS                      ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║ PACKET STATISTICS                                             ║")
        lines.append(f"║   Total Packets:      {self._stats.get('total_packets'):>12}                        ║")
        lines.append(f"║   Total Bytes:        {self._stats.get('total_bytes'):>12}                        ║")
        lines.append(f"║   TCP Packets:        {self._stats.get('tcp_packets'):>12}                        ║")
        lines.append(f"║   UDP Packets:        {self._stats.get('udp_packets'):>12}                        ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║ FILTERING STATISTICS                                          ║")
        lines.append(f"║   Forwarded:          {self._stats.get('forwarded_packets'):>12}                        ║")
        lines.append(f"║   Dropped/Blocked:    {self._stats.get('dropped_packets'):>12}                        ║")

        total = self._stats.get("total_packets")
        dropped = self._stats.get("dropped_packets")
        if total > 0:
            drop_rate = 100.0 * dropped / total
            lines.append(f"║   Drop Rate:          {drop_rate:>11.2f}%                        ║")

        if self._lb_manager:
            lb_stats = self._lb_manager.get_aggregated_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ LOAD BALANCER STATISTICS                                      ║")
            lines.append(f"║   LB Received:        {lb_stats.total_received:>12}                        ║")
            lines.append(f"║   LB Dispatched:      {lb_stats.total_dispatched:>12}                        ║")

        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ FAST PATH STATISTICS                                          ║")
            lines.append(f"║   FP Processed:       {fp_stats.total_processed:>12}                        ║")
            lines.append(f"║   FP Forwarded:       {fp_stats.total_forwarded:>12}                        ║")
            lines.append(f"║   FP Dropped:         {fp_stats.total_dropped:>12}                        ║")
            lines.append(f"║   Active Connections: {fp_stats.total_connections:>12}                        ║")

        if self._rule_manager:
            rs = self._rule_manager.get_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ BLOCKING RULES                                                ║")
            lines.append(f"║   Blocked IPs:        {rs.blocked_ips:>12}                        ║")
            lines.append(f"║   Blocked Apps:       {rs.blocked_apps:>12}                        ║")
            lines.append(f"║   Blocked Domains:    {rs.blocked_domains:>12}                        ║")
            lines.append(f"║   Blocked Ports:      {rs.blocked_ports:>12}                        ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

    def generate_classification_report(self) -> str:
        if self._fp_manager:
            return self._fp_manager.generate_classification_report()
        return ""

    def get_stats(self) -> DPIStats:
        return self._stats

    def print_status(self) -> None:
        print("\n--- Live Status ---")
        print(f"Packets: {self._stats.get('total_packets')}"
              f" | Forwarded: {self._stats.get('forwarded_packets')}"
              f" | Dropped: {self._stats.get('dropped_packets')}")
        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            print(f"Connections: {fp_stats.total_connections}")

    @property
    def rule_manager(self) -> Optional[RuleManager]:
        return self._rule_manager

    @property
    def config(self) -> "DPIEngine.Config":
        return self._config

    @property
    def is_running(self) -> bool:
        return self._running
