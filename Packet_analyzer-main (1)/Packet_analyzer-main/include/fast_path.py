"""
fast_path.py - Fast Path Processor thread.
Python equivalent of fast_path.h + fast_path.cpp
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Dict
from collections import defaultdict

from dpi_types import (
    FiveTuple, Connection, ConnectionState, AppType, PacketAction,
    PacketJob, app_type_to_string, sni_to_app_type
)
from thread_safe_queue import ThreadSafeQueue
from connection_tracker import ConnectionTracker
from rule_manager import RuleManager, BlockReasonType
from sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor


PacketOutputCallback = Callable[[PacketJob, PacketAction], None]


# ============================================================================
# FastPathProcessor
# ============================================================================
@dataclass
class FPStats:
    packets_processed:  int = 0
    packets_forwarded:  int = 0
    packets_dropped:    int = 0
    connections_tracked:int = 0
    sni_extractions:    int = 0
    classification_hits:int = 0


class FastPathProcessor:

    def __init__(self, fp_id: int,
                 rule_manager: RuleManager,
                 output_callback: PacketOutputCallback):
        self._fp_id            = fp_id
        self._input_queue      = ThreadSafeQueue(10000)
        self._conn_tracker     = ConnectionTracker(fp_id)
        self._rule_manager     = rule_manager
        self._output_callback  = output_callback

        self._packets_processed  = 0
        self._packets_forwarded  = 0
        self._packets_dropped    = 0
        self._sni_extractions    = 0
        self._classification_hits = 0

        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print(f"[FP{self._fp_id}] Started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print(f"[FP{self._fp_id}] Stopped (processed {self._packets_processed} packets)")

    # ------------------------------------------------------------------
    @property
    def input_queue(self) -> ThreadSafeQueue:
        return self._input_queue

    @property
    def connection_tracker(self) -> ConnectionTracker:
        return self._conn_tracker

    def get_stats(self) -> FPStats:
        return FPStats(
            packets_processed   = self._packets_processed,
            packets_forwarded   = self._packets_forwarded,
            packets_dropped     = self._packets_dropped,
            connections_tracked = self._conn_tracker.get_active_count(),
            sni_extractions     = self._sni_extractions,
            classification_hits = self._classification_hits,
        )

    # ------------------------------------------------------------------
    def _run(self) -> None:
        while self._running:
            job = self._input_queue.pop_with_timeout(100)
            if job is None:
                self._conn_tracker.cleanup_stale(300.0)
                continue

            self._packets_processed += 1
            action = self._process_packet(job)

            if self._output_callback:
                self._output_callback(job, action)

            if action == PacketAction.DROP:
                self._packets_dropped += 1
            else:
                self._packets_forwarded += 1

    def _process_packet(self, job: PacketJob) -> PacketAction:
        conn = self._conn_tracker.get_or_create_connection(job.tuple)
        self._conn_tracker.update_connection(conn, len(job.data), is_outbound=True)

        # TCP state
        if job.tuple.protocol == 6:
            self._update_tcp_state(conn, job.tcp_flags)

        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self._inspect_payload(job, conn)

        return self._check_rules(job, conn)

    def _inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        if job.payload_length == 0 or job.payload_offset >= len(job.data):
            return

        if self._try_extract_sni(job, conn):
            return
        if self._try_extract_http_host(job, conn):
            return

        # DNS
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            payload = job.data[job.payload_offset:]
            domain  = DNSExtractor.extract_query(payload, len(payload))
            if domain:
                self._conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # Port-based fallback
        if job.tuple.dst_port == 80:
            self._conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self._conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def _try_extract_sni(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 443 and job.payload_length < 50:
            return False
        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.data[job.payload_offset:]
        sni     = SNIExtractor.extract(payload, len(payload))
        if sni:
            self._sni_extractions += 1
            app = sni_to_app_type(sni)
            self._conn_tracker.classify_connection(conn, app, sni)
            if app not in (AppType.UNKNOWN, AppType.HTTPS):
                self._classification_hits += 1
            return True
        return False

    def _try_extract_http_host(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 80:
            return False
        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.data[job.payload_offset:]
        host    = HTTPHostExtractor.extract(payload, len(payload))
        if host:
            app = sni_to_app_type(host)
            self._conn_tracker.classify_connection(conn, app, host)
            if app not in (AppType.UNKNOWN, AppType.HTTP):
                self._classification_hits += 1
            return True
        return False

    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if not self._rule_manager:
            return PacketAction.FORWARD

        reason = self._rule_manager.should_block(
            job.tuple.src_ip,
            job.tuple.dst_port,
            conn.app_type,
            conn.sni,
        )
        if reason:
            type_name = reason.type.name
            print(f"[FP{self._fp_id}] BLOCKED packet: {type_name} {reason.detail}")
            self._conn_tracker.block_connection(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    def _update_tcp_state(self, conn: Connection, tcp_flags: int) -> None:
        SYN = 0x02
        ACK = 0x10
        FIN = 0x01
        RST = 0x04

        if tcp_flags & SYN:
            if tcp_flags & ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & FIN:
            conn.fin_seen = True

        if tcp_flags & RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (tcp_flags & ACK):
            conn.state = ConnectionState.CLOSED


# ============================================================================
# FPManager
# ============================================================================
@dataclass
class FPAggregatedStats:
    total_processed:   int = 0
    total_forwarded:   int = 0
    total_dropped:     int = 0
    total_connections: int = 0


class FPManager:

    def __init__(self, num_fps: int,
                 rule_manager: RuleManager,
                 output_callback: PacketOutputCallback):
        self._fps = [
            FastPathProcessor(i, rule_manager, output_callback)
            for i in range(num_fps)
        ]
        print(f"[FPManager] Created {num_fps} fast path processors")

    def start_all(self) -> None:
        for fp in self._fps:
            fp.start()

    def stop_all(self) -> None:
        for fp in self._fps:
            fp.stop()

    def get_fp(self, idx: int) -> FastPathProcessor:
        return self._fps[idx]

    def get_queue_ptrs(self) -> List[ThreadSafeQueue]:
        return [fp.input_queue for fp in self._fps]

    def get_num_fps(self) -> int:
        return len(self._fps)

    def get_aggregated_stats(self) -> FPAggregatedStats:
        agg = FPAggregatedStats()
        for fp in self._fps:
            s = fp.get_stats()
            agg.total_processed   += s.packets_processed
            agg.total_forwarded   += s.packets_forwarded
            agg.total_dropped     += s.packets_dropped
            agg.total_connections += s.connections_tracked
        return agg

    def generate_classification_report(self) -> str:
        app_counts:    Dict[AppType, int] = defaultdict(int)
        domain_counts: Dict[str, int]     = defaultdict(int)
        total_classified = 0
        total_unknown    = 0

        for fp in self._fps:
            def _collect(conn: Connection):
                nonlocal total_classified, total_unknown
                app_counts[conn.app_type] += 1
                if conn.app_type == AppType.UNKNOWN:
                    total_unknown += 1
                else:
                    total_classified += 1
                if conn.sni:
                    domain_counts[conn.sni] += 1
            fp.connection_tracker.for_each(_collect)

        total = total_classified + total_unknown
        cp    = 100.0 * total_classified / total if total else 0
        up    = 100.0 * total_unknown    / total if total else 0

        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║                 APPLICATION CLASSIFICATION REPORT             ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append(f"║ Total Connections:    {total:>10}                           ║")
        lines.append(f"║ Classified:           {total_classified:>10} ({cp:.1f}%)                  ║")
        lines.append(f"║ Unidentified:         {total_unknown:>10} ({up:.1f}%)                  ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║                    APPLICATION DISTRIBUTION                   ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct     = 100.0 * count / total if total else 0
            bar_len = int(pct / 5)
            bar     = "#" * bar_len
            name    = app_type_to_string(app)
            lines.append(f"║ {name:<15}{count:>8} {pct:5.1f}% {bar:<20}   ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
