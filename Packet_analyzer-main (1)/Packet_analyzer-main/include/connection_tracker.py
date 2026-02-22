"""
connection_tracker.py - Track active network connections per FP thread.
Python equivalent of connection_tracker.h + connection_tracker.cpp
"""

import time
import threading
from dataclasses import dataclass
from typing import Dict, Optional, List, Callable

from dpi_types import (
    FiveTuple, Connection, ConnectionState, AppType, PacketAction,
    app_type_to_string
)


# ============================================================================
# ConnectionTracker
# ============================================================================
@dataclass
class TrackerStats:
    active_connections:      int = 0
    total_connections_seen:  int = 0
    classified_connections:  int = 0
    blocked_connections:     int = 0


class ConnectionTracker:
    """Per-FP thread connection table. Not thread-safe by design (single owner)."""

    def __init__(self, fp_id: int, max_connections: int = 100_000):
        self._fp_id            = fp_id
        self._max_connections  = max_connections
        self._connections:     Dict[FiveTuple, Connection] = {}
        self._total_seen       = 0
        self._classified_count = 0
        self._blocked_count    = 0

    # ------------------------------------------------------------------
    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        if tuple_ in self._connections:
            return self._connections[tuple_]

        if len(self._connections) >= self._max_connections:
            self._evict_oldest()

        now = time.monotonic()
        conn = Connection(
            tuple=tuple_,
            state=ConnectionState.NEW,
            first_seen=now,
            last_seen=now,
        )
        self._connections[tuple_] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        if tuple_ in self._connections:
            return self._connections[tuple_]
        rev = tuple_.reverse()
        return self._connections.get(rev)

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool) -> None:
        if not conn:
            return
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out   += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in   += packet_size

    def classify_connection(self, conn: Connection, app: AppType, sni: str) -> None:
        if not conn:
            return
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni      = sni
            conn.state    = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        if not conn:
            return
        conn.state  = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        if tuple_ in self._connections:
            self._connections[tuple_].state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        now     = time.monotonic()
        to_del  = [
            k for k, v in self._connections.items()
            if (now - v.last_seen) > timeout_seconds or v.state == ConnectionState.CLOSED
        ]
        for k in to_del:
            del self._connections[k]
        return len(to_del)

    def get_all_connections(self) -> List[Connection]:
        return list(self._connections.values())

    def get_active_count(self) -> int:
        return len(self._connections)

    def get_stats(self) -> TrackerStats:
        return TrackerStats(
            active_connections     = len(self._connections),
            total_connections_seen = self._total_seen,
            classified_connections = self._classified_count,
            blocked_connections    = self._blocked_count,
        )

    def clear(self) -> None:
        self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._connections.values():
            callback(conn)

    def _evict_oldest(self) -> None:
        if not self._connections:
            return
        oldest_key = min(self._connections, key=lambda k: self._connections[k].last_seen)
        del self._connections[oldest_key]


# ============================================================================
# GlobalConnectionTable
# ============================================================================
@dataclass
class GlobalStats:
    total_active_connections:  int
    total_connections_seen:    int
    app_distribution:          Dict[AppType, int]
    top_domains:               List[tuple]  # (domain, count) sorted


class GlobalConnectionTable:
    """Read-only aggregation across all FP trackers."""

    def __init__(self, num_fps: int):
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.RLock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        with self._lock:
            if 0 <= fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    def get_global_stats(self) -> GlobalStats:
        with self._lock:
            total_active = 0
            total_seen   = 0
            app_dist:    Dict[AppType, int] = {}
            domain_counts: Dict[str, int]  = {}

            for tracker in self._trackers:
                if not tracker:
                    continue
                ts = tracker.get_stats()
                total_active += ts.active_connections
                total_seen   += ts.total_connections_seen

                def _collect(conn: Connection):
                    app_dist[conn.app_type] = app_dist.get(conn.app_type, 0) + 1
                    if conn.sni:
                        domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

                tracker.for_each(_collect)

            top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]

            return GlobalStats(
                total_active_connections = total_active,
                total_connections_seen   = total_seen,
                app_distribution         = app_dist,
                top_domains              = top_domains,
            )

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║               CONNECTION STATISTICS REPORT                    ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append(f"║ Active Connections:     {stats.total_active_connections:>10}                          ║")
        lines.append(f"║ Total Connections Seen: {stats.total_connections_seen:>10}                          ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║                    APPLICATION BREAKDOWN                      ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        total = sum(stats.app_distribution.values())
        sorted_apps = sorted(stats.app_distribution.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = 100.0 * count / total if total else 0
            name = app_type_to_string(app)
            lines.append(f"║ {name:<20}{count:>10} ({pct:5.1f}%)           ║")

        if stats.top_domains:
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║                      TOP DOMAINS                             ║")
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            for domain, count in stats.top_domains:
                if len(domain) > 35:
                    domain = domain[:32] + "..."
                lines.append(f"║ {domain:<40}{count:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
