"""
load_balancer.py - Load Balancer threads.
Python equivalent of load_balancer.h + load_balancer.cpp
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import threading
from dataclasses import dataclass, field
from typing import List, Optional

from dpi_types import FiveTuple, PacketJob
from thread_safe_queue import ThreadSafeQueue


# ============================================================================
# LoadBalancer
# ============================================================================
@dataclass
class LBStats:
    packets_received:   int = 0
    packets_dispatched: int = 0
    per_fp_packets:     List[int] = field(default_factory=list)


class LoadBalancer:

    def __init__(self, lb_id: int,
                 fp_queues: List[ThreadSafeQueue],
                 fp_start_id: int = 0):
        self._lb_id       = lb_id
        self._fp_start_id = fp_start_id
        self._num_fps     = len(fp_queues)
        self._fp_queues   = fp_queues
        self._input_queue = ThreadSafeQueue(10000)

        self._packets_received   = 0
        self._packets_dispatched = 0
        self._per_fp_counts      = [0] * self._num_fps

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        end_id = self._fp_start_id + self._num_fps - 1
        print(f"[LB{self._lb_id}] Started (serving FP{self._fp_start_id}-FP{end_id})")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print(f"[LB{self._lb_id}] Stopped")

    @property
    def input_queue(self) -> ThreadSafeQueue:
        return self._input_queue

    def get_stats(self) -> LBStats:
        return LBStats(
            packets_received   = self._packets_received,
            packets_dispatched = self._packets_dispatched,
            per_fp_packets     = list(self._per_fp_counts),
        )

    # ------------------------------------------------------------------
    def _run(self) -> None:
        while self._running:
            job = self._input_queue.pop_with_timeout(100)
            if job is None:
                continue

            self._packets_received += 1
            fp_index = self._select_fp(job.tuple)
            self._fp_queues[fp_index].push(job)
            self._packets_dispatched += 1
            self._per_fp_counts[fp_index] += 1

    def _select_fp(self, tuple_: FiveTuple) -> int:
        return hash(tuple_) % self._num_fps


# ============================================================================
# LBManager
# ============================================================================
@dataclass
class LBAggregatedStats:
    total_received:   int = 0
    total_dispatched: int = 0


class LBManager:

    def __init__(self, num_lbs: int, fps_per_lb: int,
                 fp_queues: List[ThreadSafeQueue]):
        self._fps_per_lb = fps_per_lb
        self._lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            fp_start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[fp_start: fp_start + fps_per_lb]
            self._lbs.append(LoadBalancer(lb_id, lb_fp_queues, fp_start))

        print(f"[LBManager] Created {num_lbs} load balancers, {fps_per_lb} FPs each")

    def start_all(self) -> None:
        for lb in self._lbs:
            lb.start()

    def stop_all(self) -> None:
        for lb in self._lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_: FiveTuple) -> LoadBalancer:
        lb_index = hash(tuple_) % len(self._lbs)
        return self._lbs[lb_index]

    def get_lb(self, idx: int) -> LoadBalancer:
        return self._lbs[idx]

    def get_num_lbs(self) -> int:
        return len(self._lbs)

    def get_aggregated_stats(self) -> LBAggregatedStats:
        agg = LBAggregatedStats()
        for lb in self._lbs:
            s = lb.get_stats()
            agg.total_received   += s.packets_received
            agg.total_dispatched += s.packets_dispatched
        return agg
