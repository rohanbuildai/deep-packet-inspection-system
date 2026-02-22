"""
thread_safe_queue.py - Thread-safe bounded queue.
Python equivalent of thread_safe_queue.h
"""

import queue
import threading
from typing import TypeVar, Generic, Optional

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    """Bounded thread-safe FIFO queue with shutdown support."""

    def __init__(self, max_size: int = 10000):
        self._queue:    queue.Queue = queue.Queue(maxsize=max_size)
        self._shutdown: bool        = False
        self._cond:     threading.Condition = threading.Condition()

    def push(self, item: T) -> None:
        """Push item; blocks if full. No-op after shutdown."""
        while not self._shutdown:
            try:
                self._queue.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def try_push(self, item: T) -> bool:
        """Non-blocking push. Returns False if full or shut down."""
        if self._shutdown:
            return False
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False

    def pop(self) -> Optional[T]:
        """Pop item; blocks until available or shutdown."""
        while True:
            try:
                return self._queue.get(timeout=0.1)
            except queue.Empty:
                if self._shutdown:
                    return None

    def pop_with_timeout(self, timeout_ms: int) -> Optional[T]:
        """Pop item with timeout in milliseconds."""
        try:
            return self._queue.get(timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def shutdown(self) -> None:
        """Signal shutdown; wake all waiters."""
        self._shutdown = True

    def is_shutdown(self) -> bool:
        return self._shutdown
