"""
rule_manager.py - Manage blocking/filtering rules.
Python equivalent of rule_manager.h + rule_manager.cpp
"""

import threading
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, List, Set

from dpi_types import AppType, app_type_to_string


def _parse_ip(ip_str: str) -> int:
    """Parse dotted-decimal IP to uint32 (little-endian byte order)."""
    parts = [int(p) for p in ip_str.strip().split(".")]
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)


def _ip_to_string(ip: int) -> str:
    return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


# ============================================================================
# RuleManager
# ============================================================================
class BlockReasonType(Enum):
    IP     = auto()
    APP    = auto()
    DOMAIN = auto()
    PORT   = auto()


@dataclass
class BlockReason:
    type:   BlockReasonType
    detail: str


@dataclass
class RuleStats:
    blocked_ips:     int = 0
    blocked_apps:    int = 0
    blocked_domains: int = 0
    blocked_ports:   int = 0


class RuleManager:

    def __init__(self):
        self._ip_lock:      threading.RLock = threading.RLock()
        self._app_lock:     threading.RLock = threading.RLock()
        self._domain_lock:  threading.RLock = threading.RLock()
        self._port_lock:    threading.RLock = threading.RLock()

        self._blocked_ips:     Set[int]     = set()
        self._blocked_apps:    Set[AppType] = set()
        self._blocked_domains: Set[str]     = set()
        self._domain_patterns: List[str]    = []
        self._blocked_ports:   Set[int]     = set()

    # ------------------------------------------------------------------
    # IP Blocking
    # ------------------------------------------------------------------
    def block_ip(self, ip) -> None:
        if isinstance(ip, str):
            ip = _parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.add(ip)
            print(f"[RuleManager] Blocked IP: {_ip_to_string(ip)}")

    def unblock_ip(self, ip) -> None:
        if isinstance(ip, str):
            ip = _parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.discard(ip)
            print(f"[RuleManager] Unblocked IP: {_ip_to_string(ip)}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._ip_lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._ip_lock:
            return [_ip_to_string(ip) for ip in self._blocked_ips]

    # ------------------------------------------------------------------
    # Application Blocking
    # ------------------------------------------------------------------
    def block_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.add(app)
            print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.discard(app)
            print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._app_lock:
            return list(self._blocked_apps)

    # ------------------------------------------------------------------
    # Domain Blocking
    # ------------------------------------------------------------------
    def block_domain(self, domain: str) -> None:
        with self._domain_lock:
            if "*" in domain:
                self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
            print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        with self._domain_lock:
            if "*" in domain:
                try:
                    self._domain_patterns.remove(domain)
                except ValueError:
                    pass
            else:
                self._blocked_domains.discard(domain)
            print(f"[RuleManager] Unblocked domain: {domain}")

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """Support *.example.com wildcard matching."""
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            if domain.endswith(suffix):
                return True
            # Also match bare domain
            if domain == pattern[2:]:
                return True
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        lower = domain.lower()
        with self._domain_lock:
            if lower in self._blocked_domains:
                return True
            for pat in self._domain_patterns:
                if self._domain_matches_pattern(lower, pat.lower()):
                    return True
        return False

    def get_blocked_domains(self) -> List[str]:
        with self._domain_lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    # ------------------------------------------------------------------
    # Port Blocking
    # ------------------------------------------------------------------
    def block_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.add(port)
            print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._port_lock:
            return port in self._blocked_ports

    # ------------------------------------------------------------------
    # Combined Check
    # ------------------------------------------------------------------
    def should_block(self, src_ip: int, dst_port: int,
                     app: AppType, domain: str) -> Optional[BlockReason]:
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockReasonType.IP, _ip_to_string(src_ip))
        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReasonType.PORT, str(dst_port))
        if self.is_app_blocked(app):
            return BlockReason(BlockReasonType.APP, app_type_to_string(app))
        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReasonType.DOMAIN, domain)
        return None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, "w") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(ip + "\n")
                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(app_type_to_string(app) + "\n")
                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(domain + "\n")
                f.write("\n[BLOCKED_PORTS]\n")
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(str(port) + "\n")
            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError as e:
            print(f"[RuleManager] Error saving rules: {e}")
            return False

    def load_rules(self, filename: str) -> bool:
        try:
            current_section = ""
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("["):
                        current_section = line
                        continue
                    if current_section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif current_section == "[BLOCKED_APPS]":
                        for app in AppType:
                            if app_type_to_string(app) == line:
                                self.block_app(app)
                                break
                    elif current_section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif current_section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))
            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError as e:
            print(f"[RuleManager] Error loading rules: {e}")
            return False

    def clear_all(self) -> None:
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    def get_stats(self) -> RuleStats:
        stats = RuleStats()
        with self._ip_lock:
            stats.blocked_ips = len(self._blocked_ips)
        with self._app_lock:
            stats.blocked_apps = len(self._blocked_apps)
        with self._domain_lock:
            stats.blocked_domains = len(self._blocked_domains) + len(self._domain_patterns)
        with self._port_lock:
            stats.blocked_ports = len(self._blocked_ports)
        return stats
