"""
types.py - Core data types for the DPI engine.
Python equivalent of types.h + types.cpp
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import threading


# ============================================================================
# Application Classification
# ============================================================================
class AppType(Enum):
    UNKNOWN    = 0
    HTTP       = auto()
    HTTPS      = auto()
    DNS        = auto()
    TLS        = auto()
    QUIC       = auto()
    # Specific applications (detected via SNI)
    GOOGLE     = auto()
    FACEBOOK   = auto()
    YOUTUBE    = auto()
    TWITTER    = auto()
    INSTAGRAM  = auto()
    NETFLIX    = auto()
    AMAZON     = auto()
    MICROSOFT  = auto()
    APPLE      = auto()
    WHATSAPP   = auto()
    TELEGRAM   = auto()
    TIKTOK     = auto()
    SPOTIFY    = auto()
    ZOOM       = auto()
    DISCORD    = auto()
    GITHUB     = auto()
    CLOUDFLARE = auto()
    APP_COUNT  = auto()  # Keep last for counting


def app_type_to_string(app_type: AppType) -> str:
    mapping = {
        AppType.UNKNOWN:    "Unknown",
        AppType.HTTP:       "HTTP",
        AppType.HTTPS:      "HTTPS",
        AppType.DNS:        "DNS",
        AppType.TLS:        "TLS",
        AppType.QUIC:       "QUIC",
        AppType.GOOGLE:     "Google",
        AppType.FACEBOOK:   "Facebook",
        AppType.YOUTUBE:    "YouTube",
        AppType.TWITTER:    "Twitter/X",
        AppType.INSTAGRAM:  "Instagram",
        AppType.NETFLIX:    "Netflix",
        AppType.AMAZON:     "Amazon",
        AppType.MICROSOFT:  "Microsoft",
        AppType.APPLE:      "Apple",
        AppType.WHATSAPP:   "WhatsApp",
        AppType.TELEGRAM:   "Telegram",
        AppType.TIKTOK:     "TikTok",
        AppType.SPOTIFY:    "Spotify",
        AppType.ZOOM:       "Zoom",
        AppType.DISCORD:    "Discord",
        AppType.GITHUB:     "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return mapping.get(app_type, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    """Map SNI/domain to application type."""
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    if any(x in lower for x in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE
    if any(x in lower for x in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE
    if any(x in lower for x in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK
    if any(x in lower for x in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM
    if any(x in lower for x in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP
    if any(x in lower for x in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER
    if any(x in lower for x in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX
    if any(x in lower for x in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON
    if any(x in lower for x in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")):
        return AppType.MICROSOFT
    if any(x in lower for x in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE
    if any(x in lower for x in ("telegram", "t.me")):
        return AppType.TELEGRAM
    if any(x in lower for x in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK
    if any(x in lower for x in ("spotify", "scdn.co")):
        return AppType.SPOTIFY
    if "zoom" in lower:
        return AppType.ZOOM
    if any(x in lower for x in ("discord", "discordapp")):
        return AppType.DISCORD
    if any(x in lower for x in ("github", "githubusercontent")):
        return AppType.GITHUB
    if any(x in lower for x in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    return AppType.HTTPS


# ============================================================================
# Connection State
# ============================================================================
class ConnectionState(Enum):
    NEW         = auto()
    ESTABLISHED = auto()
    CLASSIFIED  = auto()
    BLOCKED     = auto()
    CLOSED      = auto()


# ============================================================================
# Packet Action
# ============================================================================
class PacketAction(Enum):
    FORWARD  = auto()
    DROP     = auto()
    INSPECT  = auto()
    LOG_ONLY = auto()


# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
@dataclass(frozen=True)
class FiveTuple:
    src_ip:   int  # uint32
    dst_ip:   int  # uint32
    src_port: int  # uint16
    dst_port: int  # uint16
    protocol: int  # uint8  TCP=6, UDP=17

    def reverse(self) -> FiveTuple:
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def __hash__(self):
        h = 0
        for val in (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol):
            h ^= hash(val) + 0x9e3779b9 + (h << 6) + (h >> 2)
        return h

    def to_string(self) -> str:
        def fmt_ip(ip):
            return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{fmt_ip(self.src_ip)}:{self.src_port} -> {fmt_ip(self.dst_ip)}:{self.dst_port} ({proto})"


# ============================================================================
# Connection Entry (tracked per flow)
# ============================================================================
@dataclass
class Connection:
    tuple:       FiveTuple      = None
    state:       ConnectionState = ConnectionState.NEW
    app_type:    AppType         = AppType.UNKNOWN
    sni:         str             = ""

    packets_in:  int = 0
    packets_out: int = 0
    bytes_in:    int = 0
    bytes_out:   int = 0

    first_seen:  float = field(default_factory=time.monotonic)
    last_seen:   float = field(default_factory=time.monotonic)

    action:      PacketAction = PacketAction.FORWARD

    # TCP state tracking
    syn_seen:     bool = False
    syn_ack_seen: bool = False
    fin_seen:     bool = False


# ============================================================================
# Packet wrapper for queue passing
# ============================================================================
@dataclass
class PacketJob:
    packet_id:        int   = 0
    tuple:            FiveTuple = None
    data:             bytes = b""
    eth_offset:       int   = 0
    ip_offset:        int   = 0
    transport_offset: int   = 0
    payload_offset:   int   = 0
    payload_length:   int   = 0
    tcp_flags:        int   = 0

    ts_sec:           int   = 0
    ts_usec:          int   = 0


# ============================================================================
# Statistics (thread-safe via lock)
# ============================================================================
class DPIStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.total_packets     = 0
        self.total_bytes       = 0
        self.forwarded_packets = 0
        self.dropped_packets   = 0
        self.tcp_packets       = 0
        self.udp_packets       = 0
        self.other_packets     = 0
        self.active_connections= 0

    def add(self, field_name: str, value: int = 1):
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + value)

    def get(self, field_name: str) -> int:
        with self._lock:
            return getattr(self, field_name)
