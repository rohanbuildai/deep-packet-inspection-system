"""
pcap_reader.py - Read PCAP files.
Python equivalent of pcap_reader.h + pcap_reader.cpp
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


# PCAP Magic Numbers
PCAP_MAGIC_NATIVE  = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1


@dataclass
class PcapGlobalHeader:
    magic_number:  int = 0  # uint32
    version_major: int = 0  # uint16
    version_minor: int = 0  # uint16
    thiszone:      int = 0  # int32
    sigfigs:       int = 0  # uint32
    snaplen:       int = 0  # uint32
    network:       int = 0  # uint32

    # Store the raw bytes of the header for pass-through writing
    raw_bytes: bytes = field(default=b"", repr=False)

    STRUCT_FMT  = "<IHHiIII"
    STRUCT_SIZE = struct.calcsize("<IHHiIII")  # 24 bytes


@dataclass
class PcapPacketHeader:
    ts_sec:   int = 0  # uint32
    ts_usec:  int = 0  # uint32
    incl_len: int = 0  # uint32
    orig_len: int = 0  # uint32

    STRUCT_FMT  = "<IIII"
    STRUCT_SIZE = struct.calcsize("<IIII")  # 16 bytes


@dataclass
class RawPacket:
    header: PcapPacketHeader = field(default_factory=PcapPacketHeader)
    data:   bytes            = b""


class PcapReader:
    """Read standard .pcap files."""

    def __init__(self):
        self._file          = None
        self._global_header = PcapGlobalHeader()
        self._needs_swap    = False

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            print(f"Error: Could not open file: {filename} ({e})")
            return False

        raw = self._file.read(PcapGlobalHeader.STRUCT_SIZE)
        if len(raw) < PcapGlobalHeader.STRUCT_SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic = struct.unpack_from("<I", raw)[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._needs_swap = False
            fmt = "<IHHiIII"
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_swap = True
            fmt = ">IHHiIII"
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08X}")
            self.close()
            return False

        fields = struct.unpack(fmt, raw)
        gh = PcapGlobalHeader(
            magic_number  = fields[0],
            version_major = fields[1],
            version_minor = fields[2],
            thiszone      = fields[3],
            sigfigs       = fields[4],
            snaplen       = fields[5],
            network       = fields[6],
            raw_bytes     = raw,
        )
        self._global_header = gh

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {gh.version_major}.{gh.version_minor}")
        print(f"  Snaplen: {gh.snaplen} bytes")
        link = " (Ethernet)" if gh.network == 1 else ""
        print(f"  Link type: {gh.network}{link}")

        return True

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
        self._needs_swap = False

    def read_next_packet(self) -> Optional[RawPacket]:
        """Return next RawPacket, or None if EOF / error."""
        if not self._file:
            return None

        hdr_raw = self._file.read(PcapPacketHeader.STRUCT_SIZE)
        if len(hdr_raw) < PcapPacketHeader.STRUCT_SIZE:
            return None

        fmt = ">IIII" if self._needs_swap else "<IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr_raw)

        if incl_len > max(self._global_header.snaplen, 65535) or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return None

        pkt = RawPacket(
            header=PcapPacketHeader(ts_sec=ts_sec, ts_usec=ts_usec,
                                    incl_len=incl_len, orig_len=orig_len),
            data=data,
        )
        return pkt

    @property
    def global_header(self) -> PcapGlobalHeader:
        return self._global_header

    def is_open(self) -> bool:
        return self._file is not None

    def needs_byte_swap(self) -> bool:
        return self._needs_swap
