"""
sni_extractor.py - Extract SNI / Host headers from packet payloads.
Python equivalent of sni_extractor.h + sni_extractor.cpp
"""

import struct
from typing import Optional


# ============================================================================
# TLS SNI Extractor
# ============================================================================
CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI          = 0x0000
SNI_TYPE_HOSTNAME      = 0x00


def _read_uint16be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _read_uint24be(data: bytes, offset: int) -> int:
    b = data[offset:offset + 3]
    return (b[0] << 16) | (b[1] << 8) | b[2]


class SNIExtractor:

    @staticmethod
    def is_tls_client_hello(payload: bytes, length: int) -> bool:
        if length < 9:
            return False
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return False
        version = _read_uint16be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        record_length = _read_uint16be(payload, 3)
        if record_length > length - 5:
            return False
        if payload[5] != HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        """Extract SNI from TLS Client Hello. Returns hostname or None."""
        if not SNIExtractor.is_tls_client_hello(payload, length):
            return None

        try:
            offset = 5  # Skip TLS record header

            # Skip handshake type + 3-byte length
            # handshake_length = _read_uint24be(payload, offset + 1)
            offset += 4

            # Client version (2 bytes)
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            if offset >= length:
                return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            # Cipher suites
            if offset + 2 > length:
                return None
            cipher_suites_len = _read_uint16be(payload, offset)
            offset += 2 + cipher_suites_len

            # Compression methods
            if offset >= length:
                return None
            compression_len = payload[offset]
            offset += 1 + compression_len

            # Extensions
            if offset + 2 > length:
                return None
            extensions_len = _read_uint16be(payload, offset)
            offset += 2

            extensions_end = min(offset + extensions_len, length)

            while offset + 4 <= extensions_end:
                ext_type   = _read_uint16be(payload, offset)
                ext_length = _read_uint16be(payload, offset + 2)
                offset += 4

                if offset + ext_length > extensions_end:
                    break

                if ext_type == EXTENSION_SNI:
                    # SNI List Length (2) + SNI Type (1) + SNI Length (2) + SNI Value
                    if ext_length < 5:
                        break
                    # sni_list_len = _read_uint16be(payload, offset)
                    sni_type   = payload[offset + 2]
                    sni_length = _read_uint16be(payload, offset + 3)
                    if sni_type != SNI_TYPE_HOSTNAME:
                        break
                    if sni_length > ext_length - 5:
                        break
                    sni = payload[offset + 5: offset + 5 + sni_length].decode("ascii", errors="ignore")
                    return sni

                offset += ext_length

        except (IndexError, struct.error):
            pass

        return None


# ============================================================================
# HTTP Host Header Extractor
# ============================================================================
class HTTPHostExtractor:

    HTTP_METHODS = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]

    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        if length < 4:
            return False
        return any(payload[:4] == m for m in HTTPHostExtractor.HTTP_METHODS)

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        """Extract Host header from HTTP request. Returns hostname or None."""
        if not HTTPHostExtractor.is_http_request(payload, length):
            return None

        try:
            text = payload[:length].decode("ascii", errors="ignore")
            lines = text.split("\r\n")
            for line in lines[1:]:  # skip request line
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                    # Remove port if present
                    if ":" in host:
                        host = host.split(":")[0]
                    return host
        except Exception:
            pass

        return None


# ============================================================================
# DNS Query Extractor
# ============================================================================
class DNSExtractor:

    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        if length < 12:
            return False
        flags = payload[2]
        if flags & 0x80:  # QR bit set → response
            return False
        qdcount = struct.unpack_from(">H", payload, 4)[0]
        return qdcount > 0

    @staticmethod
    def extract_query(payload: bytes, length: int) -> Optional[str]:
        """Extract queried domain from DNS request."""
        if not DNSExtractor.is_dns_query(payload, length):
            return None

        offset = 12
        labels = []
        try:
            while offset < length:
                label_len = payload[offset]
                if label_len == 0:
                    break
                if label_len > 63:
                    break
                offset += 1
                if offset + label_len > length:
                    break
                labels.append(payload[offset:offset + label_len].decode("ascii", errors="ignore"))
                offset += label_len
        except Exception:
            pass

        if not labels:
            return None
        return ".".join(labels)


# ============================================================================
# QUIC SNI Extractor (simplified)
# ============================================================================
class QUICSNIExtractor:

    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        if length < 5:
            return False
        first_byte = payload[0]
        return (first_byte & 0x80) != 0  # Long header form

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload, length):
            return None
        # Search for TLS Client Hello pattern within QUIC packet
        for i in range(length - 50):
            if payload[i] == 0x01:  # Client Hello handshake type
                start = max(0, i - 5)
                result = SNIExtractor.extract(payload[start:], length - start)
                if result:
                    return result
        return None
