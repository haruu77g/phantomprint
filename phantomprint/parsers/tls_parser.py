"""
phantomprint/parsers/tls_parser.py

Parser de fingerprinting TLS pasivo — genera fingerprints JA4.

JA4 es el sucesor de JA3, desarrollado por FoxIO en 2023.
Más resistente a randomización de cipher suites que JA3.

Spec JA4: https://github.com/FoxIO-LLC/ja4
Paper original JA3: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s/

Formato JA4:
  {proto}{version}{has_sni}{cipher_count}{ext_count}_{sorted_ciphers}_{sorted_extensions}
  
Ejemplo:
  t13d1516h2_8daaf6152771_b1ff8ab37f4a (Chrome 120 en TLS 1.3)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from phantomprint.correlator.signal_merger import FingerprintSignal

# Cipher suites GREASE — deben ser excluidas del fingerprint JA4
# Son valores aleatorios que Chrome/otros inyectan para detectar middleboxes
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# Versiones TLS conocidas
TLS_VERSIONS = {
    0x0301: "10",  # TLS 1.0
    0x0302: "11",  # TLS 1.1
    0x0303: "12",  # TLS 1.2
    0x0304: "13",  # TLS 1.3
}

# Extension types conocidas
TLS_EXT_NAMES = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    51: "key_share",
    65281: "renegotiation_info",
}


@dataclass
class TLSClientHelloFeatures:
    """Features extraídos de un TLS ClientHello."""
    tls_version: str               # Versión TLS negociada
    cipher_suites: list[int]       # Sin GREASE, sin null/empty
    extensions: list[int]          # IDs de extensiones, en orden
    has_sni: bool                  # Server Name Indication presente
    alpn_protocols: list[str]      # Protocolos ALPN (h2, http/1.1, etc.)
    supported_groups: list[int]    # Elliptic curves soportadas
    signature_algorithms: list[int]


@dataclass
class JA4Fingerprint:
    """Fingerprint JA4 completo."""
    ja4_a: str   # {proto}{ver}{sni}{ciphers_count}{ext_count}
    ja4_b: str   # hash de cipher suites ordenados
    ja4_c: str   # hash de extensions ordenadas + alpn + sig_algs
    full: str    # ja4_a_ja4_b_ja4_c

    @classmethod
    def build(cls, features: TLSClientHelloFeatures) -> "JA4Fingerprint":
        # Parte A: metadata legible
        proto = "t"  # tcp (vs "q" para QUIC/UDP — futuro)
        version = features.tls_version
        sni = "d" if features.has_sni else "i"  # domain | ip
        cipher_count = str(len(features.cipher_suites)).zfill(2)
        ext_count = str(len(features.extensions)).zfill(2)
        ja4_a = f"{proto}{version}{sni}{cipher_count}{ext_count}"

        # Parte B: cipher suites ordenados (sort numérico, hex 4 chars)
        sorted_ciphers = sorted(features.cipher_suites)
        cipher_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

        # Parte C: extensions + alpn + sig_algs
        # Extensions ordenadas SIN SNI y SIN ALPN (están en ja4_a)
        ext_for_hash = sorted(
            e for e in features.extensions
            if e not in (0, 16)  # excluir SNI y ALPN del hash
        )
        ext_str = ",".join(str(e) for e in ext_for_hash)
        alpn_str = features.alpn_protocols[0] if features.alpn_protocols else ""
        sig_str = ",".join(str(s) for s in features.signature_algorithms)
        c_raw = f"{ext_str}_{alpn_str}_{sig_str}"
        ja4_c = hashlib.sha256(c_raw.encode()).hexdigest()[:12]

        full = f"{ja4_a}_{ja4_b}_{ja4_c}"
        return cls(ja4_a=ja4_a, ja4_b=ja4_b, ja4_c=ja4_c, full=full)


class TLSParser:
    """
    Parser pasivo de TLS ClientHello.
    
    Opera a nivel de bytes crudos — no requiere descifrar el tráfico.
    El ClientHello viaja en claro porque es el primer mensaje del handshake,
    antes de que se establezca la sesión cifrada.
    
    Arquitectura del parsing:
      pkt → detectar TLS record → parsear ClientHello → extraer features → JA4
    """

    # TLS Content Type: Handshake = 0x16
    TLS_HANDSHAKE = 0x16
    # Handshake Type: ClientHello = 0x01
    CLIENT_HELLO = 0x01

    def parse(self, pkt) -> Optional[tuple[str, FingerprintSignal]]:
        """
        Retorna (src_ip, FingerprintSignal) si el paquete es un TLS ClientHello.
        Retorna None en cualquier otro caso.
        """
        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            return None

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None

        tcp = pkt[TCP]

        # Necesitamos payload TCP con datos
        try:
            payload = bytes(tcp.payload)
        except Exception:
            return None

        if len(payload) < 6:
            return None

        # Verificar TLS Record Header
        # Byte 0: Content Type (0x16 = Handshake)
        # Bytes 1-2: Legacy TLS Version
        # Bytes 3-4: Record Length
        if payload[0] != self.TLS_HANDSHAKE:
            return None

        # Verificar que es un ClientHello dentro del Handshake Record
        # Handshake Header: Type(1) + Length(3) + ...
        if len(payload) < 9 or payload[5] != self.CLIENT_HELLO:
            return None

        src_ip = pkt[IP].src
        features = self._parse_client_hello(payload[5:])

        if not features:
            return None

        signal = self._build_signal(features)
        return (src_ip, signal)

    def _parse_client_hello(self, data: bytes) -> Optional[TLSClientHelloFeatures]:
        """
        Parsea el payload de un ClientHello en crudo.
        
        Estructura ClientHello (RFC 8446):
          HandshakeType(1) + Length(3) + LegacyVersion(2) +
          Random(32) + SessionID_len(1) + SessionID(var) +
          CipherSuites_len(2) + CipherSuites(var) +
          CompressionMethods_len(1) + CompressionMethods(var) +
          Extensions_len(2) + Extensions(var)
        """
        try:
            offset = 0

            # Handshake type + length (4 bytes)
            # handshake_type = data[0]  # ya verificado como CLIENT_HELLO
            offset += 4

            # Legacy version (2 bytes) — siempre 0x0303 en TLS 1.2+
            # La versión real se negocia en supported_versions extension
            legacy_version = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            session_id_len = data[offset]
            offset += 1 + session_id_len

            # Cipher Suites
            cs_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            cipher_suites = []
            for i in range(0, cs_len, 2):
                cs = struct.unpack("!H", data[offset+i:offset+i+2])[0]
                if cs not in GREASE_VALUES:
                    cipher_suites.append(cs)
            offset += cs_len

            # Compression Methods
            comp_len = data[offset]
            offset += 1 + comp_len

            # Extensions
            if offset + 2 > len(data):
                # No hay extensions
                tls_version = TLS_VERSIONS.get(legacy_version, "12")
                return TLSClientHelloFeatures(
                    tls_version=tls_version,
                    cipher_suites=cipher_suites,
                    extensions=[],
                    has_sni=False,
                    alpn_protocols=[],
                    supported_groups=[],
                    signature_algorithms=[],
                )

            ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            extensions = []
            has_sni = False
            alpn_protocols = []
            supported_groups = []
            signature_algorithms = []
            negotiated_version = None

            while offset < ext_end:
                ext_type = struct.unpack("!H", data[offset:offset+2])[0]
                ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
                ext_data = data[offset+4:offset+4+ext_len]
                offset += 4 + ext_len

                if ext_type in GREASE_VALUES:
                    continue

                extensions.append(ext_type)

                # Parsear extensiones específicas
                if ext_type == 0:   # SNI
                    has_sni = True

                elif ext_type == 16:  # ALPN
                    alpn_protocols = self._parse_alpn(ext_data)

                elif ext_type == 10:  # Supported Groups (curves)
                    supported_groups = self._parse_uint16_list(ext_data, skip=2)
                    supported_groups = [g for g in supported_groups if g not in GREASE_VALUES]

                elif ext_type == 13:  # Signature Algorithms
                    signature_algorithms = self._parse_uint16_list(ext_data, skip=2)

                elif ext_type == 43:  # Supported Versions
                    # En TLS 1.3, la versión real está aquí
                    versions = self._parse_supported_versions(ext_data)
                    if versions:
                        # Tomamos la más alta soportada
                        for v in [0x0304, 0x0303, 0x0302]:
                            if v in versions:
                                negotiated_version = v
                                break

            tls_version = TLS_VERSIONS.get(
                negotiated_version or legacy_version, "12"
            )

            return TLSClientHelloFeatures(
                tls_version=tls_version,
                cipher_suites=cipher_suites,
                extensions=extensions,
                has_sni=has_sni,
                alpn_protocols=alpn_protocols,
                supported_groups=supported_groups,
                signature_algorithms=signature_algorithms,
            )

        except (IndexError, struct.error):
            return None

    def _parse_alpn(self, data: bytes) -> list[str]:
        """Parsea la extensión ALPN y retorna lista de protocolos."""
        protocols = []
        try:
            list_len = struct.unpack("!H", data[0:2])[0]
            offset = 2
            while offset < 2 + list_len:
                proto_len = data[offset]
                proto = data[offset+1:offset+1+proto_len].decode("ascii", errors="replace")
                protocols.append(proto)
                offset += 1 + proto_len
        except (IndexError, struct.error):
            pass
        return protocols

    def _parse_uint16_list(self, data: bytes, skip: int = 0) -> list[int]:
        """Parsea una lista de valores uint16 con offset inicial."""
        values = []
        try:
            offset = skip
            while offset + 1 < len(data):
                val = struct.unpack("!H", data[offset:offset+2])[0]
                values.append(val)
                offset += 2
        except struct.error:
            pass
        return values

    def _parse_supported_versions(self, data: bytes) -> list[int]:
        """Parsea la extensión supported_versions."""
        versions = []
        try:
            list_len = data[0]
            for i in range(1, 1 + list_len, 2):
                v = struct.unpack("!H", data[i:i+2])[0]
                if v not in GREASE_VALUES:
                    versions.append(v)
        except (IndexError, struct.error):
            pass
        return versions

    def _build_signal(self, features: TLSClientHelloFeatures) -> FingerprintSignal:
        """Construye FingerprintSignal desde los features TLS."""
        ja4 = JA4Fingerprint.build(features)

        # Confianza: JA4 es muy específico cuando hay muchas extensions
        base_confidence = min(0.4 + (len(features.extensions) * 0.03), 0.90)

        return FingerprintSignal(
            source="tls",
            raw_hash=ja4.full,
            metadata={
                "ja4": ja4.full,
                "ja4_a": ja4.ja4_a,
                "ja4_b": ja4.ja4_b,
                "ja4_c": ja4.ja4_c,
                "tls_version": features.tls_version,
                "cipher_suites": [f"{c:04x}" for c in features.cipher_suites],
                "extensions": features.extensions,
                "has_sni": features.has_sni,
                "alpn_protocols": features.alpn_protocols,
                "supported_groups": features.supported_groups,
            },
            confidence=base_confidence,
        )
