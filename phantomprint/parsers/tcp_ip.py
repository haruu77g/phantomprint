"""
phantomprint/parsers/tcp_ip.py

Parser de fingerprinting TCP/IP pasivo.

Analiza campos del stack de red que varían por implementación de OS:
  - TTL inicial (inferido desde el TTL observado)
  - TCP window size
  - TCP options y su orden
  - IP flags (DF bit)
  - TCP quirks (URG, ECN, etc.)

Referencias:
  - p0f3 fingerprint DB: https://github.com/p0f/p0f
  - RFC 793 (TCP), RFC 791 (IP)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from phantomprint.correlator.signal_merger import FingerprintSignal


# TTL inicial más probable dado el TTL observado.
# Los OS parten de valores canónicos (64, 128, 255).
# En tránsito, el TTL decrece 1 por hop.
TTL_INITIAL_CANDIDATES = {
    range(1, 65): 64,      # Linux, macOS, iOS, Android
    range(65, 129): 128,   # Windows
    range(129, 256): 255,  # Cisco IOS, routers, algunos BSD
}

# Opciones TCP conocidas y su representación en bytes
TCP_OPT_NAMES = {
    0: "eol",
    1: "nop",
    2: "mss",
    3: "wscale",
    4: "sackok",
    5: "sack",
    8: "timestamp",
    34: "tfo",       # TCP Fast Open
}


@dataclass
class TCPIPFeatures:
    """Campos extraídos de un SYN o SYN-ACK para fingerprinting."""
    ttl_observed: int
    ttl_initial: int          # Inferido desde ttl_observed
    window_size: int
    df_bit: bool              # Don't Fragment
    tcp_options: list[str]    # Orden de opciones TCP como strings
    mss: Optional[int]        # Max Segment Size
    wscale: Optional[int]     # Window Scale factor
    has_timestamp: bool
    has_sackok: bool
    ip_version: int           # 4 o 6


def infer_initial_ttl(observed_ttl: int) -> int:
    """
    Infiere el TTL inicial del OS basándose en el TTL que llega.
    
    Un paquete que salió con TTL=128 y llega con TTL=126 estuvo
    en 2 hops. Mapeamos al candidato más probable.
    """
    for ttl_range, initial in TTL_INITIAL_CANDIDATES.items():
        if observed_ttl in ttl_range:
            return initial
    return 64  # fallback conservador


def extract_tcp_options(pkt_tcp) -> tuple[list[str], Optional[int], Optional[int], bool, bool]:
    """
    Extrae y ordena las opciones TCP de un paquete.
    
    Retorna: (option_list, mss, wscale, has_timestamp, has_sackok)
    El ORDEN de las opciones es la firma clave — cada OS las incluye
    en un orden específico y consistente.
    """
    options = []
    mss = None
    wscale = None
    has_timestamp = False
    has_sackok = False

    try:
        for opt_name, opt_val in pkt_tcp.options:
            name = opt_name.lower() if isinstance(opt_name, str) else TCP_OPT_NAMES.get(opt_name, f"unknown_{opt_name}")
            options.append(name)

            if name == "mss" and opt_val:
                mss = opt_val
            elif name == "wscale" and opt_val is not None:
                wscale = opt_val
            elif name == "timestamp":
                has_timestamp = True
            elif name == "sackok":
                has_sackok = True
    except (AttributeError, TypeError):
        pass

    return options, mss, wscale, has_timestamp, has_sackok


class TCPIPParser:
    """
    Parser de fingerprinting pasivo sobre paquetes TCP SYN / SYN-ACK.
    
    Solo analiza el primer paquete de una conexión (SYN o SYN-ACK)
    porque es donde el OS expone su stack sin modificación por la app.
    
    Un SYN desde el cliente → fingerprinting del cliente
    Un SYN-ACK desde el servidor → fingerprinting del servidor
    """

    def parse(self, pkt) -> Optional[tuple[str, FingerprintSignal]]:
        """
        Analiza un paquete y retorna (ip, FingerprintSignal) si es relevante.
        Retorna None si el paquete no es un SYN o SYN-ACK TCP.
        """
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.inet6 import IPv6
        except ImportError:
            return None

        # Solo procesamos IP/TCP
        if not pkt.haslayer(TCP):
            return None

        tcp = pkt[TCP]
        flags = tcp.flags

        # Solo SYN (0x02) y SYN-ACK (0x12) — donde el OS habla sin filtros
        is_syn = flags == 0x02
        is_syn_ack = flags == 0x12

        if not (is_syn or is_syn_ack):
            return None

        # Extraer IP source (quien genera el SYN o SYN-ACK)
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            ttl = ip_layer.ttl
            df = bool(ip_layer.flags & 0x2)  # DF bit
            ip_version = 4
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            src_ip = ip_layer.src
            ttl = ip_layer.hlim  # Hop Limit en IPv6 ≈ TTL
            df = False           # IPv6 no tiene DF bit
            ip_version = 6
        else:
            return None

        # Extraer opciones TCP
        tcp_options, mss, wscale, has_timestamp, has_sackok = extract_tcp_options(tcp)

        features = TCPIPFeatures(
            ttl_observed=ttl,
            ttl_initial=infer_initial_ttl(ttl),
            window_size=tcp.window,
            df_bit=df,
            tcp_options=tcp_options,
            mss=mss,
            wscale=wscale,
            has_timestamp=has_timestamp,
            has_sackok=has_sackok,
            ip_version=ip_version,
        )

        signal = self._build_signal(features)
        return (src_ip, signal)

    def _build_signal(self, features: TCPIPFeatures) -> FingerprintSignal:
        """
        Construye la FingerprintSignal a partir de los features extraídos.
        
        El raw_hash es el fingerprint comparable contra la DB de firmas.
        Formato: ttl_initial:window:df:options_joined
        
        Ejemplo real de Windows 11:
          "128:65535:1:mss,nop,wscale,sackok,timestamp"
        
        Ejemplo real de Linux 6.x:
          "64:64240:1:mss,sackok,timestamp,nop,wscale"
        """
        options_str = ",".join(features.tcp_options) if features.tcp_options else "none"

        # Componentes del fingerprint TCP/IP
        fp_components = [
            str(features.ttl_initial),
            str(features.window_size),
            str(int(features.df_bit)),
            options_str,
        ]
        fp_string = ":".join(fp_components)

        # Hash para comparación eficiente contra la DB
        raw_hash = hashlib.sha256(fp_string.encode()).hexdigest()[:16]

        # Confianza base: más opciones TCP = más específico = más confianza
        base_confidence = min(0.3 + (len(features.tcp_options) * 0.08), 0.85)

        return FingerprintSignal(
            source="tcp_ip",
            raw_hash=raw_hash,
            metadata={
                "fp_string": fp_string,
                "ttl_observed": features.ttl_observed,
                "ttl_initial": features.ttl_initial,
                "window_size": features.window_size,
                "df_bit": features.df_bit,
                "tcp_options": features.tcp_options,
                "mss": features.mss,
                "wscale": features.wscale,
                "has_timestamp": features.has_timestamp,
                "has_sackok": features.has_sackok,
                "ip_version": features.ip_version,
            },
            confidence=base_confidence,
        )
