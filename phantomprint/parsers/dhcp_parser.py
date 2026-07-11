"""
phantomprint/parsers/dhcp_parser.py

Parser de fingerprinting DHCP pasivo.

La Option 55 (Parameter Request List) es una de las señales pasivas
más precisas para identificar OS — cada implementación solicita
exactamente los mismos parámetros DHCP en el mismo orden.

Referencia: https://fingerbank.org/
  - Windows 10/11: 1,3,6,15,31,33,43,44,46,47,119,121,249,252
  - Linux (dhclient): 1,28,2,3,15,6,119,12,44,47,26,121,42
  - macOS: 1,121,3,6,15,119,252,95,44,46
  - Android: 1,33,3,6,15,28,51,58,59
  - iOS: 1,121,3,6,15,119,252,95,44,46,47

Nota: DHCP opera en broadcast (255.255.255.255), lo que lo hace
fácilmente capturable sin necesidad de estar en la ruta del tráfico.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from phantomprint.correlator.signal_merger import FingerprintSignal

# Nombres de opciones DHCP comunes
DHCP_OPT_NAMES = {
    1:   "subnet_mask",
    2:   "time_offset",
    3:   "router",
    4:   "time_server",
    6:   "dns",
    12:  "hostname",
    15:  "domain_name",
    17:  "root_path",
    19:  "ip_forwarding",
    23:  "default_ttl",
    26:  "mtu",
    28:  "broadcast",
    31:  "router_discovery",
    33:  "static_route",
    42:  "ntp_server",
    43:  "vendor_specific",
    44:  "netbios_ns",
    46:  "netbios_type",
    47:  "netbios_scope",
    51:  "lease_time",
    53:  "msg_type",
    55:  "param_request",
    57:  "max_msg_size",
    58:  "renewal_time",
    59:  "rebinding_time",
    60:  "vendor_class",
    61:  "client_id",
    81:  "fqdn",
    95:  "ldap",
    119: "domain_search",
    121: "classless_route",
    249: "ms_classless_route",
    252: "auto_proxy",
}

# Tipos de mensaje DHCP
DHCP_MSG_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


class DHCPParser:
    """
    Parser pasivo de paquetes DHCP.
    
    Captura DHCP DISCOVER y REQUEST — donde el cliente revela
    sus preferencias antes de tener configuración de red.
    
    El fingerprint DHCP es especialmente valioso porque:
    1. Es determinístico — siempre el mismo orden de opciones por OS
    2. Ocurre al inicio — cuando el dispositivo aparece en la red
    3. No está afectado por configuración del usuario
    """

    def parse(self, pkt) -> Optional[tuple[str, FingerprintSignal]]:
        """
        Retorna (mac_or_ip, FingerprintSignal) para DHCP DISCOVER/REQUEST.
        Usamos MAC address como identificador porque el host aún no tiene IP.
        """
        try:
            from scapy.layers.dhcp import DHCP, BOOTP
            from scapy.layers.l2 import Ether
        except ImportError:
            return None

        if not pkt.haslayer(DHCP):
            return None

        dhcp = pkt[DHCP]
        bootp = pkt[BOOTP] if pkt.haslayer(BOOTP) else None

        # Extraer tipo de mensaje DHCP
        msg_type = None
        param_request_list = []
        vendor_class = None
        hostname = None
        max_msg_size = None

        for opt in dhcp.options:
            if not isinstance(opt, tuple):
                continue
            
            opt_name, *opt_vals = opt
            opt_val = opt_vals[0] if opt_vals else None

            if opt_name == "message-type":
                msg_type = opt_val
            elif opt_name == "param_req_list":
                # Lista de opciones solicitadas — LA señal clave
                if isinstance(opt_val, (bytes, list)):
                    param_request_list = list(opt_val) if isinstance(opt_val, bytes) else opt_val
            elif opt_name == "vendor_class_id":
                if isinstance(opt_val, bytes):
                    vendor_class = opt_val.decode("ascii", errors="replace")
            elif opt_name == "hostname":
                if isinstance(opt_val, bytes):
                    hostname = opt_val.decode("ascii", errors="replace")
            elif opt_name == "max_dhcp_size":
                max_msg_size = opt_val

        # Solo nos interesan DISCOVER(1) y REQUEST(3)
        if msg_type not in (1, 3):
            return None

        # Sin Option 55, el fingerprint es inútil
        if not param_request_list:
            return None

        # Usar MAC como identificador (aún no tiene IP en DISCOVER)
        identifier = "unknown"
        if pkt.haslayer(Ether):
            identifier = pkt[Ether].src
        elif bootp and bootp.chaddr:
            # chaddr: 16 bytes, primeros 6 son MAC
            mac_bytes = bytes(bootp.chaddr)[:6]
            identifier = ":".join(f"{b:02x}" for b in mac_bytes)

        features = {
            "msg_type": DHCP_MSG_TYPES.get(msg_type, f"type_{msg_type}"),
            "param_request_list": param_request_list,
            "vendor_class": vendor_class,
            "hostname": hostname,
            "max_msg_size": max_msg_size,
        }

        signal = self._build_signal(features, param_request_list)
        return (identifier, signal)

    def _build_signal(
        self,
        features: dict,
        param_request_list: list[int],
    ) -> FingerprintSignal:
        """
        El fingerprint DHCP es simplemente la Option 55 como string.
        
        Ejemplos reales:
          Windows 11: "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
          Linux:      "1,28,2,3,15,6,119,12,44,47,26,121,42"
          macOS:      "1,121,3,6,15,119,252,95,44,46"
          iOS:        "1,121,3,6,15,119,252,95,44,46,47"
        
        El ORDEN importa — no ordenamos la lista.
        """
        option55_str = ",".join(str(o) for o in param_request_list)
        raw_hash = hashlib.sha256(option55_str.encode()).hexdigest()[:16]

        # Confianza base: más opciones = más específico
        base_confidence = min(0.35 + (len(param_request_list) * 0.04), 0.80)

        # Bonus de confianza si hay vendor_class (muy específico)
        if features.get("vendor_class"):
            base_confidence = min(base_confidence + 0.10, 0.90)

        return FingerprintSignal(
            source="dhcp",
            raw_hash=raw_hash,
            metadata={
                "option55": option55_str,
                "option55_named": [
                    DHCP_OPT_NAMES.get(o, str(o))
                    for o in param_request_list
                ],
                "vendor_class": features.get("vendor_class"),
                "hostname": features.get("hostname"),
                "msg_type": features.get("msg_type"),
                "param_count": len(param_request_list),
            },
            confidence=base_confidence,
        )
