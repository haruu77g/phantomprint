"""
phantomprint/signatures/db.py

Base de datos de firmas de fingerprinting.
SQLite en memoria + carga desde YAMLs en disco.

Cada firma mapea un hash de señal (TCP/IP, TLS, DHCP, etc.)
a un OS, browser o device conocido.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Optional

import yaml


# Firmas built-in — se cargan si no hay YAMLs externos
# Fuentes: p0f DB, Fingerbank, observación propia
BUILTIN_SIGNATURES = [
    # ─── OS: WINDOWS ───────────────────────────────────────────
    {
        "id": "os_win11",
        "name": "Windows 11",
        "type": "os",
        "description": "Windows 11 / Windows Server 2022",
        "signals": {
            "tcp_ip": [
                # TTL=128, window=65535, DF=1, mss+nop+wscale+sackok+timestamp
                "128:65535:1:mss,nop,wscale,sackok,timestamp",
                # Variante sin timestamp
                "128:65535:1:mss,nop,wscale,sackok",
                # Window 64240 (también común en W11)
                "128:64240:1:mss,nop,wscale,sackok,timestamp",
            ],
            "dhcp": [
                # Option 55 clásico de Windows 10/11
                "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
                # Variante Windows 11 build reciente
                "1,3,6,15,31,33,43,44,46,47,119,121,249,252,43",
            ],
        },
    },
    {
        "id": "os_win10",
        "name": "Windows 10",
        "type": "os",
        "description": "Windows 10 (cualquier build)",
        "signals": {
            "tcp_ip": [
                "128:65535:1:mss,nop,wscale,sackok,timestamp",
                "128:8192:1:mss,nop,wscale,sackok",
            ],
            "dhcp": [
                "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
            ],
        },
    },
    # ─── OS: LINUX ─────────────────────────────────────────────
    {
        "id": "os_linux6",
        "name": "Linux 6.x",
        "type": "os",
        "description": "Linux kernel 6.x (Ubuntu 22+, Fedora 37+, Debian 12+)",
        "signals": {
            "tcp_ip": [
                # TTL=64, window=64240, DF=1, opciones en orden Linux
                "64:64240:1:mss,sackok,timestamp,nop,wscale",
                "64:29200:1:mss,sackok,timestamp,nop,wscale",
                "64:65535:1:mss,sackok,timestamp,nop,wscale",
            ],
            "dhcp": [
                # dhclient (ISC DHCP client)
                "1,28,2,3,15,6,119,12,44,47,26,121,42",
                # systemd-networkd
                "1,3,6,12,15,17,18,22,23,28,29,30,31,33,40,41,42,119,121,249,252",
            ],
        },
    },
    {
        "id": "os_linux4_5",
        "name": "Linux 4.x/5.x",
        "type": "os",
        "description": "Linux kernel 4.x o 5.x",
        "signals": {
            "tcp_ip": [
                "64:64240:1:mss,sackok,timestamp,nop,wscale",
                "64:29200:0:mss,sackok,timestamp,nop,wscale",
            ],
        },
    },
    # ─── OS: MACOS ─────────────────────────────────────────────
    {
        "id": "os_macos_sonoma",
        "name": "macOS 14 Sonoma",
        "type": "os",
        "description": "macOS 14 Sonoma / macOS 13 Ventura",
        "signals": {
            "tcp_ip": [
                # macOS usa window=65535, TTL=64
                "64:65535:1:mss,nop,wscale,nop,nop,timestamp,sackok,eol",
                "64:65535:1:mss,nop,wscale,nop,nop,timestamp,sackok",
            ],
            "dhcp": [
                # macOS DHCP client
                "1,121,3,6,15,119,252,95,44,46",
                "1,121,3,6,15,119,252,95,44,46,47",
            ],
        },
    },
    # ─── OS: ANDROID ───────────────────────────────────────────
    {
        "id": "os_android12_14",
        "name": "Android 12-14",
        "type": "os",
        "description": "Android 12, 13 o 14",
        "signals": {
            "tcp_ip": [
                "64:65535:1:mss,sackok,timestamp,nop,wscale",
                "64:64240:1:mss,sackok,timestamp,nop,wscale",
            ],
            "dhcp": [
                "1,33,3,6,15,28,51,58,59",
                "1,33,3,6,28,51,58,59",
            ],
        },
    },
    # ─── OS: IOS ───────────────────────────────────────────────
    {
        "id": "os_ios16_17",
        "name": "iOS 16-17",
        "type": "os",
        "description": "iOS 16 o iOS 17 (iPhone/iPad)",
        "signals": {
            "tcp_ip": [
                "64:65535:1:mss,nop,wscale,nop,nop,timestamp,sackok,eol",
            ],
            "dhcp": [
                "1,121,3,6,15,119,252,95,44,46,47",
                "1,121,3,6,15,119,252,95,44,46",
            ],
        },
    },
    # ─── BROWSERS ──────────────────────────────────────────────
    # Los JA4 son hashes — aquí almacenamos los JA4 conocidos directamente
    {
        "id": "browser_chrome120",
        "name": "Chrome 120",
        "type": "browser",
        "description": "Google Chrome 120.x en cualquier plataforma",
        "signals": {
            # JA4 fingerprints de Chrome 120 (TLS 1.3)
            "tls": [
                "t13d1516h2_8daaf6152771_b1ff8ab37f4a",
                "t13d1516h2_8daaf6152771_02713d6af862",
            ],
        },
    },
    {
        "id": "browser_firefox121",
        "name": "Firefox 121",
        "type": "browser",
        "description": "Mozilla Firefox 121.x",
        "signals": {
            "tls": [
                "t13d1516h2_8daaf6152771_05b3ded8d5ab",
            ],
        },
    },
    {
        "id": "browser_safari17",
        "name": "Safari 17",
        "type": "browser",
        "description": "Apple Safari 17 (macOS/iOS)",
        "signals": {
            "tls": [
                "t13d1516h2_8daaf6152771_7a845c5b7e2a",
            ],
        },
    },
    {
        "id": "browser_curl",
        "name": "curl (libcurl)",
        "type": "browser",
        "description": "Herramienta curl / libcurl — indica acceso automatizado",
        "signals": {
            "tls": [
                "t13d1512h2_8daaf6152771_02713d6af862",
                "t13d1511h2_8daaf6152771_02713d6af862",
            ],
        },
    },
    # ─── DISPOSITIVOS IOT ──────────────────────────────────────
    {
        "id": "device_cisco_ios",
        "name": "Cisco IOS Router",
        "type": "device",
        "description": "Router Cisco con IOS",
        "signals": {
            "tcp_ip": [
                "255:4128:0:mss",
                "255:4128:1:mss",
            ],
        },
    },
    {
        "id": "device_raspberrypi",
        "name": "Raspberry Pi (Raspbian)",
        "type": "device",
        "description": "Raspberry Pi corriendo Raspbian/Raspberry Pi OS",
        "signals": {
            "tcp_ip": [
                "64:65535:1:mss,sackok,timestamp,nop,wscale",
            ],
            "dhcp": [
                "1,28,2,3,15,6,119,12,44,47,26,121,42",
            ],
        },
    },
]


class SignatureDB:
    """
    Base de datos de firmas de fingerprinting en SQLite (en memoria).
    
    Schema:
      signatures(id, name, type, description)
      signal_hashes(signature_id, source, raw_hash)
    
    Carga firmas desde:
    1. BUILTIN_SIGNATURES (siempre)
    2. YAMLs en signatures/raw/ (si existen)
    """

    def __init__(self, yaml_dir: Optional[Path] = None):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._load_builtin()

        if yaml_dir and yaml_dir.exists():
            self._load_from_yaml_dir(yaml_dir)

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE signatures (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                type        TEXT NOT NULL,  -- os | browser | device
                description TEXT
            );

            CREATE TABLE signal_hashes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_id    TEXT NOT NULL REFERENCES signatures(id),
                source          TEXT NOT NULL,   -- tcp_ip | tls | dhcp | dns | http2
                raw_hash        TEXT NOT NULL
            );

            CREATE INDEX idx_signal_lookup ON signal_hashes(source, raw_hash);
        """)

    def _hash_fp_string(self, source: str, fp_string: str) -> str:
        """
        Genera el raw_hash desde un fingerprint string legible.
        Mismo algoritmo que los parsers — permite matching.
        """
        return hashlib.sha256(fp_string.encode()).hexdigest()[:16]

    def _load_builtin(self) -> None:
        """Carga las firmas built-in en SQLite."""
        cur = self.conn.cursor()

        for sig in BUILTIN_SIGNATURES:
            cur.execute(
                "INSERT OR IGNORE INTO signatures VALUES (?, ?, ?, ?)",
                (sig["id"], sig["name"], sig["type"], sig["description"]),
            )

            for source, fp_strings in sig.get("signals", {}).items():
                for fp_string in fp_strings:
                    raw_hash = self._hash_fp_string(source, fp_string)
                    cur.execute(
                        "INSERT INTO signal_hashes (signature_id, source, raw_hash) VALUES (?, ?, ?)",
                        (sig["id"], source, raw_hash),
                    )

        self.conn.commit()

    def _load_from_yaml_dir(self, yaml_dir: Path) -> None:
        """Carga firmas adicionales desde archivos YAML."""
        cur = self.conn.cursor()

        for yaml_file in yaml_dir.rglob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    sig = yaml.safe_load(f)

                cur.execute(
                    "INSERT OR IGNORE INTO signatures VALUES (?, ?, ?, ?)",
                    (sig["id"], sig["name"], sig["type"], sig.get("description", "")),
                )

                for source, fp_strings in sig.get("signals", {}).items():
                    for fp_string in fp_strings:
                        raw_hash = self._hash_fp_string(source, fp_string)
                        cur.execute(
                            "INSERT OR IGNORE INTO signal_hashes (signature_id, source, raw_hash) VALUES (?, ?, ?)",
                            (sig["id"], source, raw_hash),
                        )
            except Exception as e:
                print(f"[WARN] Could not load signature {yaml_file}: {e}")

        self.conn.commit()

    def query_by_signal(self, source: str, raw_hash: str) -> list[dict]:
        """Busca firmas que matcheen una señal específica."""
        cur = self.conn.execute("""
            SELECT s.id, s.name, s.type, s.description
            FROM signatures s
            JOIN signal_hashes sh ON sh.signature_id = s.id
            WHERE sh.source = ? AND sh.raw_hash = ?
        """, (source, raw_hash))
        return [dict(row) for row in cur.fetchall()]

    def get_by_ids(self, ids: set[str]) -> list[dict]:
        """Hidrata candidatos por sus IDs."""
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        cur = self.conn.execute(
            f"SELECT id, name, type, description FROM signatures WHERE id IN ({placeholders})",
            list(ids),
        )
        return [dict(row) for row in cur.fetchall()]

    def list_all(self, category: Optional[str] = None) -> list[dict]:
        """Lista todas las firmas, opcionalmente filtradas por tipo."""
        if category:
            cur = self.conn.execute(
                "SELECT id, name, type, description FROM signatures WHERE type = ? ORDER BY type, name",
                (category,),
            )
        else:
            cur = self.conn.execute(
                "SELECT id, name, type, description FROM signatures ORDER BY type, name"
            )
        return [dict(row) for row in cur.fetchall()]

    def signature_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM signatures").fetchone()
        return row[0] if row else 0
