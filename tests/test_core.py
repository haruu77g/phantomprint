"""
tests/test_core.py

Tests unitarios para parsers y correlador.
Usan Scapy para construir paquetes sintéticos — no requieren captura real.
"""

import hashlib
import pytest


# ─── Tests SignalMerger ────────────────────────────────────────────────────────

class TestSignalMerger:
    """Tests del motor de correlación y scoring."""

    def setup_method(self):
        from phantomprint.signatures.db import SignatureDB
        from phantomprint.correlator.signal_merger import SignalMerger, FingerprintSignal

        self.SignalMerger = SignalMerger
        self.FingerprintSignal = FingerprintSignal
        self.db = SignatureDB()
        self.merger = SignalMerger(signature_db=self.db)

    def test_empty_profile_has_zero_score(self):
        """Un host sin señales debe tener score 0."""
        from phantomprint.correlator.signal_merger import HostProfile
        profile = HostProfile(ip="10.0.0.1")
        assert profile.composite_score == 0.0

    def test_single_signal_creates_profile(self):
        """Ingerir una señal crea un perfil para el host."""
        signal = self.FingerprintSignal(
            source="tcp_ip",
            raw_hash="deadbeef12345678",
            metadata={"test": True},
            confidence=0.7,
        )
        profile = self.merger.ingest_signal("192.168.1.1", signal)
        assert profile.ip == "192.168.1.1"
        assert len(profile.signals) == 1
        assert profile.composite_score > 0.0

    def test_score_increases_with_more_signals(self):
        """Más señales deben resultar en score más alto."""
        signal1 = self.FingerprintSignal(
            source="tcp_ip",
            raw_hash="hash_tcp",
            metadata={},
            confidence=0.8,
        )
        profile1 = self.merger.ingest_signal("10.0.0.2", signal1)
        score_after_1 = profile1.composite_score

        signal2 = self.FingerprintSignal(
            source="tls",
            raw_hash="hash_tls",
            metadata={},
            confidence=0.9,
        )
        profile2 = self.merger.ingest_signal("10.0.0.2", signal2)
        score_after_2 = profile2.composite_score

        assert score_after_2 > score_after_1

    def test_same_source_signal_replaced(self):
        """Una señal del mismo tipo debe reemplazar la anterior."""
        signal_v1 = self.FingerprintSignal(
            source="tcp_ip", raw_hash="hash_v1", metadata={}, confidence=0.5
        )
        signal_v2 = self.FingerprintSignal(
            source="tcp_ip", raw_hash="hash_v2", metadata={}, confidence=0.8
        )
        self.merger.ingest_signal("10.0.0.3", signal_v1)
        profile = self.merger.ingest_signal("10.0.0.3", signal_v2)

        assert len(profile.signals) == 1
        assert profile.signals[0].raw_hash == "hash_v2"

    def test_composite_hash_is_deterministic(self):
        """El mismo set de señales siempre produce el mismo composite_hash."""
        signal = self.FingerprintSignal(
            source="tcp_ip", raw_hash="abc123", metadata={}, confidence=0.6
        )
        profile1 = self.merger.ingest_signal("10.0.0.4", signal)
        hash1 = profile1.composite_hash

        merger2 = self.SignalMerger(signature_db=self.db)
        profile2 = merger2.ingest_signal("10.0.0.4", signal)
        hash2 = profile2.composite_hash

        assert hash1 == hash2

    def test_score_ceiling_below_1(self):
        """El score nunca debe llegar a 1.0 con señales realistas."""
        for source in ["tcp_ip", "tls", "dhcp", "http2", "dns"]:
            signal = self.FingerprintSignal(
                source=source, raw_hash=f"hash_{source}", metadata={}, confidence=1.0
            )
            self.merger.ingest_signal("10.0.0.5", signal)

        profile = self.merger.get_profile("10.0.0.5")
        assert profile is not None
        assert profile.composite_score < 1.0
        assert profile.composite_score > 0.5


# ─── Tests SignatureDB ─────────────────────────────────────────────────────────

class TestSignatureDB:
    """Tests de la base de datos de firmas."""

    def setup_method(self):
        from phantomprint.signatures.db import SignatureDB
        self.db = SignatureDB()

    def test_builtin_signatures_loaded(self):
        """La DB debe cargar las firmas built-in al inicializarse."""
        count = self.db.signature_count()
        assert count >= 10  # Al menos los 10 OS/browsers que definimos

    def test_list_all_returns_all_types(self):
        """list_all debe retornar OS, browsers y devices."""
        all_sigs = self.db.list_all()
        types = {s["type"] for s in all_sigs}
        assert "os" in types
        assert "browser" in types
        assert "device" in types

    def test_list_filter_by_category(self):
        """Filtrar por categoría debe retornar solo ese tipo."""
        os_sigs = self.db.list_all(category="os")
        assert all(s["type"] == "os" for s in os_sigs)

        browser_sigs = self.db.list_all(category="browser")
        assert all(s["type"] == "browser" for s in browser_sigs)

    def test_query_by_signal_windows11_dhcp(self):
        """El fingerprint DHCP de Windows 11 debe matchear la firma correcta."""
        fp_string = "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
        raw_hash = hashlib.sha256(fp_string.encode()).hexdigest()[:16]

        matches = self.db.query_by_signal(source="dhcp", raw_hash=raw_hash)
        names = [m["name"] for m in matches]
        assert any("Windows" in n for n in names), f"Expected Windows match, got: {names}"

    def test_query_by_signal_linux_dhcp(self):
        """El fingerprint DHCP de Linux debe matchear Linux."""
        fp_string = "1,28,2,3,15,6,119,12,44,47,26,121,42"
        raw_hash = hashlib.sha256(fp_string.encode()).hexdigest()[:16]

        matches = self.db.query_by_signal(source="dhcp", raw_hash=raw_hash)
        names = [m["name"] for m in matches]
        assert any("Linux" in n for n in names), f"Expected Linux match, got: {names}"

    def test_query_unknown_hash_returns_empty(self):
        """Un hash desconocido debe retornar lista vacía, no error."""
        matches = self.db.query_by_signal(source="tcp_ip", raw_hash="nonexistenthash")
        assert matches == []


# ─── Tests TCP/IP Parser ───────────────────────────────────────────────────────

class TestTCPIPParser:
    """Tests del parser TCP/IP."""

    def setup_method(self):
        from phantomprint.parsers.tcp_ip import TCPIPParser, infer_initial_ttl
        self.parser = TCPIPParser()
        self.infer_initial_ttl = infer_initial_ttl

    def test_infer_ttl_linux(self):
        """TTL 63 debe inferir TTL inicial 64 (Linux)."""
        assert self.infer_initial_ttl(63) == 64
        assert self.infer_initial_ttl(64) == 64
        assert self.infer_initial_ttl(1) == 64

    def test_infer_ttl_windows(self):
        """TTL 126 debe inferir TTL inicial 128 (Windows)."""
        assert self.infer_initial_ttl(128) == 128
        assert self.infer_initial_ttl(100) == 128
        assert self.infer_initial_ttl(65) == 128

    def test_infer_ttl_cisco(self):
        """TTL 255 debe inferir TTL inicial 255 (Cisco/BSD)."""
        assert self.infer_initial_ttl(255) == 255
        assert self.infer_initial_ttl(200) == 255

    def test_non_tcp_packet_returns_none(self):
        """Paquetes no-TCP deben retornar None."""
        try:
            from scapy.layers.inet import IP, UDP
            pkt = IP(dst="1.1.1.1") / UDP(dport=53)
            result = self.parser.parse(pkt)
            assert result is None
        except ImportError:
            pytest.skip("Scapy not installed")

    def test_syn_packet_produces_signal(self):
        """Un SYN TCP debe producir una señal TCP/IP."""
        try:
            from scapy.layers.inet import IP, TCP
            pkt = IP(src="192.168.1.100", dst="10.0.0.1", ttl=64) / \
                  TCP(sport=54321, dport=443, flags="S",
                      window=64240,
                      options=[
                          ("MSS", 1460),
                          ("SAckOK", b""),
                          ("Timestamp", (100, 0)),
                          ("NOP", None),
                          ("WScale", 7),
                      ])
            result = self.parser.parse(pkt)
            assert result is not None
            ip, signal = result
            assert ip == "192.168.1.100"
            assert signal.source == "tcp_ip"
            assert signal.confidence > 0.0
        except ImportError:
            pytest.skip("Scapy not installed")

    def test_non_syn_packet_returns_none(self):
        """Un ACK TCP (no SYN) debe retornar None."""
        try:
            from scapy.layers.inet import IP, TCP
            pkt = IP(src="10.0.0.1", dst="192.168.1.1", ttl=64) / \
                  TCP(sport=80, dport=54321, flags="A", window=65535)
            result = self.parser.parse(pkt)
            assert result is None
        except ImportError:
            pytest.skip("Scapy not installed")


# ─── Tests JA4 Fingerprint ────────────────────────────────────────────────────

class TestJA4:
    """Tests del fingerprint JA4."""

    def test_ja4_format_correct(self):
        """El JA4 debe tener el formato correcto: XXXXX_XXXXXXXXXXXX_XXXXXXXXXXXX"""
        from phantomprint.parsers.tls_parser import JA4Fingerprint, TLSClientHelloFeatures

        features = TLSClientHelloFeatures(
            tls_version="13",
            cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c],
            extensions=[0, 10, 11, 13, 16, 23, 43, 51],
            has_sni=True,
            alpn_protocols=["h2", "http/1.1"],
            supported_groups=[0x001d, 0x0017, 0x0018],
            signature_algorithms=[0x0403, 0x0804, 0x0401],
        )
        ja4 = JA4Fingerprint.build(features)

        parts = ja4.full.split("_")
        assert len(parts) == 3, f"JA4 debe tener 3 partes: {ja4.full}"
        assert len(parts[1]) == 12
        assert len(parts[2]) == 12

    def test_ja4_sni_flag(self):
        """El flag SNI en JA4_a debe ser 'd' cuando hay SNI, 'i' cuando no."""
        from phantomprint.parsers.tls_parser import JA4Fingerprint, TLSClientHelloFeatures

        base = TLSClientHelloFeatures(
            tls_version="13", cipher_suites=[0x1301], extensions=[],
            has_sni=False, alpn_protocols=[], supported_groups=[], signature_algorithms=[]
        )
        ja4_no_sni = JA4Fingerprint.build(base)
        assert "i" in ja4_no_sni.ja4_a

        base.has_sni = True
        ja4_with_sni = JA4Fingerprint.build(base)
        assert "d" in ja4_with_sni.ja4_a

    def test_grease_filtered(self):
        """Los valores GREASE deben ser excluidos del fingerprint."""
        from phantomprint.parsers.tls_parser import JA4Fingerprint, TLSClientHelloFeatures, GREASE_VALUES

        grease_val = 0x0a0a
        features = TLSClientHelloFeatures(
            tls_version="13",
            cipher_suites=[grease_val, 0x1301, 0x1302],  # GREASE + 2 reales
            extensions=[grease_val, 10, 13],              # GREASE + 2 reales
            has_sni=True, alpn_protocols=[], supported_groups=[], signature_algorithms=[]
        )
        ja4 = JA4Fingerprint.build(features)

        # El count de ciphers en ja4_a debe ser 2, no 3
        # Formato: t13d02XX — posición 4-5 es cipher count
        cipher_count = int(ja4.ja4_a[4:6])
        assert cipher_count == 2, f"GREASE debería excluirse, count={cipher_count}"
