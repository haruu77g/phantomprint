"""
phantomprint/engine.py
Orquestador principal — coordina captura, parsers, correlación y output.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table

from phantomprint.parsers.tcp_ip import TCPIPParser
from phantomprint.parsers.tls_parser import TLSParser
from phantomprint.parsers.dhcp_parser import DHCPParser
from phantomprint.correlator.signal_merger import SignalMerger, FingerprintSignal
from phantomprint.signatures.db import SignatureDB
from phantomprint.output.terminal import TerminalRenderer
from phantomprint.output.json_out import JSONRenderer

console = Console()


class Engine:
    """
    Orquestador central de PHANTOMPRINT.

    Flujo:
      Paquete capturado
        → parsers (TCP/IP, TLS, DHCP, ...)
          → señal generada (FingerprintSignal)
            → SignalMerger (correlación + scoring)
              → HostProfile actualizado
                → Output (terminal / JSON / STIX)
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.db = SignatureDB()
        self.merger = SignalMerger(signature_db=self.db)
        self.renderer = TerminalRenderer(console=console, verbose=verbose)

        # Inicializar parsers
        self.tcp_parser = TCPIPParser()
        self.tls_parser = TLSParser()
        self.dhcp_parser = DHCPParser()

    def _process_packet(self, pkt) -> None:
        """
        Procesa un paquete individual a través de todos los parsers.
        Cada parser devuelve None si el paquete no es relevante para él.
        """
        signals: list[tuple[str, FingerprintSignal]] = []

        # Intentar extraer señal TCP/IP
        result = self.tcp_parser.parse(pkt)
        if result:
            signals.append(result)

        # Intentar extraer señal TLS
        result = self.tls_parser.parse(pkt)
        if result:
            signals.append(result)

        # Intentar extraer señal DHCP
        result = self.dhcp_parser.parse(pkt)
        if result:
            signals.append(result)

        # Ingerir señales en el correlador
        for ip, signal in signals:
            profile = self.merger.ingest_signal(ip=ip, signal=signal)
            self.renderer.update_profile(profile)

    def run_live(
        self,
        interface: str,
        timeout: Optional[int],
        output_json: Optional[Path],
    ) -> None:
        """Captura en vivo con Scapy."""
        try:
            from scapy.all import sniff
        except ImportError:
            console.print("[red]✗ Scapy not installed. Run: pip install scapy[/]")
            return

        console.print(f"[green]◈ Sniffing on {interface}... (Ctrl+C to stop)[/]\n")

        with Live(self.renderer.build_table(), refresh_per_second=2, console=console) as live:
            self.renderer.set_live(live)
            try:
                sniff(
                    iface=interface,
                    prn=self._process_packet,
                    store=False,
                    timeout=timeout,
                )
            except KeyboardInterrupt:
                pass

        self._finalize(output_json)

    def run_pcap(
        self,
        pcap_file: Path,
        output_json: Optional[Path],
    ) -> None:
        """Análisis offline de un archivo PCAP."""
        try:
            from scapy.all import rdpcap
        except ImportError:
            console.print("[red]✗ Scapy not installed. Run: pip install scapy[/]")
            return

        console.print(f"[green]◈ Loading {pcap_file}...[/]")
        packets = rdpcap(str(pcap_file))
        console.print(f"[green]◈ Processing {len(packets)} packets...[/]\n")

        for pkt in packets:
            self._process_packet(pkt)

        self.renderer.print_final_table(self.merger.get_all_profiles())
        self._finalize(output_json)

    def _finalize(self, output_json: Optional[Path]) -> None:
        """Post-captura: guardar JSON si se especificó."""
        profiles = self.merger.get_all_profiles()

        if output_json:
            renderer = JSONRenderer()
            renderer.save(profiles=profiles, path=output_json)
            console.print(f"\n[green]✓ Results saved to {output_json}[/]")

        console.print(f"\n[bold]◈ Summary:[/] {len(profiles)} hosts fingerprinted\n")
