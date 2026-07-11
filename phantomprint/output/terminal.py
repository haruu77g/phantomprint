"""
phantomprint/output/terminal.py

Renderer de output para terminal usando Rich.
Muestra una tabla live que se actualiza en tiempo real
durante la captura, y una tabla final al terminar.
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.live import Live

if TYPE_CHECKING:
    from phantomprint.correlator.signal_merger import HostProfile


def score_to_color(score: float) -> str:
    """Colorea el score de confianza según su valor."""
    if score >= 0.70:
        return "bold green"
    elif score >= 0.40:
        return "yellow"
    elif score >= 0.20:
        return "orange1"
    else:
        return "red"


def signals_to_badges(sources: list[str]) -> str:
    """Convierte lista de fuentes de señales a badges compactos."""
    badge_map = {
        "tcp_ip": "[dim cyan]TCP[/]",
        "tls":    "[dim blue]TLS[/]",
        "dhcp":   "[dim magenta]DHCP[/]",
        "http2":  "[dim yellow]H2[/]",
        "dns":    "[dim green]DNS[/]",
    }
    return " ".join(badge_map.get(s, s) for s in sources)


class TerminalRenderer:
    """
    Renderiza perfiles de host en la terminal usando Rich.
    
    Dos modos:
    - Live: tabla que se actualiza en tiempo real (durante captura)
    - Final: tabla estática completa al terminar
    """

    def __init__(self, console: Console, verbose: bool = False):
        self.console = console
        self.verbose = verbose
        self._live: Optional[Live] = None
        self._profiles: dict[str, "HostProfile"] = {}

    def set_live(self, live: Live) -> None:
        self._live = live

    def update_profile(self, profile: "HostProfile") -> None:
        """Actualiza un perfil y refresca la tabla live si está activa."""
        self._profiles[profile.ip] = profile
        if self._live:
            self._live.update(self.build_table())

    def build_table(self) -> Table:
        """Construye la tabla Rich con el estado actual de todos los perfiles."""
        table = Table(
            title="[bold red]◈ PHANTOMPRINT[/] — Live Fingerprinting",
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=True,
        )

        table.add_column("Host / MAC", style="cyan", min_width=17)
        table.add_column("OS", min_width=20)
        table.add_column("Browser / App", min_width=18)
        table.add_column("Signals", min_width=20)
        table.add_column("Score", justify="right", min_width=8)
        table.add_column("Hash", style="dim", min_width=18)

        for profile in sorted(self._profiles.values(), key=lambda p: p.composite_score, reverse=True):
            os_name = profile.best_os().name if profile.best_os() else "[dim]unknown[/]"
            browser_name = profile.best_browser().name if profile.best_browser() else "[dim]—[/]"

            score = profile.composite_score
            score_text = Text(f"{score:.0%}", style=score_to_color(score))

            table.add_row(
                profile.ip,
                os_name,
                browser_name,
                signals_to_badges(profile.signal_sources()),
                score_text,
                profile.composite_hash[:16] if profile.composite_hash else "—",
            )

        return table

    def print_final_table(self, profiles: list["HostProfile"]) -> None:
        """Imprime la tabla final con todos los perfiles encontrados."""
        if not profiles:
            self.console.print("[yellow]◈ No hosts fingerprinted.[/]")
            return

        table = Table(
            title=f"[bold red]◈ PHANTOMPRINT[/] — Results ({len(profiles)} hosts)",
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=True,
        )

        table.add_column("Host / MAC", style="cyan", min_width=17)
        table.add_column("OS", min_width=22)
        table.add_column("Browser / App", min_width=18)
        table.add_column("Signals", min_width=24)
        table.add_column("Score", justify="right", min_width=8)

        for profile in sorted(profiles, key=lambda p: p.composite_score, reverse=True):
            os_name = profile.best_os().name if profile.best_os() else "unknown"
            browser_name = profile.best_browser().name if profile.best_browser() else "—"

            score = profile.composite_score
            score_text = Text(f"{score:.0%}", style=score_to_color(score))

            table.add_row(
                profile.ip,
                os_name,
                browser_name,
                signals_to_badges(profile.signal_sources()),
                score_text,
            )

            # En modo verbose, mostrar señales detalladas
            if self.verbose:
                for sig in profile.signals:
                    self.console.print(
                        f"  [dim]└── {sig.source}: {sig.raw_hash} "
                        f"(confidence: {sig.confidence:.0%})[/]"
                    )

        self.console.print(table)
