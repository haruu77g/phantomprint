"""
phantomprint/cli.py
CLI principal — entrada al engine desde la terminal.
"""

import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich import print as rprint

app = typer.Typer(
    name="phantomprint",
    help="[bold red]PHANTOMPRINT[/] — Passive fingerprinting without sending a single packet.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()


@app.command("live")
def live_capture(
    interface: str = typer.Option(..., "-i", "--interface", help="Network interface to capture on (e.g. eth0)"),
    timeout: Optional[int] = typer.Option(None, "-t", "--timeout", help="Stop after N seconds (default: run forever)"),
    output_json: Optional[Path] = typer.Option(None, "-o", "--output", help="Save results to JSON file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show raw signal details"),
):
    """
    Capture live traffic on a network interface and fingerprint hosts passively.
    Requires root/CAP_NET_RAW privileges.
    """
    from phantomprint.engine import Engine

    console.print(f"\n[bold red]◈ PHANTOMPRINT v0.1.0[/] — Live Capture Mode")
    console.print(f"  Interface : [cyan]{interface}[/]")
    console.print(f"  Timeout   : [cyan]{timeout or 'unlimited'}[/]")
    console.print(f"  Output    : [cyan]{output_json or 'terminal only'}[/]\n")

    engine = Engine(verbose=verbose)
    engine.run_live(interface=interface, timeout=timeout, output_json=output_json)


@app.command("pcap")
def analyze_pcap(
    pcap_file: Path = typer.Argument(..., help="Path to .pcap or .pcapng file"),
    output_json: Optional[Path] = typer.Option(None, "-o", "--output", help="Save results to JSON file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show raw signal details"),
):
    """
    Analyze a PCAP file offline and fingerprint all hosts found.
    No network access required — fully offline analysis.
    """
    from phantomprint.engine import Engine

    if not pcap_file.exists():
        console.print(f"[red]✗ File not found: {pcap_file}[/]")
        raise typer.Exit(1)

    console.print(f"\n[bold red]◈ PHANTOMPRINT v0.1.0[/] — PCAP Analysis Mode")
    console.print(f"  File   : [cyan]{pcap_file}[/]")
    console.print(f"  Output : [cyan]{output_json or 'terminal only'}[/]\n")

    engine = Engine(verbose=verbose)
    engine.run_pcap(pcap_file=pcap_file, output_json=output_json)


@app.command("signatures")
def list_signatures(
    category: Optional[str] = typer.Option(None, "-c", "--category", help="Filter by: os | browser | device"),
):
    """
    List all fingerprint signatures loaded in the database.
    """
    from phantomprint.signatures.db import SignatureDB

    db = SignatureDB()
    sigs = db.list_all(category=category)

    console.print(f"\n[bold]Loaded signatures:[/] {len(sigs)}\n")
    for sig in sigs:
        console.print(f"  [{sig['type'].upper()}] [cyan]{sig['name']}[/] — {sig['description']}")
    console.print()


def main():
    app()


if __name__ == "__main__":
    main()
