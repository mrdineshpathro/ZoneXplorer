import argparse
import sys
import asyncio
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Import Modules
from utils.banner import show_banner
from output.logger import setup_logger, log
from core.resolver_wrapper import ResolverWrapper
from core.enumerator import NSEnumerator
from core.strategies import AXFRStrategy, IXFRStrategy, NSECWalkStrategy
from core.snooper import CacheSnooper
from recon.passive import CertificateTransparency
from recon.cloud import CloudHunter
from analysis.intel import IntelAnalyzer
from analysis.visualizer import TopologyVisualizer
from output.exporter import Exporter

console = Console()

class ScanContext:
    def __init__(self):
        self.found_records = []
        self.vulns = []
        self.nameservers = []
        self.status_msg = "Initializing..."

def generate_layout(ctx: ScanContext) -> Layout:
    """Generates the Dashboard UI"""
    layout = Layout()
    layout.split_column(
        Layout(name="upper", size=3),
        Layout(name="middle"),
        Layout(name="lower", size=10)
    )

    # Header
    layout["upper"].update(Panel(f"[bold cyan]Target Domain: {ctx.domain if hasattr(ctx, 'domain') else '...'} [/] | [bold yellow]Status: {ctx.status_msg}[/]", border_style="blue"))

    # Stats Table
    stats_table = Table(show_header=True, header_style="bold magenta", expand=True)
    stats_table.add_column("Metric", style="white")
    stats_table.add_column("Count", style="green")
    
    stats_table.add_row("Name Servers Found", str(len(ctx.nameservers)))
    stats_table.add_row("Total Records", str(len(ctx.found_records)))
    stats_table.add_row("Vulnerabilities", f"[red]{len(ctx.vulns)}[/]")

    layout["middle"].update(Panel(stats_table, title="Live Statistics", border_style="green"))

    # Recent Findings (Tail)
    log_text = ""
    if ctx.found_records:
        recent = ctx.found_records[-5:]
        for r in recent:
            log_text += f"[grey70]{r['type']} -> {r['name']}[/]\n"
    
    layout["lower"].update(Panel(log_text, title="Recent Findings", border_style="white"))
    
    return layout

async def run_scan(args):
    # Setup
    show_banner()
    ctx = ScanContext()
    ctx.domain = args.domain
    setup_logger("ERROR") # Silence standard logs to keep Dashboard clean
    
    # Resolver
    resolver_wrapper = ResolverWrapper(args.proxy)
    resolver = resolver_wrapper.get_resolver()

    with Live(generate_layout(ctx), refresh_per_second=4, console=console) as live:
        
        # 1. Passive Recon
        if args.passive:
            ctx.status_msg = "Running Passive OSINT (crt.sh)..."
            live.update(generate_layout(ctx))
            ct = CertificateTransparency(args.domain)
            ct_subs = await ct.run()
            for sub in ct_subs:
                ctx.found_records.append({"name": sub, "type": "OSINT", "value": "crt.sh"})
            await asyncio.sleep(0.5)

        # 2. Enumeration
        ctx.status_msg = "Enumerating Name Servers..."
        live.update(generate_layout(ctx))
        enumerator = NSEnumerator(args.domain, resolver)
        ctx.nameservers = enumerator.get_nameservers()
        
        if not ctx.nameservers:
            ctx.status_msg = "[Red]Failed: No NS Found[/]"
            return

        # 3. Active Attacks
        ctx.status_msg = "Engaging Active Strategies (AXFR/IXFR/NSEC)..."
        live.update(generate_layout(ctx))

        zone_records = []
        snoop_findings = []

        for ns in ctx.nameservers:
            ctx.status_msg = f"Attacking Name Server: {ns}"
            live.update(generate_layout(ctx))
            
            # Snooping
            if args.snoop:
                snooper = CacheSnooper(ns)
                findings = snooper.run()
                for f in findings:
                    ctx.vulns.append(f)
                    snoop_findings.append(f)

            # Strategies
            axfr = AXFRStrategy()
            records = axfr.execute(args.domain, ns)
            
            if not records:
                serial = enumerator.get_soa_serial(ns)
                if serial:
                    ixfr = IXFRStrategy(serial)
                    records = ixfr.execute(args.domain, ns)
            
            if not records and args.walk:
                walker = NSECWalkStrategy()
                records = walker.execute(args.domain, ns)

            if records:
                zone_records.extend(records)
                ctx.found_records.extend(records)
                # Quick flash of success
                ctx.status_msg = f"[Green]Zone Dumped from {ns}![/]"
                live.update(generate_layout(ctx))
                await asyncio.sleep(1)
                break 

        # 4. Analysis
        ctx.status_msg = "Running Post-Exploitation Analysis..."
        live.update(generate_layout(ctx))

        # Deduplicate
        unique = [dict(t) for t in {tuple(d.items()) for d in ctx.found_records}]
        ctx.found_records = unique

        # Cloud Hunt
        if args.cloud:
            ctx.status_msg = "Hunting for Subdomain Takeovers..."
            live.update(generate_layout(ctx))
            hunter = CloudHunter(unique)
            cloud_vulns = await hunter.check()
            ctx.vulns.extend(cloud_vulns)

        # Intel
        analyzer = IntelAnalyzer(unique)
        intel_vulns = analyzer.run()
        ctx.vulns.extend(intel_vulns)

        ctx.status_msg = "Finalizing Report..."
        live.update(generate_layout(ctx))
        await asyncio.sleep(1)

    # --- End Live Mode, Print Final Summary ---
    
    console.print("\n[bold green]SCAN COMPLETE[/]")
    
    # 1. Scorecard
    if ctx.vulns:
        table = Table(title="[bold red]VULNERABILITY REPORT[/]", show_lines=True)
        table.add_column("Severity", style="bold red")
        table.add_column("Details", style="white")
        for v in ctx.vulns:
            color = "red" if v['severity'] in ["CRITICAL", "HIGH"] else "yellow"
            table.add_row(f"[{color}]{v['severity']}[/{color}]", v['msg'])
        console.print(table)
    else:
        console.print(Panel("[green]System Clean: No obvious vulnerabilities found.[/]", title="Security Status"))

    # 2. Export
    exporter = Exporter(args.output, args.domain)
    exporter.to_json(ctx.found_records)
    exporter.to_csv(ctx.found_records)

    # 3. Graph
    if args.graph and ctx.found_records:
        viz = TopologyVisualizer(ctx.found_records, args.domain)
        viz.generate(f"{args.output}/{args.domain}.dot")

def main():
    parser = argparse.ArgumentParser(description="ZoneXplorer v4 Ultimate")
    parser.add_argument("-d", "--domain", required=True, help="Target Domain")
    parser.add_argument("-o", "--output", default="results", help="Output Folder")
    parser.add_argument("--proxy", help="SOCKS5 (IP:PORT)")
    
    # Features
    parser.add_argument("--passive", action="store_true", help="OSINT via CRT.sh")
    parser.add_argument("--walk", action="store_true", help="NSEC Walking")
    parser.add_argument("--snoop", action="store_true", help="DNS Cache Snooping")
    parser.add_argument("--cloud", action="store_true", help="Cloud Takeover Hunt")
    parser.add_argument("--graph", action="store_true", help="Generate Network Graph")
    parser.add_argument("--all", action="store_true", help="Enable ALL features")

    args = parser.parse_args()
    
    # Helper for lazy hackers
    if args.all:
        args.passive = args.walk = args.snoop = args.cloud = args.graph = True

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        console.print("[bold red]\nScan Aborted by User[/]")

if __name__ == "__main__":
    main()