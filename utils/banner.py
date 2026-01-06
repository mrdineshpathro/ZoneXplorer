from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import DOUBLE_EDGE

console = Console()

def show_banner():
    # 1. ASCII Art Title
    ascii_art = """
    ███████╗ ██████╗ ███╗   ██╗███████╗
    ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝
      ███╔╝ ██║   ██║██╔██╗ ██║█████╗  
     ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  
    ███████╗╚██████╔╝██║ ╚████║███████╗
    ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
      [ X P L O R E R   E L I T E ]
    """
    
    # 2. Social Media Links
    social_text = Text()
    social_text.append("\nJOIN THE COMMUNITY\n", style="bold underline white")
    social_text.append(" 𝕏  Twitter  : ", style="bold cyan")
    social_text.append("https://x.com/TheExploitLab\n", style="blue link https://x.com/TheExploitLab")
    social_text.append(" ✈  Telegram : ", style="bold blue")
    social_text.append("https://t.me/TheExploitLabX\n", style="blue link https://t.me/TheExploitLabX")
    social_text.append(" ▶  YouTube  : ", style="bold red")
    social_text.append("https://youtube.com/@theexploitlab\n", style="blue link https://youtube.com/@theexploitlab")
    social_text.append(" 👾 Discord  : ", style="bold purple")
    social_text.append("https://discord.com/invite/FDBFxGyFDy", style="blue link https://discord.com/invite/FDBFxGyFDy")

    # 3. Create Panels
    art_panel = Panel(
        Align.center(ascii_art, vertical="middle"),
        border_style="bright_cyan",
        box=DOUBLE_EDGE,
        title="[bold green]v4.0 Ultimate[/]",
        subtitle="[italic grey70]Advanced DNS Recon Framework[/]"
    )

    info_panel = Panel(
        Align.center(social_text),
        border_style="magenta",
        title="[bold white]Connect[/]",
        padding=(1, 2)
    )

    console.print(art_panel)
    console.print(info_panel)
    console.print("\n")