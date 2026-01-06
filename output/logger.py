import logging
from rich.console import Console
from rich.logging import RichHandler

console = Console()

def setup_logger(level: str = "INFO"):
    """Configures the global logger with Rich formatting."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)]
    )
    return logging.getLogger("ZoneXplorer")

log = logging.getLogger("ZoneXplorer")