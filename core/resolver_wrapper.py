import socks
import socket
import dns.resolver
from output.logger import log

class ResolverWrapper:
    def __init__(self, proxy: str = None):
        self.proxy = proxy
        self.resolver = dns.resolver.Resolver()
        self._configure_proxy()

    def _configure_proxy(self):
        """Routes DNS traffic through SOCKS5 if configured."""
        if self.proxy:
            try:
                host, port = self.proxy.split(":")
                socks.set_default_proxy(socks.SOCKS5, host, int(port))
                socket.socket = socks.socksocket
                log.info(f"[bold green]✓[/] Proxy enabled: Routing via {self.proxy}")
            except ValueError:
                log.error("[bold red]![/] Invalid proxy format. Use IP:PORT")
        
        # Optimize resolver
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    def get_resolver(self) -> dns.resolver.Resolver:
        return self.resolver