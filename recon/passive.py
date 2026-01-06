import aiohttp
import asyncio
from typing import List
from output.logger import log

class CertificateTransparency:
    def __init__(self, domain: str):
        self.domain = domain
        self.url = f"https://crt.sh/?q=%.{domain}&output=json"

    async def run(self) -> List[str]:
        log.info(f"[cyan]➜[/] Querying CT Logs (crt.sh) for {self.domain}...")
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry['name_value']
                            # Handle multi-line entries
                            for sub in name_value.split('\n'):
                                if "*" not in sub: # Ignore wildcards
                                    subdomains.add(sub)
                        log.info(f"[bold green]✓[/] CT Logs found {len(subdomains)} unique subdomains.")
                    else:
                        log.warning(f"[yellow]![/] CT Log query failed: {response.status}")
        except Exception as e:
            log.warning(f"[yellow]![/] CT Log error: {e}")
            
        return list(subdomains)