import aiohttp
import asyncio
from typing import List, Dict, Any
from output.logger import log

class CloudHunter:
    """
    Checks CNAMEs against known cloud provider signatures for potential takeovers.
    """
    SIGNATURES = {
        "s3.amazonaws.com": {"code": 404, "content": "NoSuchBucket"},
        "blob.core.windows.net": {"code": 404, "content": "ResourceNotFound"},
        "googleapis.com": {"code": 404, "content": "NoSuchBucket"},
        "github.io": {"code": 404, "content": "There isn't a GitHub Pages site here"}
    }

    def __init__(self, records: List[Dict[str, Any]]):
        self.records = records
        self.vulns = []

    async def check(self) -> List[Dict[str, str]]:
        log.info("[cyan]➜[/] Hunting for Cloud Buckets & Takeovers...")
        
        tasks = []
        for rec in self.records:
            if rec['type'] == 'CNAME':
                target = rec['value'].rstrip('.')
                for provider, sig in self.SIGNATURES.items():
                    if provider in target:
                        tasks.append(self._verify_takeover(rec['name'], target, sig))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        return self.vulns

    async def _verify_takeover(self, subdomain: str, cname: str, signature: dict):
        # We try to access the subdomain via HTTP
        url = f"http://{subdomain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    text = await resp.text()
                    # Check if the error code matches an unclaimed bucket
                    if resp.status == signature['code'] and signature['content'] in text:
                        msg = f"CONFIRMED TAKEOVER: {subdomain} -> {cname}"
                        log.error(f"[bold red blink]!!![/] {msg}")
                        self.vulns.append({"severity": "CRITICAL", "msg": msg})
        except Exception:
            pass # Connection errors are expected for some dead CNAMEs