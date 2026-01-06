import dns.message
import dns.query
import dns.flags
from typing import List, Dict
from output.logger import log

class CacheSnooper:
    """
    Sends non-recursive queries (RD=0) to check if records exist in the NS cache.
    """
    def __init__(self, nameserver: str):
        self.nameserver = nameserver
        # Domains to check in the cache
        self.targets = [
            "google.com", "facebook.com", # General traffic
            "update.microsoft.com",       # Server patching
            "github.com",                 # Dev activity
            "pornhub.com",                # Policy violation
            "torproject.org"              # Security/Privacy usage
        ]

    def run(self) -> List[Dict[str, str]]:
        log.info(f"[cyan]➜[/] performing Cache Snooping on {self.nameserver}...")
        findings = []

        for target in self.targets:
            try:
                # Make query with Recursion Desired = 0
                query = dns.message.make_query(target, dns.rdatatype.A)
                query.flags &= ~dns.flags.RD 
                
                response = dns.query.udp(query, self.nameserver, timeout=3)
                
                # If we get an Answer without RD bit set, it's cached
                if len(response.answer) > 0:
                    msg = f"Cache HIT: {target} is in memory (TTL: {response.answer[0].ttl}s)"
                    log.warning(f"[yellow]![/] {msg}")
                    findings.append({"severity": "MEDIUM", "msg": msg})
            except Exception:
                pass
        
        return findings