import dns.resolver
from typing import List, Tuple, Optional
from output.logger import log

class NSEnumerator:
    def __init__(self, domain: str, resolver: dns.resolver.Resolver):
        self.domain = domain
        self.resolver = resolver

    def get_nameservers(self) -> List[str]:
        """Returns a list of Name Server IPs for the domain."""
        ns_ips = []
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            for rdata in answers:
                ns_target = rdata.target.to_text()
                # Resolve NS hostname to IP
                try:
                    ip_answers = self.resolver.resolve(ns_target, 'A')
                    for ip in ip_answers:
                        ns_ips.append(ip.to_text())
                except Exception:
                    continue
            log.info(f"[blue]*[/] Found {len(ns_ips)} Name Servers for {self.domain}")
        except Exception as e:
            log.warning(f"[yellow]![/] Could not enumerate NS: {e}")
        return list(set(ns_ips))

    def get_soa_serial(self, nameserver: str) -> Optional[int]:
        """Fetches current SOA Serial for IXFR."""
        try:
            request = dns.message.make_query(self.domain, dns.rdatatype.SOA)
            response = dns.query.udp(request, nameserver, timeout=5.0)
            if response.answer:
                return response.answer[0][0].serial
        except Exception:
            return None
        return None