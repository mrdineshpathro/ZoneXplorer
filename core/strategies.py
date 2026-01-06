import dns.query
import dns.zone
import dns.xfr
import dns.rdatatype
import dns.name
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from output.logger import log
from utils.jitter import Jitter

class AttackStrategy(ABC):
    @abstractmethod
    def execute(self, domain: str, nameserver: str) -> List[Dict[str, Any]]:
        pass

class AXFRStrategy(AttackStrategy):
    def execute(self, domain: str, nameserver: str) -> List[Dict[str, Any]]:
        Jitter.wait()
        results = []
        try:
            log.info(f"[cyan]➜[/] Attempting AXFR on {nameserver}...")
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, lifetime=10.0))
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    results.append({
                        "name": str(name) + "." + domain,
                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                        "value": str(rdataset[0])
                    })
            log.info(f"[bold green]✓[/] AXFR Successful! retrieved {len(results)} records.")
        except Exception as e:
            log.debug(f"AXFR failed on {nameserver}: {e}")
        return results

class IXFRStrategy(AttackStrategy):
    def __init__(self, current_serial: int):
        self.serial = current_serial

    def execute(self, domain: str, nameserver: str) -> List[Dict[str, Any]]:
        Jitter.wait()
        results = []
        if not self.serial:
            return []
            
        try:
            log.info(f"[cyan]➜[/] Attempting IXFR on {nameserver} (Serial: {self.serial})...")
            # Note: dnspython xfr handles IXFR if serial is provided
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, rdtype=dns.rdatatype.IXFR, serial=self.serial, lifetime=10.0))
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    results.append({
                        "name": str(name) + "." + domain,
                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                        "value": str(rdataset[0])
                    })
            log.info(f"[bold green]✓[/] IXFR Successful!")
        except Exception as e:
            log.debug(f"IXFR failed on {nameserver}: {e}")
        return results

class NSECWalkStrategy(AttackStrategy):
    def execute(self, domain: str, nameserver: str) -> List[Dict[str, Any]]:
        log.info(f"[cyan]➜[/] Attempting NSEC Zone Walking on {nameserver}...")
        found_subdomains = set()
        current_name = domain # Start at root
        
        # Safety break to prevent infinite loops
        max_hops = 100 
        hops = 0

        try:
            while hops < max_hops:
                Jitter.wait()
                hops += 1
                
                # Query for a non-existent name to trigger NSEC
                # We append a garbage label to the current known name
                query_name = f"00-nonexistent.{current_name}" if current_name == domain else current_name
                
                request = dns.message.make_query(query_name, dns.rdatatype.A, use_edns=0, payload=4096)
                request.flags |= dns.flags.DO # DNSSEC OK
                
                response = dns.query.udp(request, nameserver, timeout=4.0)
                
                # Look in Authority section for NSEC
                nsec_found = False
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        nsec_record = rrset[0]
                        next_name = nsec_record.next.to_text()
                        
                        # Check if we wrapped around or found new
                        if next_name in found_subdomains or next_name == domain:
                            return self._format_results(found_subdomains, domain)
                        
                        found_subdomains.add(next_name)
                        current_name = next_name
                        nsec_found = True
                        log.info(f"[green]+[/] NSEC Walk: Found {next_name}")
                        break
                
                if not nsec_found:
                    break
                    
        except Exception as e:
            log.debug(f"NSEC walk interrupted: {e}")

        return self._format_results(found_subdomains, domain)

    def _format_results(self, subdomains, domain) -> List[Dict[str, Any]]:
        return [{"name": sub, "type": "NSEC_WALKED", "value": "N/A"} for sub in subdomains]