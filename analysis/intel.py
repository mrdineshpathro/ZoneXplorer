import re
from typing import List, Dict, Any
from output.logger import log

class IntelAnalyzer:
    def __init__(self, records: List[Dict[str, Any]]):
        self.records = records
        self.vulns = []

    def run(self) -> List[Dict[str, Any]]:
        self._check_rfc1918()
        self._check_email_spoofing()
        self._check_high_value()
        return self.vulns

    def _check_rfc1918(self):
        """Checks for Private IP leakage."""
        private_patterns = [r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\."]
        for rec in self.records:
            if rec['type'] == 'A':
                for pat in private_patterns:
                    if re.match(pat, rec['value']):
                        msg = f"Private IP Leakage: {rec['name']} -> {rec['value']}"
                        self.vulns.append({"severity": "HIGH", "msg": msg})

    def _check_email_spoofing(self):
        """Checks for DMARC/SPF weakness."""
        has_spf = False
        has_dmarc = False
        for rec in self.records:
            if rec['type'] == 'TXT':
                if "v=spf1" in rec['value']: has_spf = True
                if "_dmarc" in rec['name']: has_dmarc = True
        
        if not has_dmarc:
            self.vulns.append({"severity": "MEDIUM", "msg": "Missing DMARC record (Email Spoofing Risk)"})
        if not has_spf:
            self.vulns.append({"severity": "MEDIUM", "msg": "Missing SPF record"})

    def _check_high_value(self):
        keywords = ['git', 'dev', 'stg', 'vpn', 'admin', 'jenkins', 'k8s', 'api']
        for rec in self.records:
            for kw in keywords:
                if kw in rec['name'].lower():
                    self.vulns.append({"severity": "INFO", "msg": f"High Value Target: {rec['name']}"})