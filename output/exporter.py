import json
import csv
import os
from typing import List, Dict, Any
from output.logger import log

class Exporter:
    def __init__(self, output_dir: str, domain: str):
        self.output_dir = output_dir
        self.domain = domain
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def to_json(self, data: List[Dict[str, Any]]):
        path = os.path.join(self.output_dir, f"{self.domain}.json")
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        log.info(f"[blue]*[/] JSON saved to {path}")

    def to_csv(self, data: List[Dict[str, Any]]):
        if not data: return
        path = os.path.join(self.output_dir, f"{self.domain}.csv")
        keys = data[0].keys()
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        log.info(f"[blue]*[/] CSV saved to {path}")