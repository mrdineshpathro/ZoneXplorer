import networkx as nx
from typing import List, Dict, Any
from output.logger import log

class TopologyVisualizer:
    def __init__(self, records: List[Dict[str, Any]], domain: str):
        self.records = records
        self.domain = domain
        self.graph = nx.DiGraph()

    def generate(self, output_path: str):
        log.info("[cyan]➜[/] Generating network topology graph...")
        
        # Add Root
        self.graph.add_node(self.domain, type='root', color='red')

        for rec in self.records:
            node_name = rec['name']
            value = rec['value']
            rtype = rec['type']

            # Simplify graph: Connect subdomains to root
            if node_name.endswith(self.domain):
                self.graph.add_edge(self.domain, node_name)
                self.graph.add_node(node_name, type='subdomain', label=f"{node_name}\n({rtype})")

                # If it's a CNAME or MX, connect to the target
                if rtype in ['CNAME', 'MX', 'NS']:
                    self.graph.add_edge(node_name, value)
                    self.graph.add_node(value, type='external', color='grey')
            
        try:
            # Export to DOT format
            nx.drawing.nx_pydot.write_dot(self.graph, output_path)
            log.info(f"[bold green]✓[/] Graph saved to {output_path}")
        except ImportError:
            log.error("[red]![/] PyGraphviz/Pydot not installed. Cannot write .dot file directly. Install 'pydot'.")
        except Exception as e:
            log.error(f"[red]![/] Visualization failed: {e}")