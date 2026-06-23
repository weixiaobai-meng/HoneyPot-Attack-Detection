"""
Step 4: convert provenance graph into thesis-oriented textual narrative.
"""

import os
from datetime import datetime
from typing import List, Dict
from collections import defaultdict

from .prompts import PromptTemplates


class GraphToTextConverter:
    """Generate structured natural-language views for LLM reasoning."""

    ACTION_DESCRIPTIONS = {
        "ssh_login": "attempted SSH access",
        "vpn_connect": "attempted VPN access",
        "file_access": "accessed honey file",
        "url_access": "accessed parasitic honey page",
        "openat": "opened file",
        "read": "read file",
        "write": "wrote file",
        "execve": "executed process",
        "fork": "spawned process",
        "connect": "established network connection",
        "unlink": "deleted file",
        "rename": "renamed file",
        "chmod": "modified file permission",
        "mkdir": "created directory",
    }

    NODE_TYPE_DESCRIPTIONS = {
        "network": "network entity",
        "browser": "browser entity",
        "file": "file entity",
        "process": "process entity",
        "service": "service entity",
        "url": "URL entity",
        "unknown": "unknown entity",
    }

    STAGE_ORDER = [
        "reconnaissance",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "collection",
        "command_and_control",
        "exfiltration",
    ]

    def __init__(self):
        self.node_cache: Dict[str, str] = {}

    def convert(self, graph_data: Dict, include_timestamps: bool = True) -> str:
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        triples = graph_data.get("triples", [])
        meta = graph_data.get("graph_meta", {})
        attack_paths = graph_data.get("attack_paths", [])
        attacker_groups = graph_data.get("attacker_groups", [])
        node_map = {node["id"]: node for node in nodes}
        sorted_edges = sorted(edges, key=lambda e: e.get("timestamp", ""))

        sections = [
            self._generate_summary(meta, nodes, edges, triples),
            self._generate_attackers(attacker_groups),
            self._generate_attack_paths(attack_paths, node_map),
            self._generate_stage_view(sorted_edges, node_map),
            self._generate_timeline(sorted_edges, node_map, include_timestamps),
            self._generate_key_paths(sorted_edges, node_map),
            self._generate_triple_summary(triples),
            self._generate_iocs(sorted_edges, node_map),
        ]
        return "\n\n".join(section for section in sections if section.strip())

    def convert_to_llm_prompt(self, graph_data: Dict, task: str = "intent_analysis") -> str:
        narrative = self.convert(graph_data, include_timestamps=True)

        if task == "intent_analysis":
            return PromptTemplates.INTENT_ANALYSIS.format(narrative=narrative)
        if task == "ttp_mapping":
            return PromptTemplates.TTP_MAPPING.format(narrative=narrative)
        if task == "report":
            return PromptTemplates.REPORT_GENERATION.format(narrative=narrative)
        return narrative

    def _generate_summary(self, meta: Dict, nodes: List[Dict], edges: List[Dict], triples: List[Dict]) -> str:
        lines = ["## 1. Event Summary", ""]
        lines.append(
            f"This provenance graph contains {meta.get('node_count', len(nodes))} nodes, "
            f"{meta.get('edge_count', len(edges))} edges, and {meta.get('triple_count', len(triples))} standard triples."
        )
        lines.append("")

        type_counter = defaultdict(int)
        for node in nodes:
            type_counter[node.get("type", "unknown")] += 1

        lines.append("Entity distribution:")
        for node_type, count in sorted(type_counter.items()):
            lines.append(f"- {self.NODE_TYPE_DESCRIPTIONS.get(node_type, node_type)}: {count}")

        if "event_edge_count" in meta or "correlation_edge_count" in meta:
            lines.append("")
            lines.append(
                f"Edge breakdown: event edges={meta.get('event_edge_count', 0)}, "
                f"correlation edges={meta.get('correlation_edge_count', 0)}, "
                f"attackers={meta.get('attacker_count', 0)}, "
                f"attack paths={meta.get('path_count', 0)}"
            )

        return "\n".join(lines)

    def _generate_attackers(self, attacker_groups: List[Dict]) -> str:
        lines = ["## 2. Attacker Clusters", ""]
        if not attacker_groups:
            lines.append("- No attacker clusters were reconstructed.")
            return "\n".join(lines)

        for item in attacker_groups[:10]:
            attacker_id = item.get("attacker_id") or "unknown_attacker"
            event_count = item.get("event_count", len(item.get("event_ids", [])))
            path_ids = item.get("path_ids", [])
            anchors = item.get("anchors", [])
            event_types = item.get("event_types", [])
            start_time = item.get("start_time") or "-"
            end_time = item.get("end_time") or "-"
            lines.append(
                f"- {attacker_id}: events={event_count}, "
                f"paths={', '.join(path_ids) if path_ids else 'none'}, "
                f"types={', '.join(event_types) if event_types else 'unknown'}, "
                f"time={start_time} -> {end_time}, "
                f"anchors={', '.join(anchors) if anchors else 'none'}"
            )
        if len(attacker_groups) > 10:
            lines.append(f"- ... {len(attacker_groups) - 10} more attacker clusters omitted.")
        return "\n".join(lines)

    def _generate_attack_paths(self, attack_paths: List[Dict], node_map: Dict) -> str:
        lines = ["## 3. Attack Path Groups", ""]
        if not attack_paths:
            lines.append("- No grouped attack paths were reconstructed.")
            return "\n".join(lines)

        for item in attack_paths[:10]:
            path_id = item.get("path_id") or "unknown_path"
            event_count = item.get("event_count", len(item.get("event_ids", [])))
            anchors = item.get("anchors", [])
            event_types = item.get("event_types", [])
            start_time = item.get("start_time") or "-"
            end_time = item.get("end_time") or "-"

            lines.append(
                f"- {path_id}: events={event_count}, "
                f"types={', '.join(event_types) if event_types else 'unknown'}, "
                f"time={start_time} -> {end_time}, "
                f"anchors={', '.join(anchors) if anchors else 'none'}"
            )
        if len(attack_paths) > 10:
            lines.append(f"- ... {len(attack_paths) - 10} more path groups omitted.")
        return "\n".join(lines)

    def _generate_stage_view(self, edges: List[Dict], node_map: Dict) -> str:
        phase_groups = defaultdict(list)
        for edge in edges:
            if edge.get("edge_kind") != "event":
                continue
            phase_groups[edge.get("stage") or "unknown"].append(edge)

        lines = ["## 4. Attack Stage View", ""]
        for stage in self.STAGE_ORDER + ["unknown"]:
            if stage not in phase_groups:
                continue
            lines.append(f"### {stage}")
            lines.append("")
            for edge in phase_groups[stage]:
                lines.append(
                    f"- {self._get_node_description(edge.get('source'), node_map)} "
                    f"{self.ACTION_DESCRIPTIONS.get(edge.get('action'), edge.get('action'))} "
                    f"{self._get_node_description(edge.get('target'), node_map)} "
                    f"(tactic={edge.get('tactic')}, technique={edge.get('technique')}, severity={edge.get('severity')})"
                )
            lines.append("")
        return "\n".join(lines)

    def _generate_timeline(self, edges: List[Dict], node_map: Dict, include_timestamps: bool) -> str:
        lines = ["## 5. Event Timeline", ""]
        event_edges = [edge for edge in edges if edge.get("edge_kind") == "event"]
        for idx, edge in enumerate(event_edges, 1):
            prefix = ""
            if include_timestamps and edge.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(edge["timestamp"])
                    prefix = f"[{ts.strftime('%H:%M:%S')}] "
                except ValueError:
                    prefix = f"[{edge['timestamp']}] "

            lines.append(
                f"{prefix}Step {idx}: "
                f"{self._get_node_description(edge.get('source'), node_map)} "
                f"{self.ACTION_DESCRIPTIONS.get(edge.get('action'), edge.get('action'))} "
                f"{self._get_node_description(edge.get('target'), node_map)}."
            )
        return "\n".join(lines)

    def _generate_key_paths(self, edges: List[Dict], node_map: Dict) -> str:
        edges = [edge for edge in edges if edge.get("edge_kind") == "event"]
        adjacency = defaultdict(list)
        indegree = defaultdict(int)
        for edge in edges:
            adjacency[edge.get("source")].append(edge)
            indegree[edge.get("target")] += 1
            indegree.setdefault(edge.get("source"), indegree.get(edge.get("source"), 0))

        entry_nodes = [node_id for node_id, degree in indegree.items() if degree == 0]
        paths = []
        for entry in entry_nodes[:5]:
            path = self._trace_linear_path(entry, adjacency)
            if path:
                paths.append(path)

        lines = ["## 6. Candidate Attack Paths", ""]
        if not paths:
            lines.append("- No attack path could be reconstructed from current edges.")
            return "\n".join(lines)

        for idx, path in enumerate(paths, 1):
            lines.append(f"Path {idx}:")
            lines.append(" -> ".join(self._get_node_description(node_id, node_map) for node_id in path))
            lines.append("")
        return "\n".join(lines)

    def _generate_triple_summary(self, triples: List[Dict]) -> str:
        lines = ["## 7. Standard Triple Samples", ""]
        if not triples:
            lines.append("- No triples were generated.")
            return "\n".join(lines)

        for triple in triples[:10]:
            if isinstance(triple, (list, tuple)) and len(triple) == 3:
                lines.append(f"- ({triple[0]}, {triple[1]}, {triple[2]}) [legacy-triple-format]")
                continue
            lines.append(
                f"- ({triple['subject']['id']}, {triple['predicate']}, {triple['object']['id']}) "
                f"[stage={triple.get('stage')}, confidence={triple.get('confidence')}]"
            )
        if len(triples) > 10:
            lines.append(f"- ... {len(triples) - 10} more triples omitted for brevity.")
        return "\n".join(lines)

    def _generate_iocs(self, edges: List[Dict], node_map: Dict) -> str:
        edges = [edge for edge in edges if edge.get("edge_kind") == "event"]
        ips = set()
        files = set()
        processes = set()
        urls = set()

        for node_id, node in node_map.items():
            node_type = node.get("type")
            label = node.get("label") or node_id
            if node_type == "network":
                ips.add(label)
            elif node_type == "file":
                files.add(label)
            elif node_type == "process":
                processes.add(label)
            elif node_type == "url":
                urls.add(label)

        lines = ["## 8. Extracted IoCs", ""]
        lines.append(f"- IPs: {', '.join(sorted(ips)) if ips else 'None'}")
        lines.append(f"- Files: {', '.join(sorted(files)) if files else 'None'}")
        lines.append(f"- Processes: {', '.join(sorted(processes)) if processes else 'None'}")
        lines.append(f"- URLs: {', '.join(sorted(urls)) if urls else 'None'}")
        return "\n".join(lines)

    def _trace_linear_path(self, start: str, adjacency: Dict[str, List[Dict]], max_depth: int = 8) -> List[str]:
        path = [start]
        current = start
        visited = {start}
        for _ in range(max_depth):
            next_edges = adjacency.get(current, [])
            if not next_edges:
                break
            next_edge = next_edges[0]
            next_node = next_edge.get("target")
            if not next_node or next_node in visited:
                break
            path.append(next_node)
            visited.add(next_node)
            current = next_node
        return path

    def _get_node_description(self, node_id: str, node_map: Dict[str, Dict]) -> str:
        if node_id in self.node_cache:
            return self.node_cache[node_id]

        node = node_map.get(node_id, {})
        node_type = node.get("type", "unknown")
        label = node.get("label") or node.get("path") or node.get("ip") or node_id or "unknown"
        desc = f"{self.NODE_TYPE_DESCRIPTIONS.get(node_type, node_type)} [{label}]"
        self.node_cache[node_id] = desc
        return desc

    def save(self, text: str, output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[+] Saved narrative text to: {output_path}")
        print(f"    length: {len(text)} chars")
