"""
Step 2: provenance graph visualization helpers.
"""

from typing import Dict


class CausalGraphVisualizer:
    """Render provenance graph into Mermaid or DOT."""

    NODE_COLORS = {
        "process": "#FF6B6B",
        "file": "#4ECDC4",
        "network": "#45B7D1",
        "browser": "#F4A261",
        "url": "#2A9D8F",
        "service": "#7D5BA6",
        "unknown": "#95A5A6",
    }

    @staticmethod
    def to_mermaid(graph_data: Dict, title: str = "Attack Graph") -> str:
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        lines = ["graph TD", f"    %% {title}", ""]

        for node in nodes:
            raw_id = node.get("id", "")
            node_id = raw_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            node_type = node.get("type", "unknown")
            label = node.get("label") or node.get("path") or node.get("ip") or raw_id
            if len(str(label)) > 24:
                label = str(label)[:21] + "..."

            if node_type in {"process", "service"}:
                lines.append(f'    {node_id}["{label}"]')
            elif node_type in {"file", "url"}:
                lines.append(f'    {node_id}[/{label}/]')
            else:
                lines.append(f'    {node_id}("{label}")')

        lines.append("")

        for edge in edges:
            source = edge.get("source", "").replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            target = edge.get("target", "").replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            action = edge.get("action", "unknown")
            stage = edge.get("stage")
            edge_label = f"{action}\\n{stage}" if stage else action
            lines.append(f"    {source} -->|{edge_label}| {target}")

        return "\n".join(lines)

    @staticmethod
    def to_dot(graph_data: Dict, title: str = "Attack Graph") -> str:
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        lines = [
            "digraph AttackGraph {",
            f'    label="{title}";',
            '    node [shape=box, style=filled];',
            "",
        ]

        for node in nodes:
            raw_id = node.get("id", "")
            node_id = raw_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            node_type = node.get("type", "unknown")
            color = CausalGraphVisualizer.NODE_COLORS.get(node_type, "#95A5A6")
            label = node.get("label") or node.get("path") or node.get("ip") or raw_id
            label = str(label).replace('"', "'")
            lines.append(f'    "{node_id}" [label="{label}", fillcolor="{color}"];')

        lines.append("")

        for edge in edges:
            source = edge.get("source", "").replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            target = edge.get("target", "").replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
            action = edge.get("action", "unknown")
            stage = edge.get("stage")
            edge_label = f"{action}\\n{stage}" if stage else action
            edge_label = edge_label.replace('"', "'")
            lines.append(f'    "{source}" -> "{target}" [label="{edge_label}"];')

        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def save_mermaid(graph_data: Dict, output_path: str, title: str = "Attack Graph") -> None:
        mermaid = CausalGraphVisualizer.to_mermaid(graph_data, title)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(mermaid)
        print(f"[+] Saved Mermaid graph to: {output_path}")

    @staticmethod
    def save_dot(graph_data: Dict, output_path: str, title: str = "Attack Graph") -> None:
        dot = CausalGraphVisualizer.to_dot(graph_data, title)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(dot)
        print(f"[+] Saved DOT graph to: {output_path}")
