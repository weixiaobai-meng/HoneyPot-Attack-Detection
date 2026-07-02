"""
Step 2: provenance graph visualization helpers.
"""

import hashlib
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
        "event": "#F6E05E",
        "unknown": "#95A5A6",
    }

    @staticmethod
    def _safe_node_id(raw_id: str) -> str:
        raw_text = str(raw_id or "unknown")
        digest = hashlib.md5(raw_text.encode("utf-8")).hexdigest()[:8]
        safe = "".join(ch if (ch.isascii() and (ch.isalnum() or ch == "_")) else "_" for ch in raw_text)
        safe = safe.strip("_")[:48] or "node"
        return f"n_{safe}_{digest}"

    @staticmethod
    def to_mermaid(graph_data: Dict, title: str = "Attack Graph") -> str:
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        lines = ["graph LR", f"    %% {title}", ""]
        node_classes = []

        for node in nodes:
            raw_id = node.get("id", "")
            node_id = CausalGraphVisualizer._safe_node_id(raw_id)
            node_type = node.get("type", "unknown")
            label = node.get("label") or node.get("path") or node.get("ip") or raw_id
            if len(str(label)) > 24:
                label = str(label)[:21] + "..."
            label = f"{node_type}\\n{label}"

            if node_type in {"process", "service"}:
                lines.append(f'    {node_id}["{label}"]')
            elif node_type in {"file", "url"}:
                lines.append(f'    {node_id}[/{label}/]')
            else:
                lines.append(f'    {node_id}("{label}")')
            node_classes.append((node_id, node_type if node_type in CausalGraphVisualizer.NODE_COLORS else "unknown"))

        lines.append("")

        for edge in edges:
            source = CausalGraphVisualizer._safe_node_id(edge.get("source", ""))
            target = CausalGraphVisualizer._safe_node_id(edge.get("target", ""))
            action = edge.get("action", "unknown")
            stage = edge.get("stage")
            edge_kind = edge.get("edge_kind")
            relation = edge.get("relation_type") or action
            if edge_kind == "correlation":
                edge_label = relation
                connector = "-.->"
            else:
                edge_label = f"{action}\\n{stage}" if stage else action
                connector = "-->"
            lines.append(f"    {source} {connector}|{edge_label}| {target}")

        lines.extend(
            [
                "",
                "    classDef process fill:#FF6B6B,stroke:#B23B3B,color:#111;",
                "    classDef file fill:#4ECDC4,stroke:#27867F,color:#111;",
                "    classDef network fill:#45B7D1,stroke:#1F6F86,color:#111;",
                "    classDef browser fill:#F4A261,stroke:#AA6732,color:#111;",
                "    classDef url fill:#2A9D8F,stroke:#17675D,color:#fff;",
                "    classDef service fill:#7D5BA6,stroke:#50386D,color:#fff;",
                "    classDef event fill:#F6E05E,stroke:#9B7B00,color:#111;",
                "    classDef unknown fill:#95A5A6,stroke:#617071,color:#111;",
            ]
        )
        for node_id, node_type in node_classes:
            lines.append(f"    class {node_id} {node_type};")

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
            node_id = CausalGraphVisualizer._safe_node_id(raw_id)
            node_type = node.get("type", "unknown")
            color = CausalGraphVisualizer.NODE_COLORS.get(node_type, "#95A5A6")
            label = node.get("label") or node.get("path") or node.get("ip") or raw_id
            label = str(label).replace('"', "'")
            lines.append(f'    "{node_id}" [label="{label}", fillcolor="{color}"];')

        lines.append("")

        for edge in edges:
            source = CausalGraphVisualizer._safe_node_id(edge.get("source", ""))
            target = CausalGraphVisualizer._safe_node_id(edge.get("target", ""))
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
