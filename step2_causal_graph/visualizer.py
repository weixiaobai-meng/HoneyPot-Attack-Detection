"""
第二步：因果图可视化器
支持输出Mermaid和DOT格式
"""

from typing import Dict, List


class CausalGraphVisualizer:
    """因果图可视化器"""
    
    NODE_COLORS = {
        "process": "#FF6B6B",
        "file": "#4ECDC4",
        "network": "#45B7D1",
        "unknown": "#95A5A6"
    }
    
    @staticmethod
    def to_mermaid(graph_data: Dict, title: str = "Attack Graph") -> str:
        """转换为Mermaid格式"""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        lines = [f"graph TD"]
        lines.append(f"    %% {title}")
        lines.append("")
        
        # 添加节点
        for node in nodes:
            node_id = node.get("id", "").replace(":", "_").replace("/", "_")
            node_type = node.get("type", "unknown")
            label = node.get("exe") or node.get("path") or node.get("ip") or node_id
            if len(str(label)) > 20:
                label = str(label)[:17] + "..."
            
            if node_type == "process":
                lines.append(f"    {node_id}[\"{label}\"]")
            elif node_type == "file":
                lines.append(f"    {node_id}[\"{label}\"]")
            else:
                lines.append(f"    {node_id}(\"{label}\")")
        
        lines.append("")
        
        # 添加边
        for edge in edges:
            source = edge.get("source", "").replace(":", "_").replace("/", "_")
            target = edge.get("target", "").replace(":", "_").replace("/", "_")
            action = edge.get("action", "unknown")
            lines.append(f"    {source} -->|{action}| {target}")
        
        return "\n".join(lines)
    
    @staticmethod
    def to_dot(graph_data: Dict, title: str = "Attack Graph") -> str:
        """转换为DOT格式"""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        lines = ["digraph AttackGraph {"]
        lines.append(f'    label="{title}";')
        lines.append('    node [shape=box, style=filled];')
        lines.append("")
        
        # 添加节点
        for node in nodes:
            node_id = node.get("id", "").replace(":", "_").replace("/", "_")
            node_type = node.get("type", "unknown")
            color = CausalGraphVisualizer.NODE_COLORS.get(node_type, "#95A5A6")
            label = node.get("exe") or node.get("path") or node.get("ip") or node_id
            lines.append(f'    "{node_id}" [label="{label}", fillcolor="{color}"];')
        
        lines.append("")
        
        # 添加边
        for edge in edges:
            source = edge.get("source", "").replace(":", "_").replace("/", "_")
            target = edge.get("target", "").replace(":", "_").replace("/", "_")
            action = edge.get("action", "unknown")
            lines.append(f'    "{source}" -> "{target}" [label="{action}"];')
        
        lines.append("}")
        return "\n".join(lines)
    
    @staticmethod
    def save_mermaid(graph_data: Dict, output_path: str, title: str = "Attack Graph"):
        """保存Mermaid格式"""
        mermaid = CausalGraphVisualizer.to_mermaid(graph_data, title)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(mermaid)
        print(f"[+] Mermaid格式已保存到: {output_path}")
    
    @staticmethod
    def save_dot(graph_data: Dict, output_path: str, title: str = "Attack Graph"):
        """保存DOT格式"""
        dot = CausalGraphVisualizer.to_dot(graph_data, title)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(dot)
        print(f"[+] DOT格式已保存到: {output_path}")
