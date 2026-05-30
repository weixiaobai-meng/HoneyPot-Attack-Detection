"""
第四步：Graph-to-Text转换器
将因果图转换为叙述性文本
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

from .prompts import PromptTemplates


class GraphToTextConverter:
    """因果图转文本引擎"""
    
    ACTION_DESCRIPTIONS = {
        "ssh_login": "尝试SSH登录",
        "file_access": "访问文件",
        "url_access": "访问URL链接",
        "openat": "打开文件",
        "read": "读取文件",
        "write": "写入文件",
        "execve": "执行程序",
        "fork": "创建子进程",
        "connect": "建立网络连接",
        "unlink": "删除文件",
        "rename": "重命名文件",
        "chmod": "修改文件权限",
        "vpn_connect": "尝试VPN连接"
    }
    
    NODE_TYPE_DESCRIPTIONS = {
        "network": "网络地址",
        "file": "文件",
        "process": "进程"
    }
    
    ATTACK_PHASE_MAP = {
        "ssh_login": "初始访问",
        "vpn_connect": "初始访问",
        "file_access": "侦察/发现",
        "url_access": "侦察/发现",
        "openat": "执行/访问",
        "read": "数据收集",
        "write": "数据篡改/持久化",
        "execve": "执行",
        "fork": "权限提升/横向移动",
        "connect": "命令控制/数据外泄",
        "unlink": "防御规避",
        "rename": "防御规避",
        "chmod": "权限提升"
    }
    
    def __init__(self):
        self.node_cache = {}
    
    def convert(self, graph_data: Dict, include_timestamps: bool = True) -> str:
        """将因果图转换为叙述性文本"""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        pruning_stats = graph_data.get("pruning_stats", {})
        
        node_map = {node["id"]: node for node in nodes}
        sorted_edges = sorted(edges, key=lambda e: e.get("timestamp", ""))
        
        sections = []
        sections.append(self._generate_summary(nodes, edges, pruning_stats))
        sections.append(self._generate_timeline(sorted_edges, node_map, include_timestamps))
        sections.append(self._generate_phase_analysis(sorted_edges, node_map))
        sections.append(self._generate_key_paths(graph_data, node_map))
        sections.append(self._generate_technical_details(sorted_edges, node_map))
        
        return "\n\n".join(sections)
    
    def convert_to_llm_prompt(self, graph_data: Dict, task: str = "intent_analysis") -> str:
        """转换为LLM提示词"""
        narrative = self.convert(graph_data, include_timestamps=True)
        
        if task == "intent_analysis":
            return PromptTemplates.INTENT_ANALYSIS.format(narrative=narrative)
        elif task == "ttp_mapping":
            return PromptTemplates.TTP_MAPPING.format(narrative=narrative)
        elif task == "report":
            return PromptTemplates.REPORT_GENERATION.format(narrative=narrative)
        else:
            return narrative
    
    def _generate_summary(self, nodes: List, edges: List, pruning_stats: Dict) -> str:
        """生成概述"""
        lines = ["## 一、攻击事件概述"]
        lines.append("")
        
        node_types = defaultdict(int)
        for node in nodes:
            node_types[node.get("type", "unknown")] += 1
        
        edge_actions = defaultdict(int)
        for edge in edges:
            edge_actions[edge.get("action", "unknown")] += 1
        
        lines.append(f"本次攻击事件涉及 {len(nodes)} 个实体节点和 {len(edges)} 个攻击行为。")
        lines.append("")
        
        lines.append("**涉及实体：**")
        for ntype, count in node_types.items():
            type_desc = self.NODE_TYPE_DESCRIPTIONS.get(ntype, ntype)
            lines.append(f"- {type_desc}: {count} 个")
        lines.append("")
        
        lines.append("**攻击行为：**")
        for action, count in edge_actions.items():
            action_desc = self.ACTION_DESCRIPTIONS.get(action, action)
            lines.append(f"- {action_desc}: {count} 次")
        
        if pruning_stats:
            lines.append("")
            lines.append(f"**图谱压缩率：** {pruning_stats.get('compression_ratio', 'N/A')} "
                        f"(原始 {pruning_stats.get('original_edges', 'N/A')} 条边，"
                        f"保留 {pruning_stats.get('kept_edges', 'N/A')} 条)")
        
        return "\n".join(lines)
    
    def _generate_timeline(self, edges: List, node_map: Dict, include_timestamps: bool) -> str:
        """生成攻击时间线"""
        lines = ["## 二、攻击时间线"]
        lines.append("")
        
        for i, edge in enumerate(edges, 1):
            source_id = edge.get("source")
            target_id = edge.get("target")
            action = edge.get("action", "unknown")
            timestamp = edge.get("timestamp")
            
            source_desc = self._get_node_description(source_id, node_map)
            target_desc = self._get_node_description(target_id, node_map)
            action_desc = self.ACTION_DESCRIPTIONS.get(action, action)
            
            time_str = ""
            if include_timestamps and timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = f"[{dt.strftime('%H:%M:%S')}] "
                except:
                    time_str = ""
            
            lines.append(f"{time_str}**步骤{i}：** {source_desc} {action_desc} {target_desc}")
        
        return "\n".join(lines)
    
    def _generate_phase_analysis(self, edges: List, node_map: Dict) -> str:
        """生成攻击阶段分析"""
        lines = ["## 三、攻击阶段分析"]
        lines.append("")
        
        phase_groups = defaultdict(list)
        for edge in edges:
            action = edge.get("action", "unknown")
            phase = self.ATTACK_PHASE_MAP.get(action, "其他")
            phase_groups[phase].append(edge)
        
        phase_order = [
            "初始访问", "执行", "持久化", "权限提升", 
            "防御规避", "侦察/发现", "横向移动", 
            "收集", "命令控制", "数据外泄"
        ]
        
        for phase in phase_order:
            if phase in phase_groups:
                phase_edges = phase_groups[phase]
                lines.append(f"### {phase}")
                lines.append("")
                
                for edge in phase_edges:
                    source_id = edge.get("source")
                    target_id = edge.get("target")
                    action = edge.get("action", "unknown")
                    
                    source_desc = self._get_node_description(source_id, node_map)
                    target_desc = self._get_node_description(target_id, node_map)
                    action_desc = self.ACTION_DESCRIPTIONS.get(action, action)
                    
                    lines.append(f"- {source_desc} → {action_desc} → {target_desc}")
                
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_key_paths(self, graph_data: Dict, node_map: Dict) -> str:
        """生成关键攻击路径"""
        lines = ["## 四、关键攻击路径"]
        lines.append("")
        
        edges = graph_data.get("edges", [])
        
        adj = defaultdict(list)
        for edge in edges:
            adj[edge.get("source")].append(edge.get("target"))
        
        targets = set(e.get("target") for e in edges)
        sources = set(e.get("source") for e in edges)
        entry_nodes = sources - targets
        
        paths = []
        for entry in list(entry_nodes)[:3]:
            path = self._find_path(adj, entry, max_depth=5)
            if path:
                paths.append(path)
        
        for i, path in enumerate(paths[:5], 1):
            lines.append(f"**路径 {i}：**")
            path_desc = []
            for node in path:
                path_desc.append(self._get_node_description(node, node_map))
            lines.append(" → ".join(path_desc))
            lines.append("")
        
        return "\n".join(lines)
    
    def _find_path(self, adj: Dict, start: str, max_depth: int = 5) -> List[str]:
        """查找路径"""
        path = [start]
        current = start
        
        for _ in range(max_depth):
            next_nodes = adj.get(current, [])
            if not next_nodes:
                break
            next_node = next_nodes[0]
            if next_node in path:
                break
            path.append(next_node)
            current = next_node
        
        return path
    
    def _generate_technical_details(self, edges: List, node_map: Dict) -> str:
        """生成技术细节"""
        lines = ["## 五、技术细节"]
        lines.append("")
        lines.append("### 涉及的系统调用/操作")
        lines.append("")
        
        syscall_map = {
            "openat": "文件打开 (openat)",
            "read": "文件读取 (read)",
            "write": "文件写入 (write)",
            "execve": "程序执行 (execve)",
            "fork": "进程创建 (fork/clone)",
            "connect": "网络连接 (connect)",
            "unlink": "文件删除 (unlink)",
            "chmod": "权限修改 (chmod)"
        }
        
        syscalls = defaultdict(int)
        for edge in edges:
            action = edge.get("action", "unknown")
            if action in syscall_map:
                syscalls[action] += 1
        
        if syscalls:
            for syscall, count in syscalls.items():
                desc = syscall_map[syscall]
                lines.append(f"- {desc}: {count} 次")
        else:
            lines.append("- 无底层系统调用记录")
        
        return "\n".join(lines)
    
    def _get_node_description(self, node_id: str, node_map: Dict) -> str:
        """获取节点的可读描述"""
        if node_id in self.node_cache:
            return self.node_cache[node_id]
        
        node = node_map.get(node_id, {})
        node_type = node.get("type", "unknown")
        
        if node_type == "network":
            ip = node.get("ip", node_id)
            desc = f"网络地址 {ip}"
        elif node_type == "file":
            path = node.get("path", node_id)
            if len(path) > 30:
                path = "..." + path[-27:]
            desc = f"文件 {path}"
        elif node_type == "process":
            exe = node.get("exe", "")
            if exe:
                desc = f"进程 {exe}"
            else:
                desc = f"进程 PID:{node.get('pid', 'unknown')}"
        else:
            desc = node_id
        
        self.node_cache[node_id] = desc
        return desc
    
    def save(self, text: str, output_path: str):
        """保存文本"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"[+] 文本已保存到: {output_path}")
        print(f"    长度: {len(text)} 字符")
