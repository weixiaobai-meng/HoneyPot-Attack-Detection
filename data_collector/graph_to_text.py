"""
Graph-to-Text 模块
将因果图转换为具有逻辑因果关系的叙述性文本
用于后续LLM攻击意图推理
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from collections import defaultdict


class GraphToTextConverter:
    """
    因果图转文本引擎
    将裁剪后的精简图谱翻译成具有逻辑因果关系的叙述性文本
    """
    
    # 动作描述映射
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
    
    # 节点类型描述
    NODE_TYPE_DESCRIPTIONS = {
        "network": "网络地址",
        "file": "文件",
        "process": "进程"
    }
    
    # 攻击阶段映射
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
        self.node_cache = {}  # 节点描述缓存
    
    def convert(self, graph_data: Dict, include_timestamps: bool = True) -> str:
        """
        将因果图转换为叙述性文本
        
        Args:
            graph_data: 因果图字典
            include_timestamps: 是否包含时间戳
            
        Returns:
            格式化的文本描述
        """
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        pruning_stats = graph_data.get("pruning_stats", {})
        
        # 构建节点索引
        node_map = {node["id"]: node for node in nodes}
        
        # 按时间排序边
        sorted_edges = sorted(edges, key=lambda e: e.get("timestamp", ""))
        
        # 生成文本
        sections = []
        
        # 1. 概述
        sections.append(self._generate_summary(nodes, edges, pruning_stats))
        
        # 2. 攻击时间线
        sections.append(self._generate_timeline(sorted_edges, node_map, include_timestamps))
        
        # 3. 攻击阶段分析
        sections.append(self._generate_phase_analysis(sorted_edges, node_map))
        
        # 4. 关键路径
        sections.append(self._generate_key_paths(graph_data, node_map))
        
        # 5. 技术细节
        sections.append(self._generate_technical_details(sorted_edges, node_map))
        
        return "\n\n".join(sections)
    
    def _generate_summary(self, nodes: List, edges: List, pruning_stats: Dict) -> str:
        """生成概述"""
        lines = ["## 一、攻击事件概述"]
        lines.append("")
        
        # 统计信息
        node_types = defaultdict(int)
        for node in nodes:
            node_types[node.get("type", "unknown")] += 1
        
        edge_actions = defaultdict(int)
        for edge in edges:
            edge_actions[edge.get("action", "unknown")] += 1
        
        lines.append(f"本次攻击事件涉及 {len(nodes)} 个实体节点和 {len(edges)} 个攻击行为。")
        lines.append("")
        
        # 节点分布
        lines.append("**涉及实体：**")
        for ntype, count in node_types.items():
            type_desc = self.NODE_TYPE_DESCRIPTIONS.get(ntype, ntype)
            lines.append(f"- {type_desc}: {count} 个")
        lines.append("")
        
        # 行为分布
        lines.append("**攻击行为：**")
        for action, count in edge_actions.items():
            action_desc = self.ACTION_DESCRIPTIONS.get(action, action)
            lines.append(f"- {action_desc}: {count} 次")
        
        # 裁剪统计
        if pruning_stats:
            lines.append("")
            lines.append(f"**图谱压缩率：** {pruning_stats.get('compression_ratio', 'N/A')} "
                        f"(原始 {pruning_stats.get('original_edges', 'N/A')} 条边，"
                        f"保留 {pruning_stats.get('kept_edges', 'N/A')} 条)")
        
        return "\n".join(lines)
    
    def _generate_timeline(self, edges: List, node_map: Dict, 
                          include_timestamps: bool) -> str:
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
            
            # 时间描述
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
        
        # 按阶段分组
        phase_groups = defaultdict(list)
        for edge in edges:
            action = edge.get("action", "unknown")
            phase = self.ATTACK_PHASE_MAP.get(action, "其他")
            phase_groups[phase].append(edge)
        
        # MITRE ATT&CK 阶段顺序
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
        
        # 处理未分类的阶段
        other_phases = [p for p in phase_groups if p not in phase_order]
        for phase in other_phases:
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
        
        # 构建邻接表
        adj = defaultdict(list)
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            action = edge.get("action", "unknown")
            adj[source].append((target, action))
        
        # 找到入口节点（入度为0）
        targets = set(e.get("target") for e in edges)
        sources = set(e.get("source") for e in edges)
        entry_nodes = sources - targets
        
        # 找到出口节点（出度为0）
        exit_nodes = targets - sources
        
        # 生成路径
        paths = []
        for entry in entry_nodes:
            for exit_node in exit_nodes:
                found_paths = self._find_paths(adj, entry, exit_node, max_depth=10)
                paths.extend(found_paths)
        
        if not paths:
            # 如果没有找到完整路径，显示部分路径
            for entry in list(entry_nodes)[:3]:
                partial_paths = self._find_paths(adj, entry, None, max_depth=5)
                paths.extend(partial_paths)
        
        # 格式化路径
        for i, path in enumerate(paths[:5], 1):  # 最多显示5条路径
            lines.append(f"**路径 {i}：**")
            path_desc = []
            for j in range(len(path) - 1):
                source = path[j]
                target = path[j + 1]
                # 找到对应的边
                for edge in edges:
                    if edge.get("source") == source and edge.get("target") == target:
                        action = edge.get("action", "unknown")
                        action_desc = self.ACTION_DESCRIPTIONS.get(action, action)
                        source_desc = self._get_node_description(source, node_map)
                        path_desc.append(f"{source_desc}")
                        if j == len(path) - 2:
                            target_desc = self._get_node_description(target, node_map)
                            path_desc.append(f"{action_desc} {target_desc}")
                        break
            
            lines.append(" → ".join(path_desc))
            lines.append("")
        
        return "\n".join(lines)
    
    def _find_paths(self, adj: Dict, start: str, end: Optional[str], 
                   max_depth: int = 10) -> List[List[str]]:
        """查找路径"""
        paths = []
        
        def dfs(current, target, path, depth):
            if depth > max_depth:
                return
            if target and current == target:
                paths.append(path.copy())
                return
            if not target and not adj.get(current):
                # 没有出边的节点
                paths.append(path.copy())
                return
            
            for next_node, _ in adj.get(current, []):
                if next_node not in path:
                    path.append(next_node)
                    dfs(next_node, target, path, depth + 1)
                    path.pop()
        
        dfs(start, end, [start], 0)
        return paths
    
    def _generate_technical_details(self, edges: List, node_map: Dict) -> str:
        """生成技术细节"""
        lines = ["## 五、技术细节"]
        lines.append("")
        lines.append("### 涉及的系统调用/操作")
        lines.append("")
        
        # 统计系统调用
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
        
        lines.append("")
        lines.append("### 涉及的进程")
        lines.append("")
        
        # 统计进程
        processes = set()
        for edge in edges:
            source = edge.get("source", "")
            target = edge.get("target", "")
            if "process:" in source:
                node = node_map.get(source, {})
                exe = node.get("exe", source)
                processes.add(exe)
            if "process:" in target:
                node = node_map.get(target, {})
                exe = node.get("exe", target)
                processes.add(exe)
        
        if processes:
            for proc in processes:
                lines.append(f"- {proc}")
        else:
            lines.append("- 无进程信息")
        
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
            # 截断长路径
            if len(path) > 30:
                path = "..." + path[-27:]
            desc = f"文件 {path}"
        elif node_type == "process":
            exe = node.get("exe", "")
            pid = node.get("pid", "")
            if exe:
                desc = f"进程 {exe}"
            else:
                desc = f"进程 PID:{pid}"
        else:
            desc = node_id
        
        self.node_cache[node_id] = desc
        return desc
    
    def convert_to_llm_prompt(self, graph_data: Dict, 
                              task: str = "intent_analysis") -> str:
        """
        将因果图转换为LLM提示词
        
        Args:
            graph_data: 因果图字典
            task: 任务类型 (intent_analysis/ttp_mapping/report)
        """
        # 生成基础文本
        narrative = self.convert(graph_data, include_timestamps=True)
        
        if task == "intent_analysis":
            return self._build_intent_analysis_prompt(narrative)
        elif task == "ttp_mapping":
            return self._build_ttp_mapping_prompt(narrative)
        elif task == "report":
            return self._build_report_prompt(narrative)
        else:
            return narrative
    
    def _build_intent_analysis_prompt(self, narrative: str) -> str:
        """构建意图分析提示词"""
        prompt = f"""你是一个资深网络安全威胁溯源专家。请根据以下Graph-to-Text还原的因果行为文本，分析攻击者的意图。

{narrative}

请严格按照以下步骤进行分析：

1. **原子动作分析**：分析这些原子动作之间的技术关联，识别攻击者的技战术特征。

2. **战术阶段推导**：推导攻击者此时处于何种战术阶段（参考MITRE ATT&CK框架）。

3. **战略意图研判**：研判其最终的战略意图，包括：
   - 攻击目标是什么（数据窃取？系统破坏？持久化控制？）
   - 攻击者的可能身份（APT组织？脚本小子？内部威胁？）
   - 攻击的严重程度评估

4. **防御建议**：基于分析结果，给出针对性的防御建议。

请用结构化的方式输出你的分析结果。"""
        
        return prompt
    
    def _build_ttp_mapping_prompt(self, narrative: str) -> str:
        """构建TTP映射提示词"""
        prompt = f"""你是一个MITRE ATT&CK框架专家。请根据以下攻击行为描述，将识别出的行为自动标注并映射至MITRE ATT&CK框架的TTPs编号。

{narrative}

请输出格式如下：

| 行为描述 | 战术 (Tactic) | 技术 (Technique) | 子技术 (Sub-technique) | TTP编号 |
|---------|---------------|------------------|----------------------|---------|
| ... | ... | ... | ... | ... |

同时，请总结攻击者使用的主要技术栈和TTPs模式。"""
        
        return prompt
    
    def _build_report_prompt(self, narrative: str) -> str:
        """构建报告生成提示词"""
        prompt = f"""你是一个网络安全事件响应专家。请根据以下攻击行为分析，生成一份专业的安全事件报告。

{narrative}

报告应包含以下部分：

1. **事件摘要**：简要描述攻击事件的时间、影响范围和严重程度。

2. **攻击详情**：详细描述攻击的技术细节和攻击链路。

3. **影响评估**：评估此次攻击对系统和数据的影响。

4. **处置建议**：给出应急响应和长期防护建议。

5. **IoC指标**：提取相关的入侵指标（IP、文件路径、进程名等）。

请使用专业的安全术语，输出结构清晰的报告。"""
        
        return prompt


def load_and_convert(graph_path: str, output_path: str = None, 
                     task: str = "intent_analysis") -> str:
    """
    加载因果图并转换为文本
    
    Args:
        graph_path: 因果图文件路径
        output_path: 输出文本文件路径
        task: 任务类型
    """
    # 加载图
    with open(graph_path, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    # 转换
    converter = GraphToTextConverter()
    
    if task:
        text = converter.convert_to_llm_prompt(graph_data, task)
    else:
        text = converter.convert(graph_data)
    
    # 保存
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"[+] 文本已保存到: {output_path}")
    
    return text


if __name__ == "__main__":
    import sys
    
    # 默认路径
    graph_path = "output/pruned_graph.json"
    if not os.path.exists(graph_path):
        graph_path = "output/causal_graph.json"
    
    if os.path.exists(graph_path):
        print(f"[*] 加载因果图: {graph_path}")
        
        # 生成不同类型的文本
        for task in ["intent_analysis", "ttp_mapping", "report"]:
            output_path = f"output/prompt_{task}.txt"
            text = load_and_convert(graph_path, output_path, task)
            print(f"[+] 生成 {task} 提示词: {len(text)} 字符")
    else:
        print(f"[-] 因果图文件不存在: {graph_path}")
        print("[*] 请先运行 data_collector/main.py demo 生成因果图")
