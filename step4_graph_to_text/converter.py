"""
Step 4: convert provenance graph into thesis-oriented textual narrative.
"""

import os
from datetime import datetime
from typing import List, Dict
from collections import Counter, defaultdict

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

    ACTION_DESCRIPTIONS_CN = {
        "ssh_login": "SSH 弱口令/远程登录尝试",
        "vpn_connect": "VPN 连接尝试",
        "file_access": "诱饵文件访问",
        "url_access": "寄生蜜点页面访问",
        "openat": "文件打开",
        "read": "文件读取",
        "write": "文件写入",
        "execve": "进程执行",
        "fork": "进程派生",
        "connect": "网络连接",
        "unlink": "文件删除",
        "rename": "文件重命名",
        "chmod": "权限修改",
        "mkdir": "目录创建",
        "correlates_to": "同源关联",
    }

    TTP_MAPPING = {
        "ssh_login": ("Initial Access", "External Remote Services", "T1133"),
        "vpn_connect": ("Initial Access", "External Remote Services", "T1133"),
        "url_access": ("Reconnaissance", "Honey Web Resource Access", "custom-parasitic-web"),
        "file_access": ("Collection", "Honey File Access", "custom-honey-file"),
        "connect": ("Command and Control", "Application Layer Protocol", "T1071"),
        "execve": ("Execution", "Command and Scripting Interpreter", "T1059"),
        "read": ("Collection", "Data from Local System", "T1005"),
        "openat": ("Collection", "Data from Local System", "T1005"),
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

    def convert_to_thesis_analysis(self, graph_data: Dict) -> str:
        """Generate a deterministic Chinese thesis-oriented analysis draft."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        meta = graph_data.get("graph_meta", {})
        attacker_groups = graph_data.get("attacker_groups", [])
        attack_paths = graph_data.get("attack_paths", [])
        pruning_stats = graph_data.get("pruning_stats", {})

        event_edges = [edge for edge in edges if edge.get("edge_kind") == "event"]
        correlation_edges = [edge for edge in edges if edge.get("edge_kind") == "correlation"]
        action_counts = Counter(edge.get("action") or "unknown" for edge in event_edges)
        stage_counts = Counter(edge.get("stage") or "unknown" for edge in event_edges)
        severity_counts = Counter(edge.get("severity") or "unknown" for edge in event_edges)
        cross_groups = [
            group for group in attacker_groups
            if len(set(group.get("event_types") or [])) >= 2
        ]
        three_type_groups = [
            group for group in attacker_groups
            if {"account", "file", "parasitic"}.issubset(set(group.get("event_types") or []))
        ]

        lines = [
            "# 多蜜点告警关联分析草稿",
            "",
            "## 1. 实验输入与图规模",
            "",
            (
                f"本次分析以统一告警事件为输入，构建攻击溯源图。图中包含 "
                f"{meta.get('node_count', len(nodes))} 个节点、"
                f"{meta.get('edge_count', len(edges))} 条边，其中事件边 "
                f"{meta.get('event_edge_count', len(event_edges))} 条，"
                f"关联边 {meta.get('correlation_edge_count', len(correlation_edges))} 条。"
            ),
            (
                f"系统共重建 {meta.get('attacker_count', len(attacker_groups))} 个攻击者簇和 "
                f"{meta.get('path_count', len(attack_paths))} 条攻击路径。"
            ),
            "",
            "## 2. 蜜点行为分布",
            "",
            self._format_counter("行为类型", action_counts, self.ACTION_DESCRIPTIONS_CN),
            "",
            self._format_counter("攻击阶段", stage_counts),
            "",
            self._format_counter("告警等级", severity_counts),
            "",
            "## 3. 跨蜜点同源证据",
            "",
        ]

        if cross_groups:
            lines.append(
                f"攻击者聚类结果中有 {len(cross_groups)} 个簇覆盖至少两类蜜点，"
                f"其中 {len(three_type_groups)} 个簇同时覆盖账户、文件和寄生三类蜜点。"
            )
            lines.append("")
            for group in cross_groups[:5]:
                lines.append(
                    f"- {group.get('attacker_id')}: 事件数={group.get('event_count')}, "
                    f"类型={', '.join(group.get('event_types') or [])}, "
                    f"锚点={', '.join(group.get('anchors') or []) or '无'}, "
                    f"时间={group.get('start_time')} -> {group.get('end_time')}"
                )
            if len(cross_groups) > 5:
                lines.append(f"- 其余 {len(cross_groups) - 5} 个跨蜜点攻击者簇已省略。")
        else:
            lines.append("当前图中尚未形成覆盖多类蜜点的同源攻击者簇，后续应继续补充文件蜜点和寄生蜜点样本。")

        lines.extend([
            "",
            "## 4. 攻击路径还原",
            "",
        ])
        if attack_paths:
            for path in sorted(attack_paths, key=lambda item: item.get("event_count", 0), reverse=True)[:5]:
                lines.append(
                    f"- {path.get('path_id')}: 攻击者={path.get('attacker_id') or 'unknown'}, "
                    f"事件数={path.get('event_count')}, "
                    f"类型={', '.join(path.get('event_types') or [])}, "
                    f"锚点={', '.join(path.get('anchors') or []) or '无'}"
                )
        else:
            lines.append("- 当前剪枝图未保留可还原的攻击路径。")

        lines.extend([
            "",
            "## 5. TTP 映射",
            "",
            "| 行为 | 战术 | 技术 | 编号 | 样本数 |",
            "|---|---|---|---|---:|",
        ])
        for action, count in sorted(action_counts.items()):
            tactic, technique, ttp_id = self.TTP_MAPPING.get(
                action,
                ("Unknown", self.ACTION_DESCRIPTIONS_CN.get(action, action), "custom-unknown"),
            )
            lines.append(
                f"| {self.ACTION_DESCRIPTIONS_CN.get(action, action)} | {tactic} | {technique} | {ttp_id} | {count} |"
            )

        lines.extend([
            "",
            "## 6. 图剪枝效果",
            "",
        ])
        if pruning_stats:
            lines.append(
                f"剪枝模式为 `{pruning_stats.get('mode', 'unknown')}`，原始边数 "
                f"{pruning_stats.get('original_edges', len(edges))}，保留边数 "
                f"{pruning_stats.get('kept_edges', len(edges))}，剪除边数 "
                f"{pruning_stats.get('pruned_edges', 0)}，压缩率 "
                f"{pruning_stats.get('compression_ratio', '0.0%')}。"
            )
            if pruning_stats.get("fallback_reason"):
                lines.append(f"本轮 DQN 未直接生效，回退原因：`{pruning_stats.get('fallback_reason')}`。")
        else:
            lines.append("当前图未记录剪枝统计信息。")

        lines.extend([
            "",
            "## 7. 可写入论文的结论表述",
            "",
            (
                "实验表明，统一告警模型能够把账户蜜点、文件蜜点和寄生蜜点产生的异构日志转化为统一事件，"
                "并进一步构建包含事件边与同源关联边的攻击溯源图。"
            ),
            (
                "当同一来源 IP、浏览器指纹、会话标识或 actor group 在不同蜜点之间重复出现时，"
                "系统能够将离散告警聚合为攻击者簇，并形成跨蜜点攻击路径，为后续攻击意图推断提供结构化证据。"
            ),
            (
                "需要注意的是，受真实公网暴露面影响，三类蜜点天然存在样本不平衡。论文中应将自然采集集、"
                "受控触发集和平衡分析集分开描述，避免把受控触发样本表述为自然攻击流量。"
            ),
        ])
        return "\n".join(lines)

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

    def _format_counter(self, title: str, counter: Counter, label_map: Dict[str, str] = None) -> str:
        lines = [f"**{title}：**"]
        if not counter:
            lines.append("- 无")
            return "\n".join(lines)
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], str(item[0]))):
            label = label_map.get(key, key) if label_map else key
            lines.append(f"- {label}: {count}")
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
