"""
因果图构建模块
将汇聚的告警数据转换为 Subject → Action → Object 的有向因果图
"""

import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict

import networkx as nx

from models import (
    UnifiedAlert, AlertType, CausalEdge, AttackGraph,
    ProcessNode, FileNode, NetworkNode
)


class CausalGraphBuilder:
    """
    因果图构建器
    将统一告警数据转换为有向无环因果溯源图
    """
    
    def __init__(self):
        self.nodes = {}  # {node_id: node_info}
        self.edges = []  # CausalEdge列表
        self.alert_mapping = {}  # alert_id -> edge_ids
        
    def build_from_alerts(self, alerts: List[UnifiedAlert]) -> AttackGraph:
        """
        从告警列表构建攻击图谱
        
        Args:
            alerts: 统一告警列表
            
        Returns:
            AttackGraph对象
        """
        graph = AttackGraph(
            graph_id=str(uuid.uuid4()),
            start_time=alerts[0].timestamp if alerts else None,
            end_time=alerts[-1].timestamp if alerts else None
        )
        
        for alert in alerts:
            edges = self._alert_to_edges(alert)
            for edge in edges:
                graph.add_edge(edge)
                self.edges.append(edge)
                # 记录映射关系
                if alert.alert_id not in self.alert_mapping:
                    self.alert_mapping[alert.alert_id] = []
                self.alert_mapping[alert.alert_id].append(edge.edge_id)
        
        graph.alerts = alerts
        return graph
    
    def _alert_to_edges(self, alert: UnifiedAlert) -> List[CausalEdge]:
        """
        将单个告警转换为因果边
        
        根据告警类型生成不同的三元组:
        - 文件蜜点: attacker_process → file_access → target_file
        - 账户蜜点: attacker → ssh_login → target_host
        - 寄生蜜点: crawler → url_access → honey_url
        - audit日志: process → syscall → file/process
        """
        edges = []
        
        if alert.alert_type == AlertType.FILE_HONEYPOT:
            edges.extend(self._file_honeypot_to_edges(alert))
        elif alert.alert_type == AlertType.ACCOUNT_HONEYPOT:
            edges.extend(self._account_honeypot_to_edges(alert))
        elif alert.alert_type == AlertType.PARASITIC_HONEYPOT:
            edges.extend(self._parasitic_honeypot_to_edges(alert))
        elif alert.alert_type == AlertType.AUDIT_EVENT:
            edges.extend(self._audit_to_edges(alert))
        
        return edges
    
    def _file_honeypot_to_edges(self, alert: UnifiedAlert) -> List[CausalEdge]:
        """文件蜜点告警 → 因果边"""
        edges = []
        
        # 外部IP → 访问 → 蜜点文件
        edge = CausalEdge(
            edge_id=str(uuid.uuid4()),
            subject_type="network",
            subject_id=alert.attacker_ip or "unknown",
            action="file_access",
            object_type="file",
            object_id=alert.target_path or "unknown",
            timestamp=alert.timestamp,
            raw_alert=alert
        )
        edges.append(edge)
        
        # 记录节点
        self._add_node("network", alert.attacker_ip or "unknown", {
            "type": "external_ip",
            "ip": alert.attacker_ip
        })
        self._add_node("file", alert.target_path or "unknown", {
            "type": "honeypot_file",
            "path": alert.target_path
        })
        
        return edges
    
    def _account_honeypot_to_edges(self, alert: UnifiedAlert) -> List[CausalEdge]:
        """账户蜜点告警 → 因果边"""
        edges = []
        
        if alert.action == "ssh_login":
            # 外部IP → SSH登录 → 目标主机
            edge = CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="network",
                subject_id=alert.attacker_ip or "unknown",
                action="ssh_login",
                object_type="network",
                object_id=alert.target_host or "unknown",
                timestamp=alert.timestamp,
                raw_alert=alert
            )
            edges.append(edge)
            
            # 记录节点
            self._add_node("network", alert.attacker_ip or "unknown", {
                "type": "attacker_ip",
                "ip": alert.attacker_ip
            })
            self._add_node("network", alert.target_host or "unknown", {
                "type": "honeypot_host",
                "ip": alert.target_host,
                "username": alert.details.get("username")
            })
            
        elif alert.action == "vpn_connect":
            # 外部IP → VPN连接 → 目标主机
            edge = CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="network",
                subject_id=alert.attacker_ip or "unknown",
                action="vpn_connect",
                object_type="network",
                object_id=alert.target_host or "unknown",
                timestamp=alert.timestamp,
                raw_alert=alert
            )
            edges.append(edge)
        
        return edges
    
    def _parasitic_honeypot_to_edges(self, alert: UnifiedAlert) -> List[CausalEdge]:
        """寄生蜜点告警 → 因果边"""
        edges = []
        
        # 爬虫/机器人 → 访问 → 蜜点URL
        edge = CausalEdge(
            edge_id=str(uuid.uuid4()),
            subject_type="network",
            subject_id=alert.attacker_ip or "unknown",
            action="url_access",
            object_type="file",
            object_id=f"honeypot_url:{alert.details.get('fingerprint', 'unknown')}",
            timestamp=alert.timestamp,
            raw_alert=alert
        )
        edges.append(edge)
        
        # 记录节点
        self._add_node("network", alert.attacker_ip or "unknown", {
            "type": "crawler",
            "ip": alert.attacker_ip,
            "fingerprint": alert.details.get("fingerprint")
        })
        
        return edges
    
    def _audit_to_edges(self, alert: UnifiedAlert) -> List[CausalEdge]:
        """
        audit系统调用日志 → 因果边
        
        这是最复杂的转换，需要根据系统调用类型生成不同的边:
        - openat/read/write: process → file
        - execve: parent_process → child_process
        - connect: process → network
        """
        edges = []
        
        if not alert.process_info:
            return edges
        
        pid = alert.process_info.get("pid", "unknown")
        ppid = alert.process_info.get("ppid", "unknown")
        exe = alert.process_info.get("exe", "unknown")
        
        # 记录进程节点
        process_id = f"process:{pid}"
        self._add_node("process", process_id, {
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "user": alert.process_info.get("user")
        })
        
        if alert.action in ["openat", "open", "read", "write", "unlink", "rename", "chmod"]:
            # 文件操作: process → file
            file_path = alert.target_path or "unknown"
            file_id = f"file:{file_path}"
            
            edge = CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=process_id,
                action=alert.action,
                object_type="file",
                object_id=file_id,
                timestamp=alert.timestamp,
                raw_alert=alert
            )
            edges.append(edge)
            
            # 记录文件节点
            self._add_node("file", file_id, {
                "path": file_path,
                "type": "file"
            })
            
        elif alert.action in ["execve", "fork", "clone"]:
            # 进程创建: parent_process → child_process
            child_process_id = f"process:{pid}"
            parent_process_id = f"process:{ppid}"
            
            edge = CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=parent_process_id,
                action=alert.action,
                object_type="process",
                object_id=child_process_id,
                timestamp=alert.timestamp,
                raw_alert=alert
            )
            edges.append(edge)
            
            # 记录父进程节点
            self._add_node("process", parent_process_id, {
                "pid": ppid,
                "type": "process"
            })
            
        elif alert.action == "connect":
            # 网络连接: process → network
            # 从details中提取目标IP和端口
            dest_ip = alert.details.get("dest_ip", "unknown")
            dest_port = alert.details.get("dest_port", "unknown")
            network_id = f"network:{dest_ip}:{dest_port}"
            
            edge = CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=process_id,
                action="connect",
                object_type="network",
                object_id=network_id,
                timestamp=alert.timestamp,
                raw_alert=alert
            )
            edges.append(edge)
            
            # 记录网络节点
            self._add_node("network", network_id, {
                "ip": dest_ip,
                "port": dest_port,
                "type": "network_connection"
            })
        
        # 如果有父进程信息，添加 fork 边
        if ppid and ppid != "0" and ppid != pid:
            parent_id = f"process:{ppid}"
            if alert.action not in ["execve", "fork", "clone"]:
                edge = CausalEdge(
                    edge_id=str(uuid.uuid4()),
                    subject_type="process",
                    subject_id=parent_id,
                    action="fork",
                    object_type="process",
                    object_id=process_id,
                    timestamp=alert.timestamp,
                    raw_alert=alert
                )
                edges.append(edge)
        
        return edges
    
    def _add_node(self, node_type: str, node_id: str, attributes: Dict):
        """添加节点"""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                **attributes
            }


class CausalGraph:
    """
    因果图类 - 使用NetworkX构建有向图
    """
    
    def __init__(self):
        self.G = nx.DiGraph()
        self.edge_alert_map = {}  # edge_id -> alert
        
    def build_from_attack_graph(self, attack_graph: AttackGraph):
        """
        从AttackGraph构建NetworkX有向图
        
        Args:
            attack_graph: AttackGraph对象
        """
        # 添加节点
        for node in attack_graph.nodes:
            self.G.add_node(node["id"], **node)
        
        # 添加边
        for edge in attack_graph.edges:
            self.G.add_edge(
                edge.subject_id,
                edge.object_id,
                edge_id=edge.edge_id,
                action=edge.action,
                timestamp=edge.timestamp.isoformat() if edge.timestamp else None,
                subject_type=edge.subject_type,
                object_type=edge.object_type
            )
            self.edge_alert_map[edge.edge_id] = edge.raw_alert
    
    def get_triples(self) -> List[Tuple[str, str, str]]:
        """
        获取所有三元组 (Subject, Action, Object)
        """
        triples = []
        for u, v, data in self.G.edges(data=True):
            subject = f"{data.get('subject_type', 'unknown')}:{u}"
            action = data.get('action', 'unknown')
            obj = f"{data.get('object_type', 'unknown')}:{v}"
            triples.append((subject, action, obj))
        return triples
    
    def get_subgraph_by_ip(self, ip: str) -> 'CausalGraph':
        """
        获取与特定IP相关的子图
        """
        related_nodes = set()
        
        # 查找包含该IP的所有节点
        for node, attrs in self.G.nodes(data=True):
            if attrs.get('ip') == ip or node == ip:
                related_nodes.add(node)
        
        # 查找相关边
        for u, v, data in self.G.edges(data=True):
            if u in related_nodes or v in related_nodes:
                related_nodes.add(u)
                related_nodes.add(v)
        
        # 创建子图
        subgraph = CausalGraph()
        subgraph.G = self.G.subgraph(related_nodes).copy()
        
        return subgraph
    
    def get_attack_paths(self, source: str = None) -> List[List[str]]:
        """
        获取攻击路径（从源节点到叶节点的所有路径）
        """
        # 找到所有叶节点（出度为0的节点）
        leaf_nodes = [n for n in self.G.nodes() if self.G.out_degree(n) == 0]
        
        paths = []
        if source:
            # 从指定源到所有叶节点的路径
            for leaf in leaf_nodes:
                try:
                    for path in nx.all_simple_paths(self.G, source, leaf):
                        paths.append(list(path))
                except nx.NetworkXError:
                    continue
        else:
            # 找到所有入度为0的节点作为源
            source_nodes = [n for n in self.G.nodes() if self.G.in_degree(n) == 0]
            for src in source_nodes:
                for leaf in leaf_nodes:
                    try:
                        for path in nx.all_simple_paths(self.G, src, leaf):
                            paths.append(list(path))
                    except nx.NetworkXError:
                        continue
        
        return paths
    
    def get_statistics(self) -> Dict:
        """
        获取图的统计信息
        """
        stats = {
            "num_nodes": self.G.number_of_nodes(),
            "num_edges": self.G.number_of_edges(),
            "num_connected_components": nx.number_weakly_connected_components(self.G),
            "avg_degree": sum(dict(self.G.degree()).values()) / max(self.G.number_of_nodes(), 1),
            "node_types": {},
            "edge_types": {}
        }
        
        # 统计节点类型
        for _, attrs in self.G.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            stats["node_types"][node_type] = stats["node_types"].get(node_type, 0) + 1
        
        # 统计边类型
        for _, _, attrs in self.G.edges(data=True):
            action = attrs.get('action', 'unknown')
            stats["edge_types"][action] = stats["edge_types"].get(action, 0) + 1
        
        return stats
    
    def to_dict(self) -> Dict:
        """
        转换为字典格式
        """
        return {
            "nodes": [
                {"id": node, **attrs}
                for node, attrs in self.G.nodes(data=True)
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    **attrs
                }
                for u, v, attrs in self.G.edges(data=True)
            ],
            "triples": self.get_triples(),
            "statistics": self.get_statistics()
        }
    
    def save(self, filepath: str):
        """
        保存图到文件
        """
        data = self.to_dict()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 因果图已保存到: {filepath}")
    
    @classmethod
    def load(cls, filepath: str) -> 'CausalGraph':
        """
        从文件加载图
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        graph = cls()
        
        # 添加节点
        for node in data.get("nodes", []):
            node_id = node.pop("id")
            graph.G.add_node(node_id, **node)
        
        # 添加边
        for edge in data.get("edges", []):
            source = edge.pop("source")
            target = edge.pop("target")
            graph.G.add_edge(source, target, **edge)
        
        return graph


class CausalGraphVisualizer:
    """
    因果图可视化器
    """
    
    # 节点颜色配置
    NODE_COLORS = {
        "process": "#FF6B6B",     # 红色
        "file": "#4ECDC4",        # 青色
        "network": "#45B7D1",     # 蓝色
        "unknown": "#95A5A6"      # 灰色
    }
    
    # 边颜色配置
    EDGE_COLORS = {
        "file_access": "#FF6B6B",
        "ssh_login": "#FFA07A",
        "url_access": "#FFD700",
        "openat": "#98FB98",
        "read": "#87CEEB",
        "write": "#DDA0DD",
        "execve": "#FF69B4",
        "fork": "#FF1493",
        "connect": "#00CED1"
    }
    
    @staticmethod
    def to_mermaid(graph: CausalGraph, title: str = "Attack Graph") -> str:
        """
        转换为Mermaid格式（可在Markdown中渲染）
        """
        lines = [f"graph TD"]
        lines.append(f"    %% {title}")
        lines.append("")
        
        # 添加节点
        for node, attrs in graph.G.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            label = attrs.get('exe') or attrs.get('path') or attrs.get('ip') or node
            # 截断长标签
            if len(str(label)) > 20:
                label = str(label)[:17] + "..."
            
            if node_type == "process":
                lines.append(f"    {node}[\"{label}\"]")
            elif node_type == "file":
                lines.append(f"    {node}[\"{label}\"]")
            else:
                lines.append(f"    {node}(\"{label}\")")
        
        lines.append("")
        
        # 添加边
        for u, v, attrs in graph.G.edges(data=True):
            action = attrs.get('action', 'unknown')
            lines.append(f"    {u} -->|{action}| {v}")
        
        return "\n".join(lines)
    
    @staticmethod
    def to_dot(graph: CausalGraph, title: str = "Attack Graph") -> str:
        """
        转换为DOT格式（Graphviz）
        """
        lines = ["digraph AttackGraph {"]
        lines.append(f'    label="{title}";')
        lines.append('    node [shape=box, style=filled];')
        lines.append("")
        
        # 添加节点
        for node, attrs in graph.G.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            color = CausalGraphVisualizer.NODE_COLORS.get(node_type, "#95A5A6")
            label = attrs.get('exe') or attrs.get('path') or attrs.get('ip') or node
            lines.append(f'    "{node}" [label="{label}", fillcolor="{color}"];')
        
        lines.append("")
        
        # 添加边
        for u, v, attrs in graph.G.edges(data=True):
            action = attrs.get('action', 'unknown')
            color = CausalGraphVisualizer.EDGE_COLORS.get(action, "#666666")
            lines.append(f'    "{u}" -> "{v}" [label="{action}", color="{color}"];')
        
        lines.append("}")
        
        return "\n".join(lines)


def build_causal_graph(alerts: List[UnifiedAlert]) -> CausalGraph:
    """
    便捷函数：从告警列表构建因果图
    """
    # 1. 构建AttackGraph
    builder = CausalGraphBuilder()
    attack_graph = builder.build_from_alerts(alerts)
    
    # 2. 转换为NetworkX图
    causal_graph = CausalGraph()
    causal_graph.build_from_attack_graph(attack_graph)
    
    return causal_graph


if __name__ == "__main__":
    # 测试因果图构建
    from adapters import AdapterFactory
    from models import AlertType
    
    # 创建测试数据
    test_alerts = [
        UnifiedAlert(
            alert_id="1",
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            attacker_ip="192.168.1.100",
            target_path="/home/bait/password.xlsx",
            action="file_access"
        ),
        UnifiedAlert(
            alert_id="2",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 35, 0),
            attacker_ip="192.168.1.100",
            target_host="192.168.1.20",
            action="ssh_login",
            details={"username": "root", "password": "admin123"}
        ),
        UnifiedAlert(
            alert_id="3",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=datetime(2024, 1, 15, 10, 31, 0),
            action="openat",
            target_path="/home/bait/password.xlsx",
            process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "root"}
        ),
        UnifiedAlert(
            alert_id="4",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=datetime(2024, 1, 15, 10, 32, 0),
            action="execve",
            target_path="/usr/bin/cat",
            process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "root"}
        ),
    ]
    
    # 构建因果图
    graph = build_causal_graph(test_alerts)
    
    # 打印统计信息
    stats = graph.get_statistics()
    print("\n[*] 因果图统计:")
    print(f"  节点数: {stats['num_nodes']}")
    print(f"  边数: {stats['num_edges']}")
    print(f"  连通分量: {stats['num_connected_components']}")
    print(f"  节点类型: {stats['node_types']}")
    print(f"  边类型: {stats['edge_types']}")
    
    # 打印三元组
    print("\n[*] 三元组:")
    for triple in graph.get_triples():
        print(f"  {triple[0]} --[{triple[1]}]--> {triple[2]}")
    
    # 保存图
    graph.save("output/causal_graph.json")
    
    # 输出Mermaid格式
    print("\n[*] Mermaid格式:")
    print(CausalGraphVisualizer.to_mermaid(graph))
