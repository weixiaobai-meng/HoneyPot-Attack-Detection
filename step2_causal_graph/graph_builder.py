"""
第二步：因果图构建器
将告警数据转换为因果三元组和有向图
"""

import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field

import networkx as nx


@dataclass
class CausalEdge:
    """因果边"""
    edge_id: str
    subject_type: str          # process/file/network
    subject_id: str            # 进程PID/文件路径/IP
    action: str                # 系统调用/操作类型
    object_type: str           # process/file/network
    object_id: str             # 目标PID/文件路径/IP
    timestamp: datetime
    raw_data: Dict = field(default_factory=dict)
    
    def to_triple(self) -> Tuple[str, str, str]:
        """转换为三元组"""
        return (f"{self.subject_type}:{self.subject_id}", 
                self.action, 
                f"{self.object_type}:{self.object_id}")


class CausalGraphBuilder:
    """因果图构建器"""
    
    def __init__(self):
        self.nodes = {}
        self.edges = []
    
    def build_from_alerts(self, alerts: list) -> Dict:
        """
        从告警列表构建因果图
        
        Args:
            alerts: UnifiedAlert列表
            
        Returns:
            因果图字典
        """
        for alert in alerts:
            edges = self._alert_to_edges(alert)
            self.edges.extend(edges)
        
        return self.to_dict()
    
    def _alert_to_edges(self, alert) -> List[CausalEdge]:
        """将告警转换为因果边"""
        alert_type = alert.alert_type.value if hasattr(alert, 'alert_type') else alert.get("alert_type")
        
        if alert_type == "file":
            return self._file_to_edges(alert)
        elif alert_type == "account":
            return self._account_to_edges(alert)
        elif alert_type == "parasitic":
            return self._parasitic_to_edges(alert)
        elif alert_type == "audit":
            return self._audit_to_edges(alert)
        return []
    
    def _file_to_edges(self, alert) -> List[CausalEdge]:
        """文件蜜点 → 因果边"""
        ip = alert.attacker_ip if hasattr(alert, 'attacker_ip') else alert.get("attacker_ip")
        path = alert.target_path if hasattr(alert, 'target_path') else alert.get("target_path")
        timestamp = alert.timestamp if hasattr(alert, 'timestamp') else alert.get("timestamp")
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        edge = CausalEdge(
            edge_id=str(uuid.uuid4()),
            subject_type="network",
            subject_id=ip or "unknown",
            action="file_access",
            object_type="file",
            object_id=path or "unknown",
            timestamp=timestamp or datetime.now()
        )
        
        self._add_node("network", ip, {"ip": ip})
        self._add_node("file", path, {"path": path})
        
        return [edge]
    
    def _account_to_edges(self, alert) -> List[CausalEdge]:
        """账户蜜点 → 因果边"""
        ip = alert.attacker_ip if hasattr(alert, 'attacker_ip') else alert.get("attacker_ip")
        host = alert.target_host if hasattr(alert, 'target_host') else alert.get("target_host")
        action = alert.action if hasattr(alert, 'action') else alert.get("action")
        timestamp = alert.timestamp if hasattr(alert, 'timestamp') else alert.get("timestamp")
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        edge = CausalEdge(
            edge_id=str(uuid.uuid4()),
            subject_type="network",
            subject_id=ip or "unknown",
            action=action or "ssh_login",
            object_type="network",
            object_id=host or "unknown",
            timestamp=timestamp or datetime.now()
        )
        
        self._add_node("network", ip, {"ip": ip})
        self._add_node("network", host, {"ip": host})
        
        return [edge]
    
    def _parasitic_to_edges(self, alert) -> List[CausalEdge]:
        """寄生蜜点 → 因果边"""
        ip = alert.attacker_ip if hasattr(alert, 'attacker_ip') else alert.get("attacker_ip")
        timestamp = alert.timestamp if hasattr(alert, 'timestamp') else alert.get("timestamp")
        details = alert.details if hasattr(alert, 'details') else alert.get("details", {})
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        fingerprint = details.get("fingerprint", "unknown") if isinstance(details, dict) else "unknown"
        
        edge = CausalEdge(
            edge_id=str(uuid.uuid4()),
            subject_type="network",
            subject_id=ip or "unknown",
            action="url_access",
            object_type="file",
            object_id=f"honeypot_url:{fingerprint}",
            timestamp=timestamp or datetime.now()
        )
        
        self._add_node("network", ip, {"ip": ip})
        
        return [edge]
    
    def _audit_to_edges(self, alert) -> List[CausalEdge]:
        """audit日志 → 因果边"""
        action = alert.action if hasattr(alert, 'action') else alert.get("action")
        target = alert.target_path if hasattr(alert, 'target_path') else alert.get("target_path")
        process_info = alert.process_info if hasattr(alert, 'process_info') else alert.get("process_info", {})
        timestamp = alert.timestamp if hasattr(alert, 'timestamp') else alert.get("timestamp")
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        if not process_info:
            return []
        
        pid = process_info.get("pid", "unknown")
        ppid = process_info.get("ppid", "unknown")
        exe = process_info.get("exe", "unknown")
        
        process_id = f"process:{pid}"
        self._add_node("process", process_id, {"pid": pid, "exe": exe})
        
        edges = []
        
        if action in ["openat", "read", "write", "unlink"]:
            file_id = f"file:{target}"
            edges.append(CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=process_id,
                action=action,
                object_type="file",
                object_id=file_id,
                timestamp=timestamp or datetime.now()
            ))
            self._add_node("file", file_id, {"path": target})
            
        elif action in ["execve", "fork"]:
            child_id = f"process:{pid}"
            parent_id = f"process:{ppid}"
            edges.append(CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=parent_id,
                action=action,
                object_type="process",
                object_id=child_id,
                timestamp=timestamp or datetime.now()
            ))
            self._add_node("process", parent_id, {"pid": ppid})
            
        elif action == "connect":
            network_id = f"network:{target}"
            edges.append(CausalEdge(
                edge_id=str(uuid.uuid4()),
                subject_type="process",
                subject_id=process_id,
                action="connect",
                object_type="network",
                object_id=network_id,
                timestamp=timestamp or datetime.now()
            ))
            self._add_node("network", network_id, {})
        
        return edges
    
    def _add_node(self, node_type: str, node_id: str, attributes: Dict):
        """添加节点"""
        if node_id and node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                **attributes
            }
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "nodes": list(self.nodes.values()),
            "edges": [
                {
                    "source": edge.subject_id,
                    "target": edge.object_id,
                    "action": edge.action,
                    "timestamp": edge.timestamp.isoformat() if isinstance(edge.timestamp, datetime) else str(edge.timestamp),
                    "subject_type": edge.subject_type,
                    "object_type": edge.object_type
                }
                for edge in self.edges
            ],
            "triples": [edge.to_triple() for edge in self.edges]
        }
    
    def save(self, output_path: str):
        """保存因果图"""
        data = self.to_dict()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 因果图已保存到: {output_path}")
        print(f"    节点数: {len(data['nodes'])}")
        print(f"    边数: {len(data['edges'])}")
