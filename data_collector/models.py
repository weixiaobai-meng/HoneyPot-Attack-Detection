"""
统一告警数据模型
汇聚三种蜜点(文件、账户、寄生)的告警数据 + audit系统调用日志
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import json


class AlertType(Enum):
    """告警类型枚举"""
    FILE_HONEYPOT = "file"        # 文件蜜点
    ACCOUNT_HONEYPOT = "account"  # 账户蜜点
    PARASITIC_HONEYPOT = "parasitic"  # 寄生蜜点
    AUDIT_EVENT = "audit"         # audit系统调用


class AuditEventType(Enum):
    """audit事件类型"""
    OPEN = "openat"
    READ = "read"
    WRITE = "write"
    DELETE = "unlink"
    RENAME = "rename"
    MKDIR = "mkdir"
    CHMOD = "chmod"
    EXECVE = "execve"
    FORK = "fork"
    CONNECT = "connect"
    UNKNOWN = "unknown"


@dataclass
class UnifiedAlert:
    """统一告警数据结构"""
    # 基础信息
    alert_id: str                          # 唯一标识
    alert_type: AlertType                  # 告警类型
    timestamp: datetime                    # 时间戳
    
    # 攻击者信息
    attacker_ip: Optional[str] = None      # 攻击者IP
    attacker_info: Optional[str] = None    # 攻击者其他信息(User-Agent等)
    
    # 目标信息
    target_host: Optional[str] = None      # 目标主机
    target_path: Optional[str] = None      # 目标路径/文件
    
    # 事件详情
    action: Optional[str] = None           # 动作(系统调用/登录/访问)
    details: Dict[str, Any] = field(default_factory=dict)  # 原始详情
    
    # 关联信息
    session_id: Optional[str] = None       # 会话ID(用于关联同一攻击者的事件)
    process_info: Optional[Dict] = None    # 进程信息(audit)
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "timestamp": self.timestamp.isoformat(),
            "attacker_ip": self.attacker_ip,
            "attacker_info": self.attacker_info,
            "target_host": self.target_host,
            "target_path": self.target_path,
            "action": self.action,
            "details": self.details,
            "session_id": self.session_id,
            "process_info": self.process_info
        }
    
    def to_json(self) -> str:
        """转换为JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class ProcessNode:
    """进程节点(用于因果图)"""
    pid: str
    ppid: str
    exe: str
    user: str
    start_time: Optional[datetime] = None


@dataclass
class FileNode:
    """文件节点(用于因果图)"""
    path: str
    inode: Optional[str] = None
    owner: Optional[str] = None


@dataclass
class NetworkNode:
    """网络节点(用于因果图)"""
    ip: str
    port: Optional[int] = None
    direction: Optional[str] = None  # inbound/outbound


@dataclass
class CausalEdge:
    """因果边(Subject -> Action -> Object)"""
    edge_id: str
    subject_type: str          # process/file/network
    subject_id: str            # 进程PID/文件路径/IP
    action: str                # 系统调用/操作类型
    object_type: str           # process/file/network
    object_id: str             # 目标PID/文件路径/IP
    timestamp: datetime
    raw_alert: Optional[UnifiedAlert] = None  # 原始告警
    
    def to_triple(self) -> tuple:
        """转换为三元组 (Subject, Action, Object)"""
        return (f"{self.subject_type}:{self.subject_id}", 
                self.action, 
                f"{self.object_type}:{self.object_id}")


@dataclass
class AttackGraph:
    """攻击图谱"""
    graph_id: str
    nodes: List[Dict] = field(default_factory=list)
    edges: List[CausalEdge] = field(default_factory=list)
    alerts: List[UnifiedAlert] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    def add_edge(self, edge: CausalEdge):
        """添加边"""
        self.edges.append(edge)
        # 添加节点
        src_node = {"id": edge.subject_id, "type": edge.subject_type}
        dst_node = {"id": edge.object_id, "type": edge.object_type}
        if src_node not in self.nodes:
            self.nodes.append(src_node)
        if dst_node not in self.nodes:
            self.nodes.append(dst_node)
    
    def get_triples(self) -> List[tuple]:
        """获取所有三元组"""
        return [edge.to_triple() for edge in self.edges]
