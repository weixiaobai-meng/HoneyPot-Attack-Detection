"""
数据适配器 - 将各蜜点的原始数据转换为统一格式
"""

import json
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod

from models import UnifiedAlert, AlertType, AuditEventType


class BaseAdapter(ABC):
    """适配器基类"""
    
    @abstractmethod
    def parse(self, raw_data: Any) -> List[UnifiedAlert]:
        """解析原始数据为统一告警格式"""
        pass
    
    @staticmethod
    def generate_alert_id() -> str:
        """生成唯一告警ID"""
        return str(uuid.uuid4())


class FileHoneypotAdapter(BaseAdapter):
    """
    文件蜜点告警适配器
    数据来源: alert_server 的 TriggerInfo
    """
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析文件蜜点告警
        
        Args:
            raw_data: TriggerInfo 字典，包含:
                - Trigger_ip: 攻击者IP
                - Token: 文件token
                - Token_url: 文件URL
                - Trigger_time: 触发时间
                - Alert_msg: 告警信息
                - Trigger_agent: User-Agent
        """
        alerts = []
        
        alert = UnifiedAlert(
            alert_id=self.generate_alert_id(),
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=self._parse_time(raw_data.get("Trigger_time")),
            attacker_ip=raw_data.get("Trigger_ip"),
            attacker_info=raw_data.get("Trigger_agent"),
            target_path=raw_data.get("Token_url"),
            action="file_access",
            details={
                "token": raw_data.get("Token"),
                "alert_msg": raw_data.get("Alert_msg"),
                "company_id": raw_data.get("Company_id")
            }
        )
        alerts.append(alert)
        
        return alerts
    
    def _parse_time(self, time_str) -> datetime:
        """解析时间字符串"""
        if isinstance(time_str, datetime):
            return time_str
        try:
            return datetime.fromisoformat(str(time_str))
        except:
            return datetime.now()


class AccountHoneypotAdapter(BaseAdapter):
    """
    账户蜜点告警适配器
    数据来源: ssh-vpn 的 JSON 日志
    """
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析账户蜜点告警
        
        Args:
            raw_data: ssh-vpn 日志字典，包含:
                - src: 攻击者IP
                - spt: 源端口
                - dst: 目标IP
                - dpt: 目标端口
                - duser: 目标用户名
                - password: 尝试的密码
                - client_version: SSH客户端版本
                - time: 时间
                - protocol: 协议(SSH/VPN)
        """
        alerts = []
        
        # 判断是SSH还是VPN
        protocol = raw_data.get("protocol", "SSH")
        
        if protocol == "OpenVPN":
            # VPN连接尝试
            alert = UnifiedAlert(
                alert_id=self.generate_alert_id(),
                alert_type=AlertType.ACCOUNT_HONEYPOT,
                timestamp=self._parse_time(raw_data.get("time")),
                attacker_ip=raw_data.get("src"),
                target_host=raw_data.get("dst"),
                action="vpn_connect",
                details={
                    "protocol": "OpenVPN",
                    "raw_data": raw_data.get("raw_data"),
                    "src_port": raw_data.get("spt")
                }
            )
        else:
            # SSH登录尝试
            alert = UnifiedAlert(
                alert_id=self.generate_alert_id(),
                alert_type=AlertType.ACCOUNT_HONEYPOT,
                timestamp=self._parse_time(raw_data.get("time")),
                attacker_ip=raw_data.get("src"),
                attacker_info=raw_data.get("client_version"),
                target_host=raw_data.get("dst"),
                action="ssh_login",
                details={
                    "username": raw_data.get("duser"),
                    "password": raw_data.get("password"),
                    "src_port": raw_data.get("spt"),
                    "dst_port": raw_data.get("dpt"),
                    "client_version": raw_data.get("client_version"),
                    "server_version": raw_data.get("server_version")
                }
            )
        
        alerts.append(alert)
        return alerts
    
    def _parse_time(self, time_str) -> datetime:
        """解析时间字符串"""
        if isinstance(time_str, datetime):
            return time_str
        try:
            # 尝试ISO格式
            return datetime.fromisoformat(str(time_str).replace("Z", "+00:00"))
        except:
            return datetime.now()


class ParasiticHoneypotAdapter(BaseAdapter):
    """
    寄生蜜点告警适配器
    数据来源: agent-go 的 url_alert.json
    """
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析寄生蜜点告警
        
        Args:
            raw_data: UrlAlertMessage 字典，包含:
                - time: 时间戳(Unix)
                - ip: 攻击者IP
                - fingerprint: 浏览器指纹
                - details: 详细信息
        """
        alerts = []
        
        # 解析时间戳
        timestamp = raw_data.get("time")
        if isinstance(timestamp, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp)
        else:
            timestamp = datetime.now()
        
        alert = UnifiedAlert(
            alert_id=self.generate_alert_id(),
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=raw_data.get("ip"),
            attacker_info=raw_data.get("fingerprint"),
            action="url_access",
            details={
                "fingerprint": raw_data.get("fingerprint"),
                "access_details": raw_data.get("details")
            }
        )
        alerts.append(alert)
        
        return alerts


class AuditLogAdapter(BaseAdapter):
    """
    audit系统调用日志适配器
    数据来源: agent-go 的 audit 监控日志
    """
    
    # 系统调用映射
    SYSCALL_MAP = {
        "openat": AuditEventType.OPEN,
        "open": AuditEventType.OPEN,
        "read": AuditEventType.READ,
        "write": AuditEventType.WRITE,
        "unlink": AuditEventType.DELETE,
        "unlinkat": AuditEventType.DELETE,
        "rename": AuditEventType.RENAME,
        "renameat": AuditEventType.RENAME,
        "mkdir": AuditEventType.MKDIR,
        "chmod": AuditEventType.CHMOD,
        "fchmod": AuditEventType.CHMOD,
        "execve": AuditEventType.EXECVE,
        "fork": AuditEventType.FORK,
        "clone": AuditEventType.FORK,
        "connect": AuditEventType.CONNECT,
    }
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析audit日志
        
        Args:
            raw_data: MonitorEvent 字典，包含:
                - id: 事件ID
                - event_type_id: 事件类型ID
                - event_type: 事件类型名称(系统调用名)
                - event_time: 事件时间
                - user: 用户
                - proc: 进程路径
                - pid: 进程ID
                - pproc: 父进程ID
                - args: 参数
                - path: 文件路径
                - data: 原始数据
        """
        alerts = []
        
        # 映射事件类型
        event_type_str = raw_data.get("event_type", "unknown")
        event_type = self.SYSCALL_MAP.get(event_type_str, AuditEventType.UNKNOWN)
        
        # 解析时间
        event_time = raw_data.get("event_time")
        if isinstance(event_time, (int, float)):
            event_time = datetime.fromtimestamp(event_time)
        elif isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time)
            except:
                event_time = datetime.now()
        else:
            event_time = datetime.now()
        
        alert = UnifiedAlert(
            alert_id=raw_data.get("id", self.generate_alert_id()),
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=event_time,
            target_path=raw_data.get("path"),
            action=event_type.value,
            details={
                "event_type_id": raw_data.get("event_type_id"),
                "args": raw_data.get("args"),
                "raw_data": raw_data.get("data")
            },
            process_info={
                "pid": raw_data.get("pid"),
                "ppid": raw_data.get("pproc"),
                "exe": raw_data.get("proc"),
                "user": raw_data.get("user")
            }
        )
        alerts.append(alert)
        
        return alerts


class AdapterFactory:
    """适配器工厂"""
    
    _adapters = {
        AlertType.FILE_HONEYPOT: FileHoneypotAdapter,
        AlertType.ACCOUNT_HONEYPOT: AccountHoneypotAdapter,
        AlertType.PARASITIC_HONEYPOT: ParasiticHoneypotAdapter,
        AlertType.AUDIT_EVENT: AuditLogAdapter,
    }
    
    @classmethod
    def get_adapter(cls, alert_type: AlertType) -> BaseAdapter:
        """获取适配器实例"""
        adapter_class = cls._adapters.get(alert_type)
        if not adapter_class:
            raise ValueError(f"Unknown alert type: {alert_type}")
        return adapter_class()
    
    @classmethod
    def register_adapter(cls, alert_type: AlertType, adapter_class: type):
        """注册新的适配器"""
        cls._adapters[alert_type] = adapter_class
