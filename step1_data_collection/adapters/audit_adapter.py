"""
audit系统调用日志适配器
数据来源: agent-go 的 audit 监控日志
"""

from datetime import datetime
from typing import List, Dict, Any

from .base import BaseAdapter
from ..models import UnifiedAlert, AlertType


class AuditLogAdapter(BaseAdapter):
    """audit系统调用日志适配器"""
    
    SYSCALL_MAP = {
        "openat": "openat",
        "open": "openat",
        "read": "read",
        "write": "write",
        "unlink": "unlink",
        "unlinkat": "unlink",
        "rename": "rename",
        "renameat": "rename",
        "mkdir": "mkdir",
        "chmod": "chmod",
        "execve": "execve",
        "fork": "fork",
        "clone": "fork",
        "connect": "connect",
    }
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析audit日志
        
        Args:
            raw_data: MonitorEvent 字典
        """
        event_type_str = raw_data.get("event_type", "unknown")
        event_type = self.SYSCALL_MAP.get(event_type_str, "unknown")
        
        event_time = raw_data.get("event_time")
        if isinstance(event_time, (int, float)):
            event_time = datetime.fromtimestamp(event_time)
        elif isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            except:
                event_time = datetime.now()
        else:
            event_time = datetime.now()
        
        alert = UnifiedAlert(
            alert_id=raw_data.get("id", self.generate_alert_id()),
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=event_time,
            target_path=raw_data.get("path"),
            action=event_type,
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
        return [alert]
