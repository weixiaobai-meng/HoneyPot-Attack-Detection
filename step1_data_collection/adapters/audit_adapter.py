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
        
        source_type = "process"
        source_id = self._build_source_id(event_type, raw_data)
        source_label = self._build_source_label(event_type, raw_data)

        alert = UnifiedAlert(
            alert_id=raw_data.get("id", self.generate_alert_id()),
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=event_time,
            target_path=raw_data.get("path"),
            action=event_type,
            source_type=source_type,
            source_id=source_id,
            source_label=source_label,
            object_type=self._infer_object_type(event_type, raw_data),
            object_id=self._build_object_id(event_type, raw_data),
            object_label=self._build_object_label(event_type, raw_data),
            stage=self._infer_stage(event_type),
            tactic=self._infer_tactic(event_type),
            technique=self._infer_technique(event_type),
            severity=self._infer_severity(event_type),
            confidence=0.92,
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
            },
            evidence={
                "path": raw_data.get("path"),
                "args": raw_data.get("args"),
                "data": raw_data.get("data"),
            },
        )
        return [alert]

    def _build_source_id(self, event_type: str, raw_data: Dict) -> str:
        if event_type in {"execve", "fork"} and raw_data.get("pproc") is not None:
            return f"process:{raw_data.get('pproc')}"
        if raw_data.get("pid") is not None:
            return f"process:{raw_data.get('pid')}"
        return "process:unknown"

    def _build_source_label(self, event_type: str, raw_data: Dict) -> str:
        if event_type in {"execve", "fork"} and raw_data.get("pproc") is not None:
            return f"parent_pid:{raw_data.get('pproc')}"
        return raw_data.get("proc") or f"pid:{raw_data.get('pid', 'unknown')}"

    def _infer_object_type(self, event_type: str, raw_data: Dict) -> str:
        if event_type in {"execve", "fork"}:
            return "process"
        if event_type == "connect":
            return "network"
        return "file"

    def _build_object_id(self, event_type: str, raw_data: Dict) -> str:
        path = raw_data.get("path")
        if event_type == "fork":
            return f"process:{raw_data.get('pid')}" if raw_data.get("pid") is not None else "process:unknown"
        if event_type == "execve":
            return f"process:{raw_data.get('pid')}" if raw_data.get("pid") is not None else "process:unknown"
        if event_type == "connect":
            target = raw_data.get("path") or raw_data.get("dst") or raw_data.get("target")
            return f"network:{target}" if target else "network:unknown"
        return f"file:{path}" if path else "file:unknown"

    def _build_object_label(self, event_type: str, raw_data: Dict) -> str:
        if event_type in {"execve", "fork"}:
            return raw_data.get("proc") or f"pid:{raw_data.get('pid', 'unknown')}"
        if event_type == "connect":
            return raw_data.get("path") or raw_data.get("dst") or raw_data.get("target") or "unknown network target"
        return raw_data.get("path") or "unknown file target"

    def _infer_stage(self, event_type: str) -> str:
        mapping = {
            "openat": "execution",
            "read": "collection",
            "write": "persistence",
            "unlink": "defense_evasion",
            "rename": "defense_evasion",
            "mkdir": "persistence",
            "chmod": "privilege_escalation",
            "execve": "execution",
            "fork": "execution",
            "connect": "command_and_control",
        }
        return mapping.get(event_type, "execution")

    def _infer_tactic(self, event_type: str) -> str:
        mapping = {
            "openat": "Execution",
            "read": "Collection",
            "write": "Persistence",
            "unlink": "Defense Evasion",
            "rename": "Defense Evasion",
            "mkdir": "Persistence",
            "chmod": "Privilege Escalation",
            "execve": "Execution",
            "fork": "Execution",
            "connect": "Command and Control",
        }
        return mapping.get(event_type, "Execution")

    def _infer_technique(self, event_type: str) -> str:
        mapping = {
            "openat": "File Discovery",
            "read": "Data from Local System",
            "write": "Modify Authentication Process",
            "unlink": "Indicator Removal on Host",
            "rename": "Indicator Removal on Host",
            "mkdir": "Create or Modify System Process",
            "chmod": "Abuse Elevation Control Mechanism",
            "execve": "Command and Scripting Interpreter",
            "fork": "System Services",
            "connect": "Application Layer Protocol",
        }
        return mapping.get(event_type, "Unknown Technique")

    def _infer_severity(self, event_type: str) -> str:
        if event_type in {"connect", "chmod", "unlink", "write"}:
            return "high"
        if event_type in {"execve", "fork", "read"}:
            return "medium"
        return "low"
