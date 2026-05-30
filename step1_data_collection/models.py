"""
第一步：统一告警数据模型
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


@dataclass
class UnifiedAlert:
    """统一告警数据结构"""
    alert_id: str                          # 唯一标识
    alert_type: AlertType                  # 告警类型
    timestamp: datetime                    # 时间戳
    attacker_ip: Optional[str] = None      # 攻击者IP
    attacker_info: Optional[str] = None    # 攻击者其他信息
    target_host: Optional[str] = None      # 目标主机
    target_path: Optional[str] = None      # 目标路径/文件
    action: Optional[str] = None           # 动作类型
    details: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None       # 会话ID
    process_info: Optional[Dict] = None    # 进程信息(audit)
    
    def to_dict(self) -> Dict:
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
        return json.dumps(self.to_dict(), ensure_ascii=False)
