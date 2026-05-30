"""
适配器基类
"""

import uuid
from abc import ABC, abstractmethod
from typing import List, Any

from ..models import UnifiedAlert, AlertType


class BaseAdapter(ABC):
    """适配器基类"""
    
    @abstractmethod
    def parse(self, raw_data: Any) -> List[UnifiedAlert]:
        """解析原始数据为统一告警格式"""
        pass
    
    @staticmethod
    def generate_alert_id() -> str:
        return str(uuid.uuid4())


class AdapterFactory:
    """适配器工厂"""
    
    _adapters = {}
    
    @classmethod
    def get_adapter(cls, alert_type: AlertType) -> BaseAdapter:
        if alert_type not in cls._adapters:
            from .file_adapter import FileHoneypotAdapter
            from .account_adapter import AccountHoneypotAdapter
            from .parasitic_adapter import ParasiticHoneypotAdapter
            from .audit_adapter import AuditLogAdapter
            
            cls._adapters = {
                AlertType.FILE_HONEYPOT: FileHoneypotAdapter(),
                AlertType.ACCOUNT_HONEYPOT: AccountHoneypotAdapter(),
                AlertType.PARASITIC_HONEYPOT: ParasiticHoneypotAdapter(),
                AlertType.AUDIT_EVENT: AuditLogAdapter(),
            }
        
        adapter = cls._adapters.get(alert_type)
        if not adapter:
            raise ValueError(f"Unknown alert type: {alert_type}")
        return adapter
