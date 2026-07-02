"""
适配器基类
"""

import uuid
from abc import ABC, abstractmethod
from typing import List, Any

from ..campaign import campaign_metadata, extract_campaign_id
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

    @staticmethod
    def attach_campaign_metadata(alert: UnifiedAlert, *sources: Any) -> UnifiedAlert:
        campaign_id = extract_campaign_id(*(sources or (alert.details, alert.evidence)))
        if not campaign_id:
            return alert

        meta = campaign_metadata(campaign_id)
        alert.campaign_id = campaign_id
        alert.scenario_id = meta.get("scenario_id")
        alert.scenario_role = meta.get("scenario_role")
        alert.details = dict(alert.details or {})
        alert.evidence = dict(alert.evidence or {})
        alert.details.update(meta)
        alert.evidence.setdefault("campaign_id", campaign_id)
        alert.evidence.setdefault("scenario_id", meta.get("scenario_id"))
        alert.evidence.setdefault("scenario_role", meta.get("scenario_role"))
        return alert


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
