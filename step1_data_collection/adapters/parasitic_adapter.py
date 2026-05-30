"""
寄生蜜点告警适配器
数据来源: agent-go 的 url_alert.json
"""

from datetime import datetime
from typing import List, Dict, Any

from .base import BaseAdapter
from ..models import UnifiedAlert, AlertType


class ParasiticHoneypotAdapter(BaseAdapter):
    """寄生蜜点告警适配器"""
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析寄生蜜点告警
        
        Args:
            raw_data: UrlAlertMessage 字典
        """
        timestamp = raw_data.get("time")
        if isinstance(timestamp, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()

        details = raw_data.get("details", {})
        if not isinstance(details, dict):
            details = {}

        url_value = details.get("path") or details.get("url")
        
        alert = UnifiedAlert(
            alert_id=self.generate_alert_id(),
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=raw_data.get("ip"),
            attacker_info=raw_data.get("fingerprint"),
            action="url_access",
            target_path=url_value,
            details={
                "fingerprint": raw_data.get("fingerprint"),
                "url": url_value,
                "access_details": details
            }
        )
        return [alert]
