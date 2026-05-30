"""
文件蜜点告警适配器
数据来源: alert_server 的 TriggerInfo
"""

from datetime import datetime
from typing import List, Dict, Any

from .base import BaseAdapter
from ..models import UnifiedAlert, AlertType


class FileHoneypotAdapter(BaseAdapter):
    """文件蜜点告警适配器"""
    
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
        trigger_time = raw_data.get("Trigger_time", raw_data.get("trigger_time"))
        trigger_ip = raw_data.get("Trigger_ip", raw_data.get("trigger_ip"))
        token_url = raw_data.get("Token_url", raw_data.get("token_url"))
        trigger_agent = raw_data.get("Trigger_agent", raw_data.get("trigger_agent"))
        token = raw_data.get("Token", raw_data.get("token"))
        alert_msg = raw_data.get("Alert_msg", raw_data.get("alert_msg"))
        company_id = raw_data.get("Company_id", raw_data.get("company_id"))

        alert = UnifiedAlert(
            alert_id=self.generate_alert_id(),
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=self._parse_time(trigger_time),
            attacker_ip=trigger_ip,
            attacker_info=trigger_agent,
            target_path=token_url,
            action="file_access",
            details={
                "token": token,
                "alert_msg": alert_msg,
                "company_id": company_id
            }
        )
        return [alert]
    
    def _parse_time(self, time_str) -> datetime:
        if isinstance(time_str, datetime):
            return time_str
        if isinstance(time_str, (int, float)):
            try:
                return datetime.fromtimestamp(time_str)
            except:
                return datetime.now()
        try:
            return datetime.fromisoformat(str(time_str))
        except:
            return datetime.now()
