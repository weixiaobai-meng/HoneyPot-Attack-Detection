"""
账户蜜点告警适配器
数据来源: ssh-vpn 的 JSON 日志
"""

from datetime import datetime
from typing import List, Dict, Any

from .base import BaseAdapter
from ..models import UnifiedAlert, AlertType


class AccountHoneypotAdapter(BaseAdapter):
    """账户蜜点告警适配器"""
    
    def parse(self, raw_data: Dict) -> List[UnifiedAlert]:
        """
        解析账户蜜点告警
        
        Args:
            raw_data: ssh-vpn 日志字典
        """
        protocol = raw_data.get("protocol", "SSH")
        
        if protocol == "OpenVPN":
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
        
        return [alert]
    
    def _parse_time(self, time_str) -> datetime:
        if isinstance(time_str, datetime):
            return time_str
        try:
            return datetime.fromisoformat(str(time_str).replace("Z", "+00:00"))
        except:
            return datetime.now()
