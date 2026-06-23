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

        url_value = details.get("path") or details.get("url") or raw_data.get("url")
        session_token = details.get("session_token") or raw_data.get("session_token")
        real_ips = details.get("real_ips") or details.get("ips") or raw_data.get("real_ips") or raw_data.get("ips") or []
        if not isinstance(real_ips, list):
            real_ips = [real_ips] if real_ips else []
        proxy_detect_result = details.get("proxy_detect_result") or details.get("ProxyDetectResult") or raw_data.get("proxy_detect_result")
        x_forwarded_for = details.get("x_forwarded_for") or raw_data.get("x_forwarded_for")
        forwarded = details.get("forwarded") or raw_data.get("forwarded")
        via = details.get("via") or raw_data.get("via")
        possible_proxy = details.get("possible_proxy")
        if possible_proxy is None:
            possible_proxy = raw_data.get("possible_proxy")
        if possible_proxy is None:
            possible_proxy = bool(
                x_forwarded_for
                or forwarded
                or via
                or str(proxy_detect_result or "").strip().lower() == "true"
            )
        bot_score = details.get("bot_score", details.get("score", raw_data.get("bot_score", raw_data.get("score", 0))))
        is_bot = details.get("is_bot", raw_data.get("is_bot", False))
        browser = details.get("browser") or details.get("browserName") or raw_data.get("browser")
        os_name = details.get("os") or details.get("osName") or raw_data.get("os")
        browser_platform = details.get("browser_platform") or details.get("platform") or details.get("navigatorPlatform") or raw_data.get("browser_platform")
        user_agent = details.get("user_agent") or details.get("userAgent") or details.get("ua") or raw_data.get("user_agent")
        reason = details.get("reason") or raw_data.get("reason")
        proxy_note = details.get("proxy_note") or raw_data.get("proxy_note")
        
        alert = UnifiedAlert(
            alert_id=self.generate_alert_id(),
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=raw_data.get("ip"),
            attacker_info=raw_data.get("fingerprint"),
            action="url_access",
            target_path=url_value,
            session_id=session_token,
            source_type="browser",
            source_id=f"browser:{raw_data.get('fingerprint')}" if raw_data.get("fingerprint") else "browser:unknown",
            source_label=raw_data.get("fingerprint") or "unknown browser fingerprint",
            object_type="url",
            object_id=f"url:{url_value}" if url_value else "url:unknown",
            object_label=url_value or "unknown url",
            stage="reconnaissance",
            tactic="Reconnaissance",
            technique="Honey Web Resource Access",
            severity="medium",
            confidence=0.88,
            details={
                "fingerprint": raw_data.get("fingerprint"),
                "url": url_value,
                "session_token": session_token,
                "real_ips": real_ips,
                "proxy_detect_result": proxy_detect_result,
                "possible_proxy": possible_proxy,
                "x_forwarded_for": x_forwarded_for,
                "forwarded": forwarded,
                "via": via,
                "bot_score": bot_score,
                "is_bot": is_bot,
                "browser": browser,
                "os": os_name,
                "browser_platform": browser_platform,
                "user_agent": user_agent,
                "reason": reason,
                "proxy_note": proxy_note,
                "access_details": details
            },
            evidence={
                "fingerprint": raw_data.get("fingerprint"),
                "ip": raw_data.get("ip"),
                "url": url_value,
                "session_token": session_token,
                "real_ips": real_ips,
                "proxy_detect_result": proxy_detect_result,
                "possible_proxy": possible_proxy,
                "bot_score": bot_score,
                "is_bot": is_bot,
                "browser": browser,
                "os": os_name,
                "browser_platform": browser_platform,
                "user_agent": user_agent,
                "details": details,
            },
        )
        return [alert]
