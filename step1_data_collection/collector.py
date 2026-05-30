"""
第一步：数据汇聚器
从各数据源读取并汇聚告警数据
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Dict
from pathlib import Path

from .models import UnifiedAlert, AlertType
from .adapters import AdapterFactory


class DataCollector:
    """统一数据汇聚器"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()

    @staticmethod
    def _normalize_dt(value: Optional[datetime]) -> Optional[datetime]:
        """统一时间对象，避免 offset-aware 与 offset-naive 比较异常。"""
        if value is None:
            return None
        if value.tzinfo is not None and value.utcoffset() is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def _in_time_range(
        self,
        value: datetime,
        start_time: Optional[datetime],
        end_time: Optional[datetime]
    ) -> bool:
        """判断时间是否在给定窗口内。"""
        ts = self._normalize_dt(value)
        st = self._normalize_dt(start_time)
        et = self._normalize_dt(end_time)
        if st and ts < st:
            return False
        if et and ts > et:
            return False
        return True
    
    def _default_config(self) -> Dict:
        base_dir = Path(__file__).parent.parent
        return {
            "file_honeypot": {
                "db_path": str(base_dir / "alert_server" / "data" / "alert.db"),
                "type": "sqlite"
            },
            "account_honeypot": {
                "log_path": str(base_dir / "ssh-vpn" / "ssh_auth_log.json"),
                "type": "json"
            },
            "parasitic_honeypot": {
                "log_path": str(base_dir / "agent-go" / "log" / "url_alert.json"),
                "type": "json"
            },
            "audit_log": {
                "log_dir": str(base_dir / "agent-go" / "log"),
                "type": "file"
            }
        }
    
    def collect_all(self, start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """汇聚所有数据源"""
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        all_alerts = []
        
        file_alerts = self.collect_file_honeypot(start_time, end_time)
        all_alerts.extend(file_alerts)
        print(f"[+] 文件蜜点告警: {len(file_alerts)} 条")
        
        account_alerts = self.collect_account_honeypot(start_time, end_time)
        all_alerts.extend(account_alerts)
        print(f"[+] 账户蜜点告警: {len(account_alerts)} 条")
        
        parasitic_alerts = self.collect_parasitic_honeypot(start_time, end_time)
        all_alerts.extend(parasitic_alerts)
        print(f"[+] 寄生蜜点告警: {len(parasitic_alerts)} 条")
        
        audit_alerts = self.collect_audit_logs(start_time, end_time)
        all_alerts.extend(audit_alerts)
        print(f"[+] Audit日志: {len(audit_alerts)} 条")
        
        all_alerts.sort(key=lambda x: x.timestamp)
        return all_alerts
    
    def collect_file_honeypot(self, start_time=None, end_time=None) -> List[UnifiedAlert]:
        """收集文件蜜点告警"""
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        alerts = []
        config = self.config.get("file_honeypot", {})
        db_path = config.get("db_path")
        
        if not db_path or not os.path.exists(db_path):
            print(f"[-] 文件蜜点数据库不存在: {db_path}")
            return alerts
        
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM trigger_infos WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND trigger_time >= ?"
                params.append(start_time.isoformat())
            if end_time:
                query += " AND trigger_time <= ?"
                params.append(end_time.isoformat())
            
            query += " ORDER BY trigger_time DESC"
            cursor.execute(query, params)
            
            adapter = AdapterFactory.get_adapter(AlertType.FILE_HONEYPOT)
            for row in cursor.fetchall():
                for alert in adapter.parse(dict(row)):
                    if not self._in_time_range(alert.timestamp, start_time, end_time):
                        continue
                    alerts.append(alert)
            
            conn.close()
        except Exception as e:
            print(f"[-] 读取文件蜜点数据库失败: {e}")
        
        return alerts
    
    def collect_account_honeypot(self, start_time=None, end_time=None) -> List[UnifiedAlert]:
        """收集账户蜜点告警"""
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        alerts = []
        config = self.config.get("account_honeypot", {})
        log_path = config.get("log_path")
        
        if not log_path or not os.path.exists(log_path):
            print(f"[-] 账户蜜点日志不存在: {log_path}")
            return alerts
        
        try:
            adapter = AdapterFactory.get_adapter(AlertType.ACCOUNT_HONEYPOT)
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_data = json.loads(line)
                        for alert in adapter.parse(raw_data):
                            if not self._in_time_range(alert.timestamp, start_time, end_time):
                                continue
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[-] 读取账户蜜点日志失败: {e}")
        
        return alerts
    
    def collect_parasitic_honeypot(self, start_time=None, end_time=None) -> List[UnifiedAlert]:
        """收集寄生蜜点告警"""
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        alerts = []
        config = self.config.get("parasitic_honeypot", {})
        log_path = config.get("log_path")
        
        if not log_path or not os.path.exists(log_path):
            print(f"[-] 寄生蜜点日志不存在: {log_path}")
            return alerts
        
        try:
            adapter = AdapterFactory.get_adapter(AlertType.PARASITIC_HONEYPOT)
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    if content.startswith('['):
                        data_list = json.loads(content)
                    else:
                        data_list = []
                        for line in content.split('\n'):
                            if line.strip():
                                try:
                                    data_list.append(json.loads(line))
                                except:
                                    continue
                    
                    for raw_data in data_list:
                        for alert in adapter.parse(raw_data):
                            if not self._in_time_range(alert.timestamp, start_time, end_time):
                                continue
                            alerts.append(alert)
        except Exception as e:
            print(f"[-] 读取寄生蜜点日志失败: {e}")
        
        return alerts
    
    def collect_audit_logs(self, start_time=None, end_time=None) -> List[UnifiedAlert]:
        """收集audit日志"""
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        alerts = []
        config = self.config.get("audit_log", {})
        log_dir = config.get("log_dir")
        
        if not log_dir or not os.path.exists(log_dir):
            print(f"[-] Audit日志目录不存在: {log_dir}")
            return alerts
        
        try:
            adapter = AdapterFactory.get_adapter(AlertType.AUDIT_EVENT)
            for filename in os.listdir(log_dir):
                if filename.startswith("file_event_audit"):
                    filepath = os.path.join(log_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                raw_data = json.loads(line)
                                for alert in adapter.parse(raw_data):
                                    if not self._in_time_range(alert.timestamp, start_time, end_time):
                                        continue
                                    alerts.append(alert)
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            print(f"[-] 读取Audit日志失败: {e}")
        
        return alerts
    
    def save_alerts(self, alerts: List[UnifiedAlert], output_path: str):
        """保存告警数据"""
        data = [alert.to_dict() for alert in alerts]
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 已保存 {len(alerts)} 条告警到 {output_path}")
