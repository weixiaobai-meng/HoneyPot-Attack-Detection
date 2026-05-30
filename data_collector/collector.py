"""
数据汇聚器 - 从各数据源读取并汇聚告警数据
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from models import UnifiedAlert, AlertType
from adapters import AdapterFactory


class DataCollector:
    """
    统一数据汇聚器
    负责从各蜜点数据源读取原始数据，转换为统一格式
    """
    
    def __init__(self, config: Dict = None):
        """
        初始化汇聚器
        
        Args:
            config: 配置字典，包含各数据源的路径
        """
        self.config = config or self._default_config()
        self.adapters = {
            AlertType.FILE_HONEYPOT: AdapterFactory.get_adapter(AlertType.FILE_HONEYPOT),
            AlertType.ACCOUNT_HONEYPOT: AdapterFactory.get_adapter(AlertType.ACCOUNT_HONEYPOT),
            AlertType.PARASITIC_HONEYPOT: AdapterFactory.get_adapter(AlertType.PARASITIC_HONEYPOT),
            AlertType.AUDIT_EVENT: AdapterFactory.get_adapter(AlertType.AUDIT_EVENT),
        }
    
    def _default_config(self) -> Dict:
        """默认配置"""
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
    
    def collect_all(self, 
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """
        汇聚所有数据源的告警
        
        Args:
            start_time: 开始时间过滤
            end_time: 结束时间过滤
            
        Returns:
            统一格式的告警列表
        """
        all_alerts = []
        
        # 收集文件蜜点告警
        file_alerts = self.collect_file_honeypot(start_time, end_time)
        all_alerts.extend(file_alerts)
        print(f"[+] 文件蜜点告警: {len(file_alerts)} 条")
        
        # 收集账户蜜点告警
        account_alerts = self.collect_account_honeypot(start_time, end_time)
        all_alerts.extend(account_alerts)
        print(f"[+] 账户蜜点告警: {len(account_alerts)} 条")
        
        # 收集寄生蜜点告警
        parasitic_alerts = self.collect_parasitic_honeypot(start_time, end_time)
        all_alerts.extend(parasitic_alerts)
        print(f"[+] 寄生蜜点告警: {len(parasitic_alerts)} 条")
        
        # 收集audit日志
        audit_alerts = self.collect_audit_logs(start_time, end_time)
        all_alerts.extend(audit_alerts)
        print(f"[+] Audit日志: {len(audit_alerts)} 条")
        
        # 按时间排序
        all_alerts.sort(key=lambda x: x.timestamp)
        
        return all_alerts
    
    def collect_file_honeypot(self, 
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """
        收集文件蜜点告警
        
        从alert_server的SQLite数据库读取TriggerInfo
        """
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
            
            # 查询TriggerInfo表
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
            rows = cursor.fetchall()
            
            for row in rows:
                raw_data = dict(row)
                alert_list = self.adapters[AlertType.FILE_HONEYPOT].parse(raw_data)
                alerts.extend(alert_list)
            
            conn.close()
        except Exception as e:
            print(f"[-] 读取文件蜜点数据库失败: {e}")
        
        return alerts
    
    def collect_account_honeypot(self,
                                 start_time: Optional[datetime] = None,
                                 end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """
        收集账户蜜点告警
        
        从ssh-vpn的JSON日志文件读取
        """
        alerts = []
        config = self.config.get("account_honeypot", {})
        log_path = config.get("log_path")
        
        if not log_path or not os.path.exists(log_path):
            print(f"[-] 账户蜜点日志不存在: {log_path}")
            return alerts
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_data = json.loads(line)
                        alert_list = self.adapters[AlertType.ACCOUNT_HONEYPOT].parse(raw_data)
                        for alert in alert_list:
                            if start_time and alert.timestamp < start_time:
                                continue
                            if end_time and alert.timestamp > end_time:
                                continue
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[-] 读取账户蜜点日志失败: {e}")
        
        return alerts
    
    def collect_parasitic_honeypot(self,
                                   start_time: Optional[datetime] = None,
                                   end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """
        收集寄生蜜点告警
        
        从agent-go的url_alert.json读取
        """
        alerts = []
        config = self.config.get("parasitic_honeypot", {})
        log_path = config.get("log_path")
        
        if not log_path or not os.path.exists(log_path):
            print(f"[-] 寄生蜜点日志不存在: {log_path}")
            return alerts
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    # 可能是JSON数组或每行一个JSON
                    if content.startswith('['):
                        data_list = json.loads(content)
                    else:
                        data_list = []
                        for line in content.split('\n'):
                            line = line.strip()
                            if line:
                                try:
                                    data_list.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                    
                    for raw_data in data_list:
                        alert_list = self.adapters[AlertType.PARASITIC_HONEYPOT].parse(raw_data)
                        for alert in alert_list:
                            if start_time and alert.timestamp < start_time:
                                continue
                            if end_time and alert.timestamp > end_time:
                                continue
                            alerts.append(alert)
        except Exception as e:
            print(f"[-] 读取寄生蜜点日志失败: {e}")
        
        return alerts
    
    def collect_audit_logs(self,
                           start_time: Optional[datetime] = None,
                           end_time: Optional[datetime] = None) -> List[UnifiedAlert]:
        """
        收集audit系统调用日志
        
        从agent-go的日志目录读取audit事件文件
        """
        alerts = []
        config = self.config.get("audit_log", {})
        log_dir = config.get("log_dir")
        
        if not log_dir or not os.path.exists(log_dir):
            print(f"[-] Audit日志目录不存在: {log_dir}")
            return alerts
        
        try:
            # 查找所有audit事件日志文件
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
                                alert_list = self.adapters[AlertType.AUDIT_EVENT].parse(raw_data)
                                for alert in alert_list:
                                    if start_time and alert.timestamp < start_time:
                                        continue
                                    if end_time and alert.timestamp > end_time:
                                        continue
                                    alerts.append(alert)
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            print(f"[-] 读取Audit日志失败: {e}")
        
        return alerts
    
    def save_unified_alerts(self, alerts: List[UnifiedAlert], output_path: str):
        """
        保存汇聚后的统一告警数据
        
        Args:
            alerts: 统一告警列表
            output_path: 输出文件路径
        """
        data = [alert.to_dict() for alert in alerts]
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"[+] 已保存 {len(alerts)} 条告警到 {output_path}")


class AlertAggregator:
    """
    告警聚合器 - 将同一攻击者的事件关联起来
    """
    
    def __init__(self, time_window_seconds: int = 300):
        """
        Args:
            time_window_seconds: 时间窗口(秒)，用于关联同一会话的事件
        """
        self.time_window = time_window_seconds
    
    def aggregate_by_ip(self, alerts: List[UnifiedAlert]) -> Dict[str, List[UnifiedAlert]]:
        """
        按攻击者IP聚合告警
        
        Returns:
            {ip: [alerts]} 字典
        """
        ip_groups = {}
        for alert in alerts:
            ip = alert.attacker_ip or "unknown"
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(alert)
        
        # 按时间排序
        for ip in ip_groups:
            ip_groups[ip].sort(key=lambda x: x.timestamp)
        
        return ip_groups
    
    def create_sessions(self, alerts: List[UnifiedAlert]) -> Dict[str, List[UnifiedAlert]]:
        """
        创建攻击会话 - 将时间窗口内的事件关联为同一会话
        
        Returns:
            {session_id: [alerts]} 字典
        """
        # 先按IP分组
        ip_groups = self.aggregate_by_ip(alerts)
        
        sessions = {}
        session_counter = 0
        
        for ip, ip_alerts in ip_groups.items():
            current_session = []
            session_start = None
            
            for alert in ip_alerts:
                if session_start is None:
                    # 新会话
                    session_counter += 1
                    session_id = f"session_{ip}_{session_counter}"
                    session_start = alert.timestamp
                    current_session = [alert]
                    alert.session_id = session_id
                else:
                    # 检查是否在时间窗口内
                    time_diff = (alert.timestamp - session_start).total_seconds()
                    if time_diff <= self.time_window:
                        # 同一会话
                        current_session.append(alert)
                        alert.session_id = sessions.get(session_counter, {}).get("session_id")
                    else:
                        # 新会话
                        if current_session:
                            sessions[f"session_{ip}_{session_counter}"] = current_session
                        session_counter += 1
                        session_id = f"session_{ip}_{session_counter}"
                        session_start = alert.timestamp
                        current_session = [alert]
                        alert.session_id = session_id
            
            # 保存最后一组
            if current_session:
                sessions[f"session_{ip}_{session_counter}"] = current_session
        
        return sessions


if __name__ == "__main__":
    # 测试汇聚功能
    collector = DataCollector()
    
    # 汇聚所有数据
    alerts = collector.collect_all()
    
    # 保存到文件
    output_path = "output/unified_alerts.json"
    collector.save_unified_alerts(alerts, output_path)
    
    # 按IP聚合
    aggregator = AlertAggregator()
    ip_groups = aggregator.aggregate_by_ip(alerts)
    
    print("\n[*] 按IP聚合结果:")
    for ip, ip_alerts in ip_groups.items():
        print(f"  {ip}: {len(ip_alerts)} 条告警")
