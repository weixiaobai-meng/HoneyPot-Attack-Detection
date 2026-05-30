"""
数据汇聚模块配置
"""

import os
from pathlib import Path

# 基础路径
BASE_DIR = Path(__file__).parent.parent

# 数据源配置
DATA_SOURCES = {
    # 文件蜜点 - alert_server 数据库
    "file_honeypot": {
        "db_path": str(BASE_DIR / "alert_server" / "data" / "alert.db"),
        "type": "sqlite"
    },
    
    # 账户蜜点 - ssh-vpn 日志
    "account_honeypot": {
        "log_path": str(BASE_DIR / "ssh-vpn" / "ssh_auth_log.json"),
        "type": "json"
    },
    
    # 寄生蜜点 - agent-go url_alert
    "parasitic_honeypot": {
        "log_path": str(BASE_DIR / "agent-go" / "log" / "url_alert.json"),
        "type": "json"
    },
    
    # audit系统调用日志
    "audit_log": {
        "log_dir": str(BASE_DIR / "agent-go" / "log"),
        "pattern": "file_event_audit*",
        "type": "file"
    }
}

# 输出配置
OUTPUT_DIR = str(BASE_DIR / "data_collector" / "output")
UNIFIED_ALERTS_FILE = os.path.join(OUTPUT_DIR, "unified_alerts.json")
CAUSAL_GRAPH_FILE = os.path.join(OUTPUT_DIR, "causal_graph.json")

# 会话聚合配置
SESSION_TIME_WINDOW = 300  # 5分钟内的事件视为同一会话

# 日志配置
LOG_LEVEL = "INFO"
LOG_FILE = str(BASE_DIR / "data_collector" / "collector.log")
