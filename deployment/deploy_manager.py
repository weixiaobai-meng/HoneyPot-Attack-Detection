"""
部署管理模块
统一管理蜜点系统的部署、启动和数据采集

组件结构:
deployment/
├── config/
│   ├── deployment.json       # 部署配置
│   └── components.json       # 组件配置
├── alerts/                   # 收集的告警数据
│   ├── file_alerts.json      # 文件蜜点告警
│   ├── account_alerts.json   # 账户蜜点告警
│   ├── parasitic_alerts.json # 寄生蜜点告警
│   └── audit_alerts.json     # audit日志
├── output/                   # 输出目录
│   └── collected_alerts.json # 汇聚后的告警
└── deploy_manager.py         # 部署管理脚本

关联组件 (位于项目根目录):
├── systemwire2/              # 管理端
├── alert_server/             # 告警服务
├── agent-go/                 # 探针
├── ssh-vpn/                  # SSH蜜罐
└── js/                       # 寄生蜜点脚本
"""

import os
import sys
import json
import glob
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class DeploymentManager:
    """部署管理器"""
    
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or Path(__file__).parent.parent
        self.deployment_dir = Path(__file__).parent
        self.output_dir = self.deployment_dir / "output"
        self.alerts_dir = self.deployment_dir / "alerts"
        self.config_dir = self.deployment_dir / "config"
        
        # 确保目录存在
        self.output_dir.mkdir(exist_ok=True)
        self.alerts_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        
        # 加载组件配置
        self.components = self._load_components()
    
    def _load_components(self):
        """加载组件配置"""
        config_path = self.config_dir / "components.json"
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    
    def check_components(self):
        """检查各组件是否存在"""
        print("\n" + "=" * 70)
        print("  检查系统组件")
        print("=" * 70)
        
        results = {}
        for name, config in self.components.get("components", {}).items():
            path = self.base_dir / config["path"].lstrip("../")
            exists = path.exists()
            status = "✓ 存在" if exists else "✗ 缺失"
            print(f"  [{status}] {name}: {path}")
            results[name] = exists
        
        return results
    
    def collect_file_alerts(self):
        """收集文件蜜点告警 (从alert_server)"""
        print("\n  收集文件蜜点告警...")
        
        alerts = []
        
        # 尝试从alert_server的SQLite数据库读取
        db_path = self.base_dir / "alert_server" / "data" / "alert.db"
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # 查询最近24小时的告警
                time_threshold = (datetime.now() - timedelta(hours=24)).isoformat()
                cursor.execute("""
                    SELECT * FROM trigger_infos 
                    WHERE trigger_time > ? 
                    ORDER BY trigger_time DESC
                """, (time_threshold,))
                
                for row in cursor.fetchall():
                    alerts.append({
                        "alert_id": f"file_{row['id']}",
                        "alert_type": "file",
                        "timestamp": row['trigger_time'],
                        "attacker_ip": row['trigger_ip'],
                        "target_path": row['token_url'],
                        "action": "file_access",
                        "details": {
                            "token": row['token'],
                            "alert_msg": row['alert_msg'],
                            "user_agent": row['trigger_agent']
                        }
                    })
                
                conn.close()
                print(f"    从数据库读取 {len(alerts)} 条告警")
            except Exception as e:
                print(f"    数据库读取失败: {e}")
        
        # 保存
        output_path = self.alerts_dir / "file_alerts.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        
        return alerts
    
    def collect_account_alerts(self):
        """收集账户蜜点告警 (从ssh-vpn)"""
        print("\n  收集账户蜜点告警...")
        
        alerts = []
        max_lines = 1000  # 限制读取行数
        
        # 从ssh-vpn的日志文件读取
        log_path = self.base_dir / "ssh-vpn" / "ssh_auth_log.json"
        if log_path.exists():
            try:
                # 检查文件大小
                file_size = log_path.stat().st_size
                if file_size > 10 * 1024 * 1024:  # 大于10MB
                    print(f"    文件较大 ({file_size / 1024 / 1024:.1f}MB)，只读取最近{max_lines}行")
                
                with open(log_path, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f):
                        if i >= max_lines:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            alerts.append({
                                "alert_id": f"account_{len(alerts)+1}",
                                "alert_type": "account",
                                "timestamp": data.get("time", datetime.now().isoformat()),
                                "attacker_ip": data.get("src"),
                                "target_host": data.get("dst"),
                                "action": "ssh_login",
                                "details": {
                                    "username": data.get("duser"),
                                    "password": data.get("password"),
                                    "client_version": data.get("client_version"),
                                    "src_port": data.get("spt"),
                                    "dst_port": data.get("dpt")
                                }
                            })
                        except json.JSONDecodeError:
                            continue
                print(f"    从日志文件读取 {len(alerts)} 条告警")
            except Exception as e:
                print(f"    日志文件读取失败: {e}")
        
        # 保存
        output_path = self.alerts_dir / "account_alerts.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        
        return alerts
    
    def collect_parasitic_alerts(self):
        """收集寄生蜜点告警 (从agent-go)"""
        print("\n  收集寄生蜜点告警...")
        
        alerts = []
        
        # 从agent-go的日志文件读取
        log_path = self.base_dir / "agent-go" / "log" / "url_alert.json"
        if log_path.exists():
            try:
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
                        
                        for data in data_list:
                            timestamp = data.get("time")
                            if isinstance(timestamp, (int, float)):
                                timestamp = datetime.fromtimestamp(timestamp).isoformat()
                            
                            alerts.append({
                                "alert_id": f"parasitic_{len(alerts)+1}",
                                "alert_type": "parasitic",
                                "timestamp": timestamp,
                                "attacker_ip": data.get("ip"),
                                "action": "url_access",
                                "details": {
                                    "fingerprint": data.get("fingerprint"),
                                    "url": data.get("details", {}).get("path"),
                                    "info": data.get("details")
                                }
                            })
                print(f"    从日志文件读取 {len(alerts)} 条告警")
            except Exception as e:
                print(f"    日志文件读取失败: {e}")
        
        # 保存
        output_path = self.alerts_dir / "parasitic_alerts.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        
        return alerts
    
    def collect_audit_alerts(self):
        """收集audit日志 (从agent-go)"""
        print("\n  收集audit日志...")
        
        alerts = []
        
        # 从agent-go的日志目录读取
        log_dir = self.base_dir / "agent-go" / "log"
        if log_dir.exists():
            try:
                for log_file in log_dir.glob("file_event_audit*.log"):
                    with open(log_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                
                                # 解析时间
                                event_time = data.get("event_time")
                                if isinstance(event_time, (int, float)):
                                    event_time = datetime.fromtimestamp(event_time).isoformat()
                                
                                alerts.append({
                                    "alert_id": data.get("id", f"audit_{len(alerts)+1}"),
                                    "alert_type": "audit",
                                    "timestamp": event_time,
                                    "action": data.get("event_type", "unknown"),
                                    "target_path": data.get("path"),
                                    "process_info": {
                                        "pid": data.get("pid"),
                                        "ppid": data.get("pproc"),
                                        "exe": data.get("proc"),
                                        "user": data.get("user")
                                    },
                                    "details": {
                                        "args": data.get("args"),
                                        "raw_data": data.get("data")
                                    }
                                })
                            except json.JSONDecodeError:
                                continue
                print(f"    从日志文件读取 {len(alerts)} 条告警")
            except Exception as e:
                print(f"    日志文件读取失败: {e}")
        
        # 保存
        output_path = self.alerts_dir / "audit_alerts.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        
        return alerts
    
    def collect_all_alerts(self):
        """收集所有类型的告警"""
        print("\n" + "=" * 70)
        print("  收集告警数据")
        print("=" * 70)
        
        all_alerts = []
        
        # 收集各类告警
        file_alerts = self.collect_file_alerts()
        all_alerts.extend(file_alerts)
        
        account_alerts = self.collect_account_alerts()
        all_alerts.extend(account_alerts)
        
        parasitic_alerts = self.collect_parasitic_alerts()
        all_alerts.extend(parasitic_alerts)
        
        audit_alerts = self.collect_audit_alerts()
        all_alerts.extend(audit_alerts)
        
        # 按时间排序
        all_alerts.sort(key=lambda x: x.get("timestamp", ""))
        
        # 保存汇聚后的告警
        output_path = self.output_dir / "collected_alerts.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(all_alerts, f, ensure_ascii=False, indent=2)
        
        # 统计
        print("\n  " + "-" * 50)
        print(f"  汇总统计:")
        print(f"    文件蜜点告警: {len(file_alerts)} 条")
        print(f"    账户蜜点告警: {len(account_alerts)} 条")
        print(f"    寄生蜜点告警: {len(parasitic_alerts)} 条")
        print(f"    audit日志:    {len(audit_alerts)} 条")
        print(f"    总计:         {len(all_alerts)} 条")
        print(f"\n  [✓] 告警数据已保存: {output_path}")
        
        return all_alerts
    
    def export_to_step1(self):
        """将告警数据导出到step1"""
        print("\n" + "=" * 70)
        print("  导出数据到Step1")
        print("=" * 70)
        
        source_path = self.output_dir / "collected_alerts.json"
        target_dir = self.base_dir / "step1_data_collection" / "output"
        target_path = target_dir / "unified_alerts.json"
        
        # 确保目标目录存在
        target_dir.mkdir(parents=True, exist_ok=True)
        
        if source_path.exists():
            # 读取并转换格式
            with open(source_path, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
            
            # 保存到step1
            with open(target_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            
            print(f"  [✓] 数据已导出: {target_path}")
            print(f"      告警数量: {len(alerts)}")
        else:
            print(f"  [!] 源文件不存在: {source_path}")
            print("      请先运行: python deploy_manager.py collect")
        
        return target_path
    
    def get_status(self):
        """获取系统状态"""
        status = {
            "timestamp": datetime.now().isoformat(),
            "components": {},
            "alerts": {},
            "data_flow": {}
        }
        
        # 检查组件状态
        for name, config in self.components.get("components", {}).items():
            path = self.base_dir / config["path"].lstrip("../")
            status["components"][name] = {
                "exists": path.exists(),
                "path": str(path)
            }
        
        # 检查告警文件
        alert_files = [
            ("file_alerts", self.alerts_dir / "file_alerts.json"),
            ("account_alerts", self.alerts_dir / "account_alerts.json"),
            ("parasitic_alerts", self.alerts_dir / "parasitic_alerts.json"),
            ("audit_alerts", self.alerts_dir / "audit_alerts.json"),
            ("collected", self.output_dir / "collected_alerts.json")
        ]
        
        for name, path in alert_files:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                status["alerts"][name] = {
                    "exists": True,
                    "count": len(data)
                }
            else:
                status["alerts"][name] = {
                    "exists": True,
                    "count": 0
                }
        
        # 检查数据流
        flow_files = [
            ("step1_output", self.base_dir / "step1_data_collection" / "output" / "unified_alerts.json"),
            ("step2_output", self.base_dir / "step2_causal_graph" / "output" / "causal_graph.json"),
            ("step3_output", self.base_dir / "step3_dqn_pruning" / "output" / "pruned_graph.json")
        ]
        
        for name, path in flow_files:
            status["data_flow"][name] = {
                "exists": path.exists(),
                "path": str(path)
            }
        
        return status
    
    def generate_report(self):
        """生成部署报告"""
        print("\n" + "=" * 70)
        print("  生成部署报告")
        print("=" * 70)
        
        status = self.get_status()
        
        report = {
            "system_name": "蜜点管理系统",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "components": status["components"],
            "alerts_summary": status["alerts"],
            "data_flow": status["data_flow"]
        }
        
        report_path = self.deployment_dir / "deployment_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"  [✓] 报告已生成: {report_path}")
        
        return report


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="部署管理工具")
    parser.add_argument("command", choices=["check", "collect", "export", "status", "report"],
                       help="执行的命令")
    parser.add_argument("--hours", type=int, default=24, help="收集最近N小时的数据")
    
    args = parser.parse_args()
    
    manager = DeploymentManager()
    
    if args.command == "check":
        manager.check_components()
    elif args.command == "collect":
        manager.collect_all_alerts()
    elif args.command == "export":
        manager.export_to_step1()
    elif args.command == "status":
        status = manager.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    elif args.command == "report":
        manager.generate_report()


if __name__ == "__main__":
    main()
