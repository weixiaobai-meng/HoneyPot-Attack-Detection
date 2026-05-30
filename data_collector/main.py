"""
数据汇聚 + 因果图构建 + Graph-to-Text 主入口
功能1: 汇聚三种蜜点的告警数据 + audit日志
功能2: 构建因果溯源图 (Subject → Action → Object)
功能3: 将因果图转换为LLM提示词
"""

import argparse
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from models import UnifiedAlert, AlertType
from collector import DataCollector, AlertAggregator
from causal_graph import CausalGraph, CausalGraphBuilder, CausalGraphVisualizer, build_causal_graph
from graph_to_text import GraphToTextConverter, load_and_convert


def main():
    parser = argparse.ArgumentParser(description="蜜点告警数据汇聚与因果图构建工具")
    
    # 子命令
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # collect命令 - 汇聚数据
    collect_parser = subparsers.add_parser("collect", help="汇聚告警数据")
    collect_parser.add_argument("--hours", type=int, default=24, 
                        help="收集最近N小时的数据 (默认24)")
    collect_parser.add_argument("--output", type=str, default="output/unified_alerts.json",
                        help="输出文件路径")
    collect_parser.add_argument("--source", type=str, choices=["all", "file", "account", "parasitic", "audit"],
                        default="all", help="数据源 (默认all)")
    collect_parser.add_argument("--aggregate", action="store_true",
                        help="是否按IP聚合")
    
    # graph命令 - 构建因果图
    graph_parser = subparsers.add_parser("graph", help="构建因果图")
    graph_parser.add_argument("--input", type=str, default="output/unified_alerts.json",
                        help="输入告警数据文件")
    graph_parser.add_argument("--output", type=str, default="output/causal_graph.json",
                        help="输出因果图文件")
    graph_parser.add_argument("--format", type=str, choices=["json", "mermaid", "dot"], default="json",
                        help="输出格式")
    graph_parser.add_argument("--ip", type=str, help="筛选特定IP的子图")
    
    # text命令 - Graph-to-Text转换
    text_parser = subparsers.add_parser("text", help="因果图转文本")
    text_parser.add_argument("--input", type=str, default="output/pruned_graph.json",
                        help="输入因果图文件")
    text_parser.add_argument("--output", type=str, default="output/llm_prompt.txt",
                        help="输出文本文件")
    text_parser.add_argument("--task", type=str, 
                        choices=["intent_analysis", "ttp_mapping", "report", "raw"],
                        default="intent_analysis", help="任务类型")
    
    # demo命令 - 演示
    demo_parser = subparsers.add_parser("demo", help="运行演示")
    
    args = parser.parse_args()
    
    if args.command == "collect":
        run_collect(args)
    elif args.command == "graph":
        run_graph(args)
    elif args.command == "text":
        run_text(args)
    elif args.command == "demo":
        demo_full_pipeline()
    else:
        # 默认运行演示
        demo_full_pipeline()


def run_collect(args):
    """运行数据汇聚"""
    # 创建输出目录
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    # 初始化汇聚器
    collector = DataCollector()
    
    # 时间范围
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=args.hours)
    
    print(f"[*] 收集时间范围: {start_time} ~ {end_time}")
    print(f"[*] 数据源: {args.source}")
    print()
    
    # 收集数据
    if args.source == "all":
        alerts = collector.collect_all(start_time, end_time)
    elif args.source == "file":
        alerts = collector.collect_file_honeypot(start_time, end_time)
    elif args.source == "account":
        alerts = collector.collect_account_honeypot(start_time, end_time)
    elif args.source == "parasitic":
        alerts = collector.collect_parasitic_honeypot(start_time, end_time)
    elif args.source == "audit":
        alerts = collector.collect_audit_logs(start_time, end_time)
    
    print()
    print(f"[*] 共收集到 {len(alerts)} 条告警")
    
    # 保存数据
    collector.save_unified_alerts(alerts, args.output)
    
    # 聚合分析
    if args.aggregate and alerts:
        aggregator = AlertAggregator()
        ip_groups = aggregator.aggregate_by_ip(alerts)
        
        print()
        print("[*] 按攻击者IP聚合:")
        for ip, ip_alerts in ip_groups.items():
            print(f"  {ip}: {len(ip_alerts)} 条告警")
            
            # 显示告警类型分布
            type_dist = {}
            for alert in ip_alerts:
                t = alert.alert_type.value
                type_dist[t] = type_dist.get(t, 0) + 1
            print(f"    类型分布: {type_dist}")
    
    print()
    print(f"[+] 数据已保存到: {args.output}")


def run_graph(args):
    """运行因果图构建"""
    print(f"[*] 读取告警数据: {args.input}")
    
    # 读取告警数据
    alerts = load_alerts_from_file(args.input)
    print(f"[*] 加载了 {len(alerts)} 条告警")
    
    # 构建因果图
    print("[*] 构建因果图...")
    graph = build_causal_graph(alerts)
    
    # 筛选特定IP的子图
    if args.ip:
        print(f"[*] 筛选IP {args.ip} 的子图...")
        graph = graph.get_subgraph_by_ip(args.ip)
    
    # 输出结果
    if args.format == "json":
        graph.save(args.output)
    elif args.format == "mermaid":
        mermaid = CausalGraphVisualizer.to_mermaid(graph)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(mermaid)
        print(f"[+] Mermaid格式已保存到: {args.output}")
    elif args.format == "dot":
        dot = CausalGraphVisualizer.to_dot(graph)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(dot)
        print(f"[+] DOT格式已保存到: {args.output}")
    
    # 打印统计信息
    stats = graph.get_statistics()
    print("\n[*] 因果图统计:")
    print(f"  节点数: {stats['num_nodes']}")
    print(f"  边数: {stats['num_edges']}")
    print(f"  连通分量: {stats['num_connected_components']}")
    print(f"  节点类型: {stats['node_types']}")
    print(f"  边类型: {stats['edge_types']}")
    
    # 打印三元组
    print("\n[*] 三元组:")
    for triple in graph.get_triples()[:10]:  # 只显示前10个
        print(f"  {triple[0]} --[{triple[1]}]--> {triple[2]}")
    if len(graph.get_triples()) > 10:
        print(f"  ... 共 {len(graph.get_triples())} 个三元组")


def run_text(args):
    """运行Graph-to-Text转换"""
    print(f"[*] 读取因果图: {args.input}")
    
    if not os.path.exists(args.input):
        print(f"[-] 因果图文件不存在: {args.input}")
        print("[*] 请先运行: python main.py demo")
        return
    
    # 转换
    if args.task == "raw":
        # 原始叙述文本
        task = None
    else:
        task = args.task
    
    text = load_and_convert(args.input, args.output, task)
    
    print(f"[+] 文本已保存到: {args.output}")
    print(f"[+] 文本长度: {len(text)} 字符")
    
    # 显示预览
    print("\n[*] 文本预览:")
    print("-" * 60)
    preview = text[:1000]
    print(preview)
    if len(text) > 1000:
        print("... (更多内容请查看输出文件)")
    print("-" * 60)


def load_alerts_from_file(filepath: str) -> list:
    """从文件加载告警数据"""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    alerts = []
    for item in data:
        # 转换时间
        timestamp = item.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        alert = UnifiedAlert(
            alert_id=item.get("alert_id"),
            alert_type=AlertType(item.get("alert_type")),
            timestamp=timestamp,
            attacker_ip=item.get("attacker_ip"),
            attacker_info=item.get("attacker_info"),
            target_host=item.get("target_host"),
            target_path=item.get("target_path"),
            action=item.get("action"),
            details=item.get("details", {}),
            session_id=item.get("session_id"),
            process_info=item.get("process_info")
        )
        alerts.append(alert)
    
    return alerts


def demo_full_pipeline():
    """完整流程演示"""
    print("=" * 60)
    print("  蜜点告警数据汇聚 + 因果图构建 演示")
    print("=" * 60)
    
    # 创建示例数据 - 模拟一个完整的APT攻击场景
    sample_alerts = create_sample_attack_scenario()
    
    # ==================== 第一步：数据汇聚 ====================
    print("\n" + "=" * 60)
    print("  第一步：数据汇聚")
    print("=" * 60)
    
    print("\n[+] 汇聚的告警数据:")
    print("-" * 60)
    for alert in sample_alerts:
        print(f"  [{alert.alert_type.value:10}] {alert.timestamp.strftime('%H:%M:%S')} | "
              f"IP: {str(alert.attacker_ip or 'N/A'):15} | "
              f"Action: {str(alert.action or 'N/A'):15} | "
              f"Target: {str(alert.target_path or alert.target_host or 'N/A')}")
    
    print("-" * 60)
    print(f"  共 {len(sample_alerts)} 条告警")
    
    # 按IP聚合
    aggregator = AlertAggregator()
    ip_groups = aggregator.aggregate_by_ip(sample_alerts)
    
    print("\n[*] 按攻击者IP聚合:")
    for ip, ip_alerts in ip_groups.items():
        print(f"\n  攻击者 {ip}:")
        print(f"    告警数量: {len(ip_alerts)}")
        for alert in ip_alerts:
            print(f"    - [{alert.alert_type.value}] {alert.action}")
    
    # ==================== 第二步：因果图构建 ====================
    print("\n" + "=" * 60)
    print("  第二步：因果图构建")
    print("=" * 60)
    
    # 构建因果图
    graph = build_causal_graph(sample_alerts)
    
    # 打印统计信息
    stats = graph.get_statistics()
    print("\n[*] 因果图统计:")
    print(f"  节点数: {stats['num_nodes']}")
    print(f"  边数: {stats['num_edges']}")
    print(f"  连通分量: {stats['num_connected_components']}")
    print(f"  节点类型: {stats['node_types']}")
    print(f"  边类型: {stats['edge_types']}")
    
    # 打印三元组
    print("\n[*] 因果三元组 (Subject → Action → Object):")
    print("-" * 60)
    for triple in graph.get_triples():
        print(f"  {triple[0]}")
        print(f"    --[{triple[1]}]-->")
        print(f"    {triple[2]}")
        print()
    
    # 保存因果图
    os.makedirs("output", exist_ok=True)
    graph.save("output/causal_graph.json")
    
    # 输出Mermaid格式（可直接在Markdown中渲染）
    mermaid = CausalGraphVisualizer.to_mermaid(graph, "APT Attack Causal Graph")
    with open("output/causal_graph.mmd", 'w', encoding='utf-8') as f:
        f.write(mermaid)
    print("[+] Mermaid格式已保存到: output/causal_graph.mmd")
    
    # 输出攻击路径
    print("\n[*] 攻击路径分析:")
    paths = graph.get_attack_paths()
    for i, path in enumerate(paths[:5]):  # 只显示前5条路径
        print(f"  路径 {i+1}: {' → '.join(path)}")
    
    # ==================== 总结 ====================
    print("\n" + "=" * 60)
    print("  演示完成")
    print("=" * 60)
    print("\n[+] 已完成:")
    print("  1. 数据汇聚 - 将三种蜜点告警+audit日志转换为统一格式")
    print("  2. 因果图构建 - 将告警转换为 Subject→Action→Object 三元组")
    print("\n[*] 输出文件:")
    print("  - output/causal_graph.json  (因果图JSON格式)")
    print("  - output/causal_graph.mmd   (Mermaid可视化格式)")
    print("\n[*] 后续步骤:")
    print("  3. 使用DQN对因果图进行降噪裁剪 (shiyan目录)")
    print("  4. 使用LLM进行攻击意图推理")


def create_sample_attack_scenario() -> list:
    """
    创建示例攻击场景 - 模拟完整APT攻击链
    攻击者(192.168.1.100) → 初始访问 → 权限提升 → 横向移动 → 数据外泄
    """
    alerts = []
    
    # 阶段1: 初始访问 - 攻击者尝试SSH登录
    alerts.append(UnifiedAlert(
        alert_id="ssh_001",
        alert_type=AlertType.ACCOUNT_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 0, 0),
        attacker_ip="192.168.1.100",
        target_host="192.168.1.20",
        action="ssh_login",
        details={"username": "admin", "password": "password123"}
    ))
    
    alerts.append(UnifiedAlert(
        alert_id="ssh_002",
        alert_type=AlertType.ACCOUNT_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 0, 30),
        attacker_ip="192.168.1.100",
        target_host="192.168.1.20",
        action="ssh_login",
        details={"username": "root", "password": "toor"}
    ))
    
    # 阶段2: 侦察 - 访问蜜点文件
    alerts.append(UnifiedAlert(
        alert_id="file_001",
        alert_type=AlertType.FILE_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 5, 0),
        attacker_ip="192.168.1.100",
        target_path="/home/admin/passwords.xlsx",
        action="file_access",
        details={"token": "abc123"}
    ))
    
    alerts.append(UnifiedAlert(
        alert_id="file_002",
        alert_type=AlertType.FILE_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 5, 30),
        attacker_ip="192.168.1.100",
        target_path="/etc/shadow.backup",
        action="file_access",
        details={"token": "def456"}
    ))
    
    # 阶段3: 权限提升 - 执行命令
    alerts.append(UnifiedAlert(
        alert_id="audit_001",
        alert_type=AlertType.AUDIT_EVENT,
        timestamp=datetime(2024, 1, 15, 10, 10, 0),
        action="execve",
        target_path="/usr/bin/cat",
        process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
    ))
    
    alerts.append(UnifiedAlert(
        alert_id="audit_002",
        alert_type=AlertType.AUDIT_EVENT,
        timestamp=datetime(2024, 1, 15, 10, 10, 5),
        action="openat",
        target_path="/home/admin/passwords.xlsx",
        process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
    ))
    
    # 阶段4: 横向移动 - 访问其他主机
    alerts.append(UnifiedAlert(
        alert_id="ssh_003",
        alert_type=AlertType.ACCOUNT_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 15, 0),
        attacker_ip="192.168.1.20",  # 从被攻陷的主机发起
        target_host="192.168.1.30",
        action="ssh_login",
        details={"username": "root", "password": "stolen_password"}
    ))
    
    # 阶段5: 数据外泄 - 网络连接
    alerts.append(UnifiedAlert(
        alert_id="audit_003",
        alert_type=AlertType.AUDIT_EVENT,
        timestamp=datetime(2024, 1, 15, 10, 20, 0),
        action="connect",
        process_info={"pid": "12400", "ppid": "12300", "exe": "/usr/bin/curl", "user": "admin"},
        details={"dest_ip": "10.0.0.100", "dest_port": "443"}
    ))
    
    # 阶段6: 触发寄生蜜点
    alerts.append(UnifiedAlert(
        alert_id="para_001",
        alert_type=AlertType.PARASITIC_HONEYPOT,
        timestamp=datetime(2024, 1, 15, 10, 25, 0),
        attacker_ip="192.168.1.100",
        action="url_access",
        details={"fingerprint": "fp_abc123", "url": "/admin/config.php"}
    ))
    
    # 按时间排序
    alerts.sort(key=lambda x: x.timestamp)
    
    return alerts


if __name__ == "__main__":
    main()
