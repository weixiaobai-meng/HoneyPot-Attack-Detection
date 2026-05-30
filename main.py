"""
研究生毕设 - 主入口
串联四个步骤：数据汇聚 → 因果图构建 → DQN裁剪 → Graph-to-Text
"""

import argparse
import os
import json
from datetime import datetime, timedelta

# 导入各步骤模块
from step1_data_collection import DataCollector
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
from step3_dqn_pruning import DQNTrainer, load_graphs_for_training, get_graph_statistics
from step4_graph_to_text import GraphToTextConverter


def main():
    parser = argparse.ArgumentParser(description="蜜点告警分析系统")
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 第一步：数据汇聚
    step1_parser = subparsers.add_parser("step1", help="第一步：数据汇聚")
    step1_parser.add_argument("--hours", type=int, default=24, help="收集最近N小时的数据")
    step1_parser.add_argument("--output", type=str, default="step1_data_collection/output/unified_alerts.json")
    
    # 第二步：因果图构建
    step2_parser = subparsers.add_parser("step2", help="第二步：因果图构建")
    step2_parser.add_argument("--input", type=str, default="step1_data_collection/output/unified_alerts.json")
    step2_parser.add_argument("--output", type=str, default="step2_causal_graph/output/causal_graph.json")
    step2_parser.add_argument("--format", type=str, choices=["json", "mermaid", "dot"], default="json")
    
    # 第三步：DQN裁剪
    step3_parser = subparsers.add_parser("step3", help="第三步：DQN裁剪")
    step3_parser.add_argument("--mode", type=str, choices=["train", "predict"], default="train")
    step3_parser.add_argument("--input", type=str, default="step2_causal_graph/output/causal_graph.json")
    step3_parser.add_argument("--output", type=str, default="step3_dqn_pruning/output/pruned_graph.json")
    step3_parser.add_argument("--epochs", type=int, default=120)
    
    # 第四步：Graph-to-Text
    step4_parser = subparsers.add_parser("step4", help="第四步：Graph-to-Text")
    step4_parser.add_argument("--input", type=str, default="step3_dqn_pruning/output/pruned_graph.json")
    step4_parser.add_argument("--output", type=str, default="step4_graph_to_text/output/llm_prompt.txt")
    step4_parser.add_argument("--task", type=str, choices=["intent_analysis", "ttp_mapping", "report"], 
                             default="intent_analysis")
    
    # 演示模式
    demo_parser = subparsers.add_parser("demo", help="运行完整演示")
    
    # 运行全部
    all_parser = subparsers.add_parser("all", help="运行全部步骤")
    
    args = parser.parse_args()
    
    if args.command == "step1":
        run_step1(args)
    elif args.command == "step2":
        run_step2(args)
    elif args.command == "step3":
        run_step3(args)
    elif args.command == "step4":
        run_step4(args)
    elif args.command == "demo":
        run_demo()
    elif args.command == "all":
        run_all()
    else:
        parser.print_help()


def run_step1(args):
    """第一步：数据汇聚"""
    print("=" * 60)
    print("  第一步：数据汇聚")
    print("=" * 60)
    
    collector = DataCollector()
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=args.hours)
    
    print(f"\n[*] 收集时间范围: {start_time} ~ {end_time}")
    
    alerts = collector.collect_all(start_time, end_time)
    
    print(f"\n[*] 共收集到 {len(alerts)} 条告警")
    
    collector.save_alerts(alerts, args.output)
    
    return alerts


def run_step2(args):
    """第二步：因果图构建"""
    print("\n" + "=" * 60)
    print("  第二步：因果图构建")
    print("=" * 60)
    
    # 加载告警数据
    print(f"\n[*] 读取告警数据: {args.input}")
    with open(args.input, 'r', encoding='utf-8') as f:
        alerts_data = json.load(f)
    
    print(f"[*] 加载了 {len(alerts_data)} 条告警")
    
    # 构建因果图
    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(alerts_data)
    
    # 保存
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, ensure_ascii=False, indent=2)
    
    print(f"\n[*] 因果图已保存到: {args.output}")
    print(f"    节点数: {len(graph_data['nodes'])}")
    print(f"    边数: {len(graph_data['edges'])}")
    
    # 可视化
    if args.format == "mermaid":
        mermaid_path = args.output.replace('.json', '.mmd')
        CausalGraphVisualizer.save_mermaid(graph_data, mermaid_path)
    elif args.format == "dot":
        dot_path = args.output.replace('.json', '.dot')
        CausalGraphVisualizer.save_dot(graph_data, dot_path)
    
    return graph_data


def run_step3(args):
    """第三步：DQN裁剪"""
    print("\n" + "=" * 60)
    print("  第三步：DQN图谱裁剪")
    print("=" * 60)
    
    trainer = DQNTrainer(epochs=args.epochs)
    
    if args.mode == "train":
        # 加载数据
        print(f"\n[*] 加载因果图: {args.input}")
        stats = get_graph_statistics(args.input)
        print(f"    节点数: {stats['num_nodes']}")
        print(f"    边数: {stats['num_edges']}")
        
        # 生成训练数据
        print("\n[*] 生成训练数据...")
        train_graphs = load_graphs_for_training(args.input, num_graphs=100, augment=True)
        val_graphs = load_graphs_for_training(args.input, num_graphs=20, augment=True)
        test_graphs = load_graphs_for_training(args.input, num_graphs=30, augment=False)
        
        # 训练
        save_path = "step3_dqn_pruning/output/checkpoints/dqn_best.pt"
        trainer.train(train_graphs, val_graphs, save_path)
        
        # 测试
        metrics = trainer.evaluate_on_test(test_graphs)
        
        # 裁剪
        trainer.predict_and_prune(args.input, args.output)
        
    elif args.mode == "predict":
        model_path = "step3_dqn_pruning/output/checkpoints/dqn_best.pt"
        trainer.model.load_state_dict(torch.load(model_path))
        trainer.predict_and_prune(args.input, args.output)


def run_step4(args):
    """第四步：Graph-to-Text"""
    print("\n" + "=" * 60)
    print("  第四步：Graph-to-Text")
    print("=" * 60)
    
    # 加载因果图
    print(f"\n[*] 读取因果图: {args.input}")
    with open(args.input, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    # 转换
    converter = GraphToTextConverter()
    text = converter.convert_to_llm_prompt(graph_data, args.task)
    
    # 保存
    converter.save(text, args.output)
    
    # 显示预览
    print("\n[*] 文本预览:")
    print("-" * 60)
    print(text[:500])
    if len(text) > 500:
        print("...")
    print("-" * 60)


def run_demo():
    """运行演示"""
    print("=" * 60)
    print("  蜜点告警分析系统 - 完整演示")
    print("=" * 60)
    
    # 创建演示数据
    demo_alerts = create_demo_alerts()
    
    # 第一步：保存告警
    step1_output = "step1_data_collection/output/unified_alerts.json"
    os.makedirs(os.path.dirname(step1_output), exist_ok=True)
    with open(step1_output, 'w', encoding='utf-8') as f:
        json.dump([a.to_dict() for a in demo_alerts], f, ensure_ascii=False, indent=2)
    print(f"\n[+] 第一步完成: {len(demo_alerts)} 条告警已保存")
    
    # 第二步：构建因果图
    step2_output = "step2_causal_graph/output/causal_graph.json"
    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(demo_alerts)
    os.makedirs(os.path.dirname(step2_output), exist_ok=True)
    with open(step2_output, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, ensure_ascii=False, indent=2)
    print(f"[+] 第二步完成: 因果图已保存 (节点:{len(graph_data['nodes'])}, 边:{len(graph_data['edges'])})")
    
    # 第三步：DQN裁剪（使用模拟数据）
    step3_output = "step3_dqn_pruning/output/pruned_graph.json"
    # 模拟裁剪结果
    pruned_data = graph_data.copy()
    pruned_data["edges"] = graph_data["edges"][:5]  # 保留前5条边
    pruned_data["pruning_stats"] = {
        "original_edges": len(graph_data["edges"]),
        "kept_edges": 5,
        "pruned_edges": len(graph_data["edges"]) - 5,
        "compression_ratio": f"{100*(len(graph_data['edges'])-5)/len(graph_data['edges']):.1f}%"
    }
    os.makedirs(os.path.dirname(step3_output), exist_ok=True)
    with open(step3_output, 'w', encoding='utf-8') as f:
        json.dump(pruned_data, f, ensure_ascii=False, indent=2)
    print(f"[+] 第三步完成: 裁剪后因果图已保存 (压缩率:{pruned_data['pruning_stats']['compression_ratio']})")
    
    # 第四步：Graph-to-Text
    step4_output = "step4_graph_to_text/output/llm_prompt.txt"
    converter = GraphToTextConverter()
    text = converter.convert_to_llm_prompt(pruned_data, "intent_analysis")
    converter.save(text, step4_output)
    print(f"[+] 第四步完成: LLM提示词已保存")
    
    print("\n" + "=" * 60)
    print("  演示完成！")
    print("=" * 60)
    print("\n输出文件:")
    print(f"  1. {step1_output}")
    print(f"  2. {step2_output}")
    print(f"  3. {step3_output}")
    print(f"  4. {step4_output}")


def run_all():
    """运行全部步骤"""
    print("=" * 60)
    print("  运行全部步骤")
    print("=" * 60)
    
    # 第一步
    args1 = argparse.Namespace(hours=24, output="step1_data_collection/output/unified_alerts.json")
    run_step1(args1)
    
    # 第二步
    args2 = argparse.Namespace(
        input="step1_data_collection/output/unified_alerts.json",
        output="step2_causal_graph/output/causal_graph.json",
        format="json"
    )
    run_step2(args2)
    
    # 第三步
    args3 = argparse.Namespace(
        mode="train",
        input="step2_causal_graph/output/causal_graph.json",
        output="step3_dqn_pruning/output/pruned_graph.json",
        epochs=120
    )
    run_step3(args3)
    
    # 第四步
    args4 = argparse.Namespace(
        input="step3_dqn_pruning/output/pruned_graph.json",
        output="step4_graph_to_text/output/llm_prompt.txt",
        task="intent_analysis"
    )
    run_step4(args4)


def create_demo_alerts():
    """创建演示告警数据"""
    from step1_data_collection import UnifiedAlert, AlertType
    
    alerts = [
        UnifiedAlert(
            alert_id="ssh_001",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            attacker_ip="192.168.1.100",
            target_host="192.168.1.20",
            action="ssh_login",
            details={"username": "admin", "password": "password123"}
        ),
        UnifiedAlert(
            alert_id="file_001",
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 5, 0),
            attacker_ip="192.168.1.100",
            target_path="/home/admin/passwords.xlsx",
            action="file_access"
        ),
        UnifiedAlert(
            alert_id="audit_001",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=datetime(2024, 1, 15, 10, 10, 0),
            action="execve",
            target_path="/usr/bin/cat",
            process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
        ),
        UnifiedAlert(
            alert_id="audit_002",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=datetime(2024, 1, 15, 10, 10, 5),
            action="openat",
            target_path="/home/admin/passwords.xlsx",
            process_info={"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
        ),
        UnifiedAlert(
            alert_id="ssh_002",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 15, 0),
            attacker_ip="192.168.1.20",
            target_host="192.168.1.30",
            action="ssh_login",
            details={"username": "root", "password": "stolen_pass"}
        ),
        UnifiedAlert(
            alert_id="audit_003",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=datetime(2024, 1, 15, 10, 20, 0),
            action="connect",
            process_info={"pid": "12400", "ppid": "12300", "exe": "/usr/bin/curl", "user": "admin"},
            details={"dest_ip": "10.0.0.100", "dest_port": "443"}
        ),
        UnifiedAlert(
            alert_id="para_001",
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=datetime(2024, 1, 15, 10, 25, 0),
            attacker_ip="192.168.1.100",
            action="url_access",
            details={"fingerprint": "fp_abc123", "url": "/admin/config.php"}
        ),
    ]
    
    return alerts


if __name__ == "__main__":
    import torch
    main()
