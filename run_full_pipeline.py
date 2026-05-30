"""
完整流程脚本
从部署到分析的端到端流程
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime


class FullPipeline:
    """完整流程管理器"""
    
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or Path(__file__).parent
        self.steps = [
            ("deployment", "部署管理"),
            ("step1", "数据汇聚"),
            ("step2", "因果图构建"),
            ("step3", "DQN裁剪"),
            ("step4", "Graph-to-Text")
        ]
    
    def run_step(self, step_name, **kwargs):
        """运行指定步骤"""
        print("\n" + "=" * 70)
        print(f"  运行 {step_name}")
        print("=" * 70)
        
        if step_name == "deployment":
            return self.run_deployment(**kwargs)
        elif step_name == "step1":
            return self.run_step1(**kwargs)
        elif step_name == "step2":
            return self.run_step2(**kwargs)
        elif step_name == "step3":
            return self.run_step3(**kwargs)
        elif step_name == "step4":
            return self.run_step4(**kwargs)
        else:
            print(f"  未知步骤: {step_name}")
            return False
    
    def run_deployment(self, **kwargs):
        """运行部署步骤"""
        sys.path.insert(0, str(self.base_dir / "deployment"))
        from deploy_manager import DeploymentManager
        
        manager = DeploymentManager(self.base_dir)
        
        # 检查组件
        manager.check_components()
        
        # 生成配置
        manager.generate_config()
        
        # 收集告警
        alerts_path = manager.collect_alerts()
        
        # 导出到step1
        manager.export_to_step1(alerts_path)
        
        return True
    
    def run_step1(self, **kwargs):
        """运行数据汇聚"""
        from step1_data_collection import DataCollector
        
        collector = DataCollector()
        
        # 如果deployment有输出，使用它
        deployment_output = self.base_dir / "deployment" / "output" / "collected_alerts.json"
        if deployment_output.exists():
            print(f"  使用部署数据: {deployment_output}")
            # 加载并转换
            with open(deployment_output, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
        else:
            # 使用模拟数据
            print("  使用模拟数据")
            alerts = self.create_sample_alerts()
        
        # 保存
        output_path = self.base_dir / "step1_data_collection" / "output" / "unified_alerts.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        from step1_data_collection.models import UnifiedAlert, AlertType
        
        # 转换为统一格式
        unified_alerts = []
        for alert in alerts:
            if isinstance(alert, dict):
                unified_alerts.append(alert)
            else:
                unified_alerts.append(alert.to_dict())
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(unified_alerts, f, ensure_ascii=False, indent=2)
        
        print(f"  [✓] 告警数据已保存: {output_path}")
        print(f"      告警数量: {len(unified_alerts)}")
        
        return True
    
    def run_step2(self, **kwargs):
        """运行因果图构建"""
        from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
        
        # 加载告警数据
        alerts_path = self.base_dir / "step1_data_collection" / "output" / "unified_alerts.json"
        with open(alerts_path, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
        
        # 构建因果图
        builder = CausalGraphBuilder()
        graph_data = builder.build_from_alerts(alerts)
        
        # 保存
        output_dir = self.base_dir / "step2_causal_graph" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / "causal_graph.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, ensure_ascii=False, indent=2)
        
        # 生成Mermaid
        mermaid_path = output_dir / "causal_graph.mmd"
        CausalGraphVisualizer.save_mermaid(graph_data, mermaid_path)
        
        print(f"  [✓] 因果图已保存: {output_path}")
        print(f"      节点数: {len(graph_data['nodes'])}")
        print(f"      边数: {len(graph_data['edges'])}")
        
        return True
    
    def run_step3(self, **kwargs):
        """运行DQN裁剪"""
        from step3_dqn_pruning import DQNTrainer, load_graphs_for_training, get_graph_statistics
        
        graph_path = self.base_dir / "step2_causal_graph" / "output" / "causal_graph.json"
        
        # 获取统计信息
        stats = get_graph_statistics(str(graph_path))
        print(f"  原始图: {stats['num_nodes']} 节点, {stats['num_edges']} 边")
        
        # 生成训练数据
        train_graphs = load_graphs_for_training(str(graph_path), num_graphs=200, augment=True)
        val_graphs = load_graphs_for_training(str(graph_path), num_graphs=40, augment=True)
        test_graphs = load_graphs_for_training(str(graph_path), num_graphs=60, augment=False)
        
        # 训练
        trainer = DQNTrainer(epochs=60, patience=20)
        
        save_path = str(self.base_dir / "step3_dqn_pruning" / "output" / "checkpoints" / "dqn_best.pt")
        trainer.train(train_graphs, val_graphs, save_path=save_path)
        
        # 评估
        metrics = trainer.evaluate_on_test(test_graphs)
        
        # 裁剪
        pruned_path = str(self.base_dir / "step3_dqn_pruning" / "output" / "pruned_graph.json")
        trainer.predict_and_prune(str(graph_path), pruned_path)
        
        return True
    
    def run_step4(self, **kwargs):
        """运行Graph-to-Text"""
        from step4_graph_to_text import GraphToTextConverter
        
        pruned_path = self.base_dir / "step3_dqn_pruning" / "output" / "pruned_graph.json"
        
        with open(pruned_path, 'r', encoding='utf-8') as f:
            graph_data = json.load(f)
        
        converter = GraphToTextConverter()
        
        output_dir = self.base_dir / "step4_graph_to_text" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成各种提示词
        for task in ["intent_analysis", "ttp_mapping", "report"]:
            text = converter.convert_to_llm_prompt(graph_data, task)
            
            output_path = output_dir / f"llm_prompt_{task}.txt"
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            print(f"  [✓] 已生成: {output_path} ({len(text)} 字符)")
        
        return True
    
    def create_sample_alerts(self):
        """创建示例告警数据"""
        base_time = datetime(2024, 6, 15, 10, 0, 0)
        
        return [
            {
                "alert_id": "sample_1",
                "alert_type": "account",
                "timestamp": base_time.isoformat(),
                "attacker_ip": "192.168.1.100",
                "target_host": "192.168.1.20",
                "action": "ssh_login",
                "details": {"username": "admin", "password": "test123"}
            },
            {
                "alert_id": "sample_2",
                "alert_type": "file",
                "timestamp": (base_time.timestamp() + 300),
                "attacker_ip": "192.168.1.100",
                "target_path": "/home/admin/passwords.xlsx",
                "action": "file_access",
                "details": {"token": "abc123"}
            }
        ]
    
    def run_full_pipeline(self):
        """运行完整流程"""
        print("\n" + "=" * 70)
        print("  完整流程: 部署 → 数据汇聚 → 因果图 → DQN → Graph-to-Text")
        print("=" * 70)
        
        results = {}
        
        for step_name, step_desc in self.steps:
            print(f"\n{'='*70}")
            print(f"  步骤: {step_desc}")
            print(f"{'='*70}")
            
            try:
                success = self.run_step(step_name)
                results[step_name] = {"success": success}
            except Exception as e:
                print(f"  [✗] 错误: {e}")
                results[step_name] = {"success": False, "error": str(e)}
                break
        
        # 生成报告
        print("\n" + "=" * 70)
        print("  流程执行结果")
        print("=" * 70)
        
        for step_name, step_desc in self.steps:
            result = results.get(step_name, {})
            status = "✓ 成功" if result.get("success") else "✗ 失败"
            print(f"  {step_desc}: {status}")
        
        return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="完整流程脚本")
    parser.add_argument("--step", choices=["deployment", "step1", "step2", "step3", "step4", "all"],
                       default="all", help="运行指定步骤或全部")
    
    args = parser.parse_args()
    
    pipeline = FullPipeline()
    
    if args.step == "all":
        pipeline.run_full_pipeline()
    else:
        pipeline.run_step(args.step)


if __name__ == "__main__":
    main()
