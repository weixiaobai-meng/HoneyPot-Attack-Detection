"""
端到端实验：模拟完整APT攻击场景
从蜜点部署 → 攻击触发 → 数据采集 → 因果图构建 → DQN裁剪 → Graph-to-Text

本实验用于验证系统完整性和生成论文实验数据
"""

import json
import os
import sys
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))


def create_realistic_attack_scenario():
    """
    创建真实的APT攻击场景数据
    
    攻击链路模拟：
    1. 侦察阶段：攻击者扫描目标网络
    2. 初始访问：尝试SSH暴力破解
    3. 执行阶段：成功登录后执行命令
    4. 持久化：创建后门
    5. 横向移动：尝试访问其他主机
    6. 数据窃取：访问敏感文件
    7. 数据外泄：通过网络连接外传数据
    """
    print("\n" + "=" * 70)
    print("  阶段一：创建真实APT攻击场景数据")
    print("=" * 70)
    
    base_time = datetime(2024, 6, 15, 10, 0, 0)
    alerts = []
    
    # ============== 攻击者信息 ==============
    attacker_ip = "192.168.1.100"
    target_hosts = ["192.168.1.20", "192.168.1.30", "192.168.1.40"]
    
    # ============== 阶段1：侦察 ==============
    print("\n  [阶段1] 侦察 - 账户蜜点触发")
    for i, host in enumerate(target_hosts):
        alerts.append({
            "alert_id": f"recon_{i+1}",
            "alert_type": "account",
            "timestamp": (base_time + timedelta(minutes=i*2)).isoformat(),
            "attacker_ip": attacker_ip,
            "target_host": host,
            "action": "ssh_login",
            "details": {
                "username": random.choice(["admin", "root", "test", "oracle"]),
                "password": random.choice(["password123", "admin@2024", "root123", "test"]),
                "client_version": "SSH-2.0-libssh2_1.10.0",
                "attempt": i+1
            }
        })
    print(f"    生成 {len(alerts)} 条SSH登录尝试告警")
    
    # ============== 阶段2：初始访问成功 ==============
    print("\n  [阶段2] 初始访问 - 文件蜜点触发")
    file_alerts = [
        {
            "alert_id": "file_access_1",
            "alert_type": "file",
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "attacker_ip": attacker_ip,
            "target_path": "/home/admin/passwords.xlsx",
            "action": "file_access",
            "details": {"token": "abc123", "user_agent": "Mozilla/5.0"}
        },
        {
            "alert_id": "file_access_2",
            "alert_type": "file",
            "timestamp": (base_time + timedelta(minutes=11)).isoformat(),
            "attacker_ip": attacker_ip,
            "target_path": "/home/admin/database_backup.sql",
            "action": "file_access",
            "details": {"token": "def456", "user_agent": "Mozilla/5.0"}
        },
        {
            "alert_id": "file_access_3",
            "alert_type": "file",
            "timestamp": (base_time + timedelta(minutes=12)).isoformat(),
            "attacker_ip": attacker_ip,
            "target_path": "/etc/shadow.bak",
            "action": "file_access",
            "details": {"token": "ghi789", "user_agent": "curl/7.68.0"}
        }
    ]
    alerts.extend(file_alerts)
    print(f"    生成 {len(file_alerts)} 条文件蜜点告警")
    
    # ============== 阶段3：执行命令 ==============
    print("\n  [阶段3] 命令执行 - audit日志记录")
    audit_alerts = [
        {
            "alert_id": "audit_exec_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "action": "execve",
            "target_path": "/usr/bin/cat",
            "process_info": {"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
        },
        {
            "alert_id": "audit_open_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=15, seconds=5)).isoformat(),
            "action": "openat",
            "target_path": "/home/admin/passwords.xlsx",
            "process_info": {"pid": "12345", "ppid": "12300", "exe": "/usr/bin/cat", "user": "admin"}
        },
        {
            "alert_id": "audit_exec_2",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=16)).isoformat(),
            "action": "execve",
            "target_path": "/usr/bin/whoami",
            "process_info": {"pid": "12350", "ppid": "12300", "exe": "/usr/bin/whoami", "user": "admin"}
        },
        {
            "alert_id": "audit_exec_3",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=17)).isoformat(),
            "action": "execve",
            "target_path": "/usr/bin/id",
            "process_info": {"pid": "12355", "ppid": "12300", "exe": "/usr/bin/id", "user": "admin"}
        },
        {
            "alert_id": "audit_exec_4",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=18)).isoformat(),
            "action": "execve",
            "target_path": "/bin/bash",
            "process_info": {"pid": "12360", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        },
        {
            "alert_id": "audit_read_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=18, seconds=10)).isoformat(),
            "action": "read",
            "target_path": "/etc/passwd",
            "process_info": {"pid": "12360", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        },
        {
            "alert_id": "audit_read_2",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=18, seconds=20)).isoformat(),
            "action": "read",
            "target_path": "/etc/shadow",
            "process_info": {"pid": "12360", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        }
    ]
    alerts.extend(audit_alerts)
    print(f"    生成 {len(audit_alerts)} 条audit日志")
    
    # ============== 阶段4：持久化 ==============
    print("\n  [阶段4] 持久化 - 创建后门")
    persistence_alerts = [
        {
            "alert_id": "audit_write_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
            "action": "write",
            "target_path": "/home/admin/.ssh/authorized_keys",
            "process_info": {"pid": "12370", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        },
        {
            "alert_id": "audit_chmod_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=20, seconds=5)).isoformat(),
            "action": "chmod",
            "target_path": "/home/admin/.ssh/authorized_keys",
            "process_info": {"pid": "12370", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        },
        {
            "alert_id": "audit_write_2",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=21)).isoformat(),
            "action": "write",
            "target_path": "/tmp/.backdoor.sh",
            "process_info": {"pid": "12375", "ppid": "12300", "exe": "/bin/bash", "user": "admin"}
        },
        {
            "alert_id": "audit_exec_5",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=21, seconds=10)).isoformat(),
            "action": "execve",
            "target_path": "/bin/chmod",
            "process_info": {"pid": "12380", "ppid": "12375", "exe": "/bin/chmod", "user": "admin"}
        }
    ]
    alerts.extend(persistence_alerts)
    print(f"    生成 {len(persistence_alerts)} 条持久化告警")
    
    # ============== 阶段5：横向移动 ==============
    print("\n  [阶段5] 横向移动 - 尝试访问其他主机")
    lateral_alerts = [
        {
            "alert_id": "lateral_ssh_1",
            "alert_type": "account",
            "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
            "attacker_ip": "192.168.1.20",  # 从被攻陷的主机发起
            "target_host": "192.168.1.30",
            "action": "ssh_login",
            "details": {
                "username": "root",
                "password": "stolen_password_hash",
                "client_version": "SSH-2.0-OpenSSH_8.2",
                "source": "lateral_movement"
            }
        },
        {
            "alert_id": "lateral_ssh_2",
            "alert_type": "account",
            "timestamp": (base_time + timedelta(minutes=26)).isoformat(),
            "attacker_ip": "192.168.1.20",
            "target_host": "192.168.1.40",
            "action": "ssh_login",
            "details": {
                "username": "admin",
                "password": "password123",
                "client_version": "SSH-2.0-OpenSSH_8.2",
                "source": "lateral_movement"
            }
        }
    ]
    alerts.extend(lateral_alerts)
    print(f"    生成 {len(lateral_alerts)} 条横向移动告警")
    
    # ============== 阶段6：数据外泄 ==============
    print("\n  [阶段6] 数据外泄 - 网络连接")
    exfil_alerts = [
        {
            "alert_id": "audit_connect_1",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=30)).isoformat(),
            "action": "connect",
            "process_info": {"pid": "12400", "ppid": "12300", "exe": "/usr/bin/curl", "user": "admin"},
            "details": {"dest_ip": "10.0.0.100", "dest_port": "443", "protocol": "HTTPS"}
        },
        {
            "alert_id": "audit_exec_6",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=30, seconds=10)).isoformat(),
            "action": "execve",
            "target_path": "/usr/bin/tar",
            "process_info": {"pid": "12410", "ppid": "12300", "exe": "/usr/bin/tar", "user": "admin"}
        },
        {
            "alert_id": "audit_connect_2",
            "alert_type": "audit",
            "timestamp": (base_time + timedelta(minutes=32)).isoformat(),
            "action": "connect",
            "process_info": {"pid": "12420", "ppid": "12300", "exe": "/usr/bin/wget", "user": "admin"},
            "details": {"dest_ip": "10.0.0.200", "dest_port": "8080", "protocol": "HTTP"}
        }
    ]
    alerts.extend(exfil_alerts)
    print(f"    生成 {len(exfil_alerts)} 条数据外泄告警")
    
    # ============== 阶段7：寄生蜜点触发 ==============
    print("\n  [阶段7] 寄生蜜点 - 爬虫检测")
    parasitic_alerts = [
        {
            "alert_id": "para_1",
            "alert_type": "parasitic",
            "timestamp": (base_time + timedelta(minutes=35)).isoformat(),
            "attacker_ip": attacker_ip,
            "action": "url_access",
            "details": {
                "fingerprint": "fp_bot_" + str(uuid.uuid4())[:8],
                "url": "/admin/config.php",
                "is_bot": True,
                "bot_score": 0.92
            }
        },
        {
            "alert_id": "para_2",
            "alert_type": "parasitic",
            "timestamp": (base_time + timedelta(minutes=36)).isoformat(),
            "attacker_ip": attacker_ip,
            "action": "url_access",
            "details": {
                "fingerprint": "fp_bot_" + str(uuid.uuid4())[:8],
                "url": "/admin/database.sql",
                "is_bot": True,
                "bot_score": 0.88
            }
        }
    ]
    alerts.extend(parasitic_alerts)
    print(f"    生成 {len(parasitic_alerts)} 条寄生蜜点告警")
    
    # 排序
    alerts.sort(key=lambda x: x["timestamp"])
    
    # 统计
    print("\n  " + "-" * 50)
    print(f"  总计生成 {len(alerts)} 条告警数据")
    print(f"  攻击者IP: {attacker_ip}")
    print(f"  攻击时间: {base_time.strftime('%Y-%m-%d %H:%M:%S')} ~ {(base_time + timedelta(minutes=40)).strftime('%H:%M:%S')}")
    print(f"  攻击阶段: 7个阶段")
    print(f"  告警类型分布:")
    for atype in ["account", "file", "audit", "parasitic"]:
        count = len([a for a in alerts if a["alert_type"] == atype])
        print(f"    - {atype}: {count} 条")
    
    return alerts


def save_alerts(alerts, output_dir="step1_data_collection/output"):
    """保存告警数据"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "unified_alerts.json")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    
    print(f"\n  [✓] 告警数据已保存: {output_path}")
    return output_path


def run_step2_causal_graph(alerts_path):
    """运行第二步：因果图构建"""
    print("\n" + "=" * 70)
    print("  阶段二：因果图构建")
    print("=" * 70)
    
    # 导入模块
    sys.path.insert(0, str(Path(__file__).parent / "step2_causal_graph"))
    from step2_causal_graph.graph_builder import CausalGraphBuilder
    from step2_causal_graph.visualizer import CausalGraphVisualizer
    
    # 加载告警数据
    with open(alerts_path, 'r', encoding='utf-8') as f:
        alerts = json.load(f)
    
    print(f"\n  加载 {len(alerts)} 条告警数据")
    
    # 构建因果图
    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(alerts)
    
    # 保存
    output_dir = "step2_causal_graph/output"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "causal_graph.json")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, ensure_ascii=False, indent=2)
    
    # 生成Mermaid
    mermaid_path = os.path.join(output_dir, "causal_graph.mmd")
    CausalGraphVisualizer.save_mermaid(graph_data, mermaid_path, "APT Attack Causal Graph")
    
    # 统计
    print(f"\n  因果图统计:")
    print(f"    节点数: {len(graph_data['nodes'])}")
    print(f"    边数: {len(graph_data['edges'])}")
    print(f"    三元组数: {len(graph_data['triples'])}")
    
    # 节点类型分布
    node_types = {}
    for node in graph_data['nodes']:
        ntype = node.get('type', 'unknown')
        node_types[ntype] = node_types.get(ntype, 0) + 1
    print(f"    节点类型: {node_types}")
    
    # 边类型分布
    edge_types = {}
    for edge in graph_data['edges']:
        action = edge.get('action', 'unknown')
        edge_types[action] = edge_types.get(action, 0) + 1
    print(f"    边类型: {edge_types}")
    
    print(f"\n  [✓] 因果图已保存: {output_path}")
    print(f"  [✓] Mermaid已保存: {mermaid_path}")
    
    return output_path, graph_data


def run_step3_dqn_pruning(graph_path):
    """运行第三步：DQN裁剪"""
    print("\n" + "=" * 70)
    print("  阶段三：DQN图谱裁剪")
    print("=" * 70)
    
    # 导入模块
    sys.path.insert(0, str(Path(__file__).parent / "step3_dqn_pruning"))
    from step3_dqn_pruning.graph_loader import load_graph_from_file, generate_synthetic_labels, load_graphs_for_training
    from step3_dqn_pruning.model import DynamicEdgeQNetwork
    from step3_dqn_pruning.trainer import DQNTrainer, compute_graph_metrics
    
    print("\n  [1] 加载因果图数据...")
    
    # 加载图
    data = load_graph_from_file(graph_path)
    data = generate_synthetic_labels(data, core_ratio=0.35)
    
    print(f"    节点数: {data.x.size(0)}")
    print(f"    边数: {data.edge_index.size(1)}")
    print(f"    核心边比例: {data.y.sum().item() / data.y.size(0) * 100:.1f}%")
    
    print("\n  [2] 生成训练数据...")
    train_graphs = load_graphs_for_training(graph_path, num_graphs=200, augment=True)
    val_graphs = load_graphs_for_training(graph_path, num_graphs=40, augment=True)
    test_graphs = load_graphs_for_training(graph_path, num_graphs=60, augment=False)
    
    print(f"    训练集: {len(train_graphs)} 图")
    print(f"    验证集: {len(val_graphs)} 图")
    print(f"    测试集: {len(test_graphs)} 图")
    
    print("\n  [3] 初始化DQN模型...")
    trainer = DQNTrainer(
        node_feat_dim=16,
        hidden_dim=128,
        out_dim=64,
        lr=5e-4,
        epochs=100,
        patience=30
    )
    
    print("\n  [4] 开始训练...")
    save_path = "step3_dqn_pruning/output/checkpoints/dqn_best.pt"
    trainer.train(train_graphs, val_graphs, save_path=save_path)
    
    print("\n  [5] 测试集评估...")
    metrics = trainer.evaluate_on_test(test_graphs)
    
    print("\n  [6] 执行图谱裁剪...")
    pruned_path = "step3_dqn_pruning/output/pruned_graph.json"
    pruned_data = trainer.predict_and_prune(graph_path, pruned_path)
    
    return pruned_path, metrics


def run_step4_graph_to_text(pruned_path):
    """运行第四步：Graph-to-Text"""
    print("\n" + "=" * 70)
    print("  阶段四：Graph-to-Text 转换")
    print("=" * 70)
    
    # 导入模块
    sys.path.insert(0, str(Path(__file__).parent / "step4_graph_to_text"))
    from step4_graph_to_text.converter import GraphToTextConverter
    
    # 加载裁剪后的图
    with open(pruned_path, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    print(f"\n  加载裁剪后的因果图:")
    print(f"    节点数: {len(graph_data.get('nodes', []))}")
    print(f"    边数: {len(graph_data.get('edges', []))}")
    
    if 'pruning_stats' in graph_data:
        stats = graph_data['pruning_stats']
        print(f"    压缩率: {stats.get('compression_ratio', 'N/A')}")
    
    converter = GraphToTextConverter()
    
    # 生成不同类型的提示词
    output_dir = "step4_graph_to_text/output"
    os.makedirs(output_dir, exist_ok=True)
    
    tasks = [
        ("intent_analysis", "意图分析"),
        ("ttp_mapping", "TTP映射"),
        ("report", "事件报告")
    ]
    
    for task_type, task_name in tasks:
        print(f"\n  生成{task_name}提示词...")
        text = converter.convert_to_llm_prompt(graph_data, task_type)
        
        output_path = os.path.join(output_dir, f"llm_prompt_{task_type}.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
        
        print(f"    [✓] 已保存: {output_path} ({len(text)} 字符)")
    
    # 显示意图分析预览
    print("\n  " + "-" * 50)
    print("  意图分析提示词预览:")
    print("  " + "-" * 50)
    preview = converter.convert_to_llm_prompt(graph_data, "intent_analysis")
    # 显示前500字符
    for line in preview[:800].split('\n')[:20]:
        print(f"    {line}")
    print("    ...")
    
    return output_dir


def generate_experiment_report(alerts, graph_data, dqn_metrics, output_dir):
    """生成实验报告"""
    print("\n" + "=" * 70)
    print("  生成实验报告")
    print("=" * 70)
    
    report = {
        "experiment_name": "基于蜜点技术的APT攻击检测与意图推理系统",
        "timestamp": datetime.now().isoformat(),
        
        "phase1_data_collection": {
            "total_alerts": len(alerts),
            "alert_types": {
                "account": len([a for a in alerts if a["alert_type"] == "account"]),
                "file": len([a for a in alerts if a["alert_type"] == "file"]),
                "audit": len([a for a in alerts if a["alert_type"] == "audit"]),
                "parasitic": len([a for a in alerts if a["alert_type"] == "parasitic"])
            },
            "time_range": {
                "start": alerts[0]["timestamp"],
                "end": alerts[-1]["timestamp"]
            }
        },
        
        "phase2_causal_graph": {
            "nodes": len(graph_data.get("nodes", [])),
            "edges": len(graph_data.get("edges", [])),
            "triples": len(graph_data.get("triples", []))
        },
        
        "phase3_dqn_pruning": dqn_metrics,
        
        "phase4_graph_to_text": {
            "output_files": [
                "llm_prompt_intent_analysis.txt",
                "llm_prompt_ttp_mapping.txt",
                "llm_prompt_report.txt"
            ]
        }
    }
    
    # 保存报告
    report_path = "experiment_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print(f"\n  [✓] 实验报告已保存: {report_path}")
    
    # 打印报告摘要
    print("\n  " + "=" * 50)
    print("  实验报告摘要")
    print("=" * 50)
    print(f"  实验名称: {report['experiment_name']}")
    print(f"  实验时间: {report['timestamp']}")
    print(f"\n  阶段1 - 数据采集:")
    print(f"    总告警数: {report['phase1_data_collection']['total_alerts']}")
    print(f"    告警类型: {report['phase1_data_collection']['alert_types']}")
    print(f"\n  阶段2 - 因果图构建:")
    print(f"    节点数: {report['phase2_causal_graph']['nodes']}")
    print(f"    边数: {report['phase2_causal_graph']['edges']}")
    print(f"    三元组: {report['phase2_causal_graph']['triples']}")
    print(f"\n  阶段3 - DQN裁剪:")
    print(f"    准确率: {dqn_metrics.get('accuracy', 0):.4f}")
    print(f"    F1分数: {dqn_metrics.get('f1', 0):.4f}")
    print(f"    核心边召回率: {dqn_metrics.get('core_recall', 0):.4f}")
    print(f"\n  阶段4 - Graph-to-Text:")
    print(f"    输出文件: {len(report['phase4_graph_to_text']['output_files'])} 个")
    
    return report


def main():
    print("\n" + "=" * 70)
    print("  基于蜜点技术的APT攻击检测与意图推理系统")
    print("  端到端实验验证")
    print("=" * 70)
    
    # 阶段1：创建攻击场景数据
    alerts = create_realistic_attack_scenario()
    alerts_path = save_alerts(alerts)
    
    # 阶段2：因果图构建
    graph_path, graph_data = run_step2_causal_graph(alerts_path)
    
    # 阶段3：DQN裁剪
    pruned_path, dqn_metrics = run_step3_dqn_pruning(graph_path)
    
    # 阶段4：Graph-to-Text
    output_dir = run_step4_graph_to_text(pruned_path)
    
    # 生成实验报告
    report = generate_experiment_report(alerts, graph_data, dqn_metrics, output_dir)
    
    print("\n" + "=" * 70)
    print("  实验完成！")
    print("=" * 70)
    print("\n  输出文件:")
    print("    1. step1_data_collection/output/unified_alerts.json")
    print("    2. step2_causal_graph/output/causal_graph.json")
    print("    3. step2_causal_graph/output/causal_graph.mmd")
    print("    4. step3_dqn_pruning/output/pruned_graph.json")
    print("    5. step3_dqn_pruning/output/checkpoints/dqn_best.pt")
    print("    6. step4_graph_to_text/output/llm_prompt_*.txt")
    print("    7. experiment_report.json")


if __name__ == "__main__":
    main()
