"""
使用真实因果图数据训练DQN模型
整合 data_collector 和 shiyan 模块
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import sys
from pathlib import Path

# 添加父目录到路径
sys.path.append(str(Path(__file__).parent.parent / "data_collector"))

from dqn_model import DynamicEdgeQNetwork
from attack_env import AttackGraphEnv
from config import cfg
from graph_loader import (
    load_graph_from_file, 
    load_graphs_for_training,
    generate_synthetic_labels,
    get_graph_statistics
)


def focal_loss(logits, targets, alpha=0.75, gamma=2.0):
    """Focal Loss for imbalanced classification"""
    p = torch.sigmoid(logits)
    p_t = p * targets + (1 - p) * (1 - targets)
    alpha_t = alpha * targets + (1 - alpha) * (1 - targets)
    return -(alpha_t * (1 - p_t) ** gamma * torch.log(p_t + 1e-8)).mean()


def compute_graph_metrics(model, data, device, epsilon=0.0):
    """计算单个图的评估指标"""
    model.eval()
    with torch.no_grad():
        qv, _ = model(data.x, data.edge_index)
        E = data.edge_index.size(1)
        actions = []
        for i in range(E):
            if np.random.random() < epsilon:
                actions.append(np.random.randint(0, 2))
            else:
                actions.append(qv[i].argmax().item())
        actions = torch.tensor(actions)
        y = data.y.long()

        ckc = ((actions == 0) & (y == 1)).sum().item()  # 正确保留核心
        cpr = ((actions == 1) & (y == 0)).sum().item()  # 正确裁剪冗余
        wpc = ((actions == 1) & (y == 1)).sum().item()  # 错误裁剪核心
        wkr = ((actions == 0) & (y == 0)).sum().item()  # 错误保留冗余
        t = max(E, 1)

        acc = (ckc + cpr) / t
        prec = cpr / max(cpr + wpc, 1)
        rec = cpr / max(cpr + wkr, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-8)
        cr = ckc / max(ckc + wpc, 1)  # 核心边召回率
        tr = (cpr * cfg.reward_prune_redundant + ckc * cfg.reward_keep_core
              + wpc * cfg.penalty_prune_core + wkr * cfg.penalty_keep_redundant)

        return {'accuracy': acc, 'precision': prec, 'recall': rec,
                'f1': f1, 'core_recall': cr, 'total_reward': tr,
                'ckc': ckc, 'cpr': cpr, 'wpc': wpc, 'wkr': wkr}


def evaluate_set(model, graphs, device):
    """评估一组图"""
    all_m = [compute_graph_metrics(model, g.to(device), device) for g in graphs]
    return {k: sum(m[k] for m in all_m) / len(all_m) for k in all_m[0]}


def train_with_real_data(
    causal_graph_path: str,
    num_train: int = 100,
    num_val: int = 20,
    num_test: int = 30,
    epochs: int = 120,
    batch_size: int = 32,
    save_path: str = "checkpoints/dqn_real_best.pt"
):
    """
    使用真实因果图数据训练DQN模型
    
    Args:
        causal_graph_path: 因果图JSON文件路径
        num_train: 训练图数量
        num_val: 验证图数量
        num_test: 测试图数量
        epochs: 训练轮数
        batch_size: 批次大小
        save_path: 模型保存路径
    """
    print("=" * 60)
    print("  DQN 攻击图谱裁剪 — 真实数据训练")
    print("=" * 60)
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"\n  设备: {device}")
    
    # 创建保存目录
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    # ==================== 1. 加载数据 ====================
    print("\n[1/3] 加载因果图数据...")
    
    # 检查文件是否存在
    if not os.path.exists(causal_graph_path):
        print(f"[-] 因果图文件不存在: {causal_graph_path}")
        print("[*] 请先运行 data_collector/main.py demo 生成因果图")
        return None
    
    # 显示图统计信息
    stats = get_graph_statistics(causal_graph_path)
    print(f"  原始图统计:")
    print(f"    节点数: {stats['num_nodes']}")
    print(f"    边数: {stats['num_edges']}")
    print(f"    节点类型: {stats['node_types']}")
    print(f"    边类型: {stats['edge_types']}")
    
    # 生成训练数据（通过数据增强）
    print(f"\n  生成训练数据...")
    train_graphs = load_graphs_for_training(causal_graph_path, num_train, augment=True)
    val_graphs = load_graphs_for_training(causal_graph_path, num_val, augment=True)
    test_graphs = load_graphs_for_training(causal_graph_path, num_test, augment=False)
    
    # 统计标签分布
    train_core = sum(int(g.y.sum()) for g in train_graphs)
    train_total = sum(g.y.size(0) for g in train_graphs)
    print(f"  训练集: {len(train_graphs)} 图, 核心边: {train_core}/{train_total} ({100*train_core/train_total:.1f}%)")
    print(f"  验证集: {len(val_graphs)} 图")
    print(f"  测试集: {len(test_graphs)} 图")
    
    # ==================== 2. 初始化模型 ====================
    print("\n[2/3] 初始化模型...")
    model = DynamicEdgeQNetwork().to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"  模型参数: {n_params:,}")
    
    # ==================== 3. 训练 ====================
    print("\n[3/3] 开始训练...")
    model = train_q_network(
        model, train_graphs, val_graphs, device,
        epochs=epochs, lr=cfg.pretrain_lr, save_path=save_path
    )
    
    # ==================== 4. 测试集评估 ====================
    print("\n" + "=" * 60)
    print("  测试集最终评估")
    print("=" * 60)
    
    # 加载最佳模型
    if os.path.exists(save_path):
        model.load_state_dict(torch.load(save_path, map_location=device))
    
    fm = evaluate_set(model, test_graphs, device)
    print(f"  准确率:         {fm['accuracy']:.4f}")
    print(f"  精确率:         {fm['precision']:.4f}")
    print(f"  召回率:         {fm['recall']:.4f}")
    print(f"  F1:             {fm['f1']:.4f}")
    print(f"  核心边召回率:   {fm['core_recall']:.4f}  <-- 最关键指标")
    print(f"  正确保留核心:   {fm['ckc']:.1f}")
    print(f"  正确裁剪冗余:   {fm['cpr']:.1f}")
    print(f"  错误裁剪核心:   {fm['wpc']:.1f}")
    print(f"  错误保留冗余:   {fm['wkr']:.1f}")
    print(f"  总奖励:         {fm['total_reward']:.1f}")
    print("=" * 60)
    
    # ==================== 5. 保存结果 ====================
    results_path = save_path.replace('.pt', '_results.json')
    import json
    results = {
        "model_path": save_path,
        "causal_graph_path": causal_graph_path,
        "training_config": {
            "num_train": num_train,
            "num_val": num_val,
            "num_test": num_test,
            "epochs": epochs,
            "learning_rate": cfg.pretrain_lr
        },
        "test_metrics": fm,
        "graph_stats": stats
    }
    
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n  结果已保存到: {results_path}")
    
    return model


def train_q_network(model, train_graphs, val_graphs, device, 
                    epochs=120, lr=1e-3, save_path="checkpoints/dqn_best.pt"):
    """训练Q-Network"""
    print(f"\n  训练配置: epochs={epochs}, lr={lr}")
    print(f"  核心边权重: α={cfg.focal_alpha}, γ={cfg.focal_gamma}")
    
    opt = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    best_val_f1 = 0.0
    best_state = None
    patience = 30
    no_improve = 0

    for ep in range(1, epochs + 1):
        model.train()
        total_loss, n = 0.0, 0
        for g in train_graphs:
            g = g.to(device)
            qv, _ = model(g.x, g.edge_index)
            logits = qv[:, 0] - qv[:, 1]
            loss = focal_loss(logits, g.y, cfg.focal_alpha, cfg.focal_gamma)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 3.0)
            opt.step()
            total_loss += loss.item()
            n += 1
        scheduler.step()

        if ep % 10 == 0 or ep == 1:
            val_m = evaluate_set(model, val_graphs, device)
            tr_m = evaluate_set(model, train_graphs[:10], device)
            print(f"  Ep {ep:3d}/{epochs} | Loss: {total_loss/n:.4f} | "
                  f"Tr F1: {tr_m['f1']:.3f} CR: {tr_m['core_recall']:.3f} | "
                  f"Val F1: {val_m['f1']:.3f} CR: {val_m['core_recall']:.3f}")

            if val_m['f1'] > best_val_f1 + 1e-4:
                best_val_f1 = val_m['f1']
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                no_improve = 0
                # 保存最佳模型
                torch.save(best_state, save_path)
            else:
                no_improve += 1

            if no_improve >= patience:
                print(f"  早停 ({patience} epochs 未提升)")
                break

    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"  恢复最优 (Val F1: {best_val_f1:.3f})")
    return model


def predict_attack_graph(model_path: str, causal_graph_path: str, output_path: str = None):
    """
    使用训练好的模型对因果图进行预测
    
    Args:
        model_path: 模型文件路径
        causal_graph_path: 因果图文件路径
        output_path: 输出裁剪后的图路径
    """
    import json
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # 加载模型
    model = DynamicEdgeQNetwork().to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    
    # 加载因果图
    data = load_graph_from_file(causal_graph_path)
    data = generate_synthetic_labels(data)  # 生成标签
    data = data.to(device)
    
    # 预测
    with torch.no_grad():
        qv, _ = model(data.x, data.edge_index)
        actions = qv.argmax(dim=1)
    
    # 统计结果
    num_edges = data.edge_index.size(1)
    keep_count = (actions == 0).sum().item()
    prune_count = (actions == 1).sum().item()
    
    print(f"\n[*] 预测结果:")
    print(f"  总边数: {num_edges}")
    print(f"  保留: {keep_count} ({100*keep_count/num_edges:.1f}%)")
    print(f"  裁剪: {prune_count} ({100*prune_count/num_edges:.1f}%)")
    
    # 生成裁剪后的图
    if output_path:
        # 加载原始图数据
        with open(causal_graph_path, 'r', encoding='utf-8') as f:
            graph_data = json.load(f)
        
        # 保留的边
        edges = graph_data.get("edges", [])
        kept_edges = []
        
        for i, edge in enumerate(edges):
            if i < len(actions) and actions[i].item() == 0:
                kept_edges.append(edge)
        
        graph_data["edges"] = kept_edges
        graph_data["pruning_stats"] = {
            "original_edges": num_edges,
            "kept_edges": keep_count,
            "pruned_edges": prune_count,
            "compression_ratio": f"{100*prune_count/num_edges:.1f}%"
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        
        print(f"  裁剪后的图已保存到: {output_path}")
    
    return actions, qv


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DQN攻击图谱裁剪训练")
    parser.add_argument("--mode", choices=["train", "predict"], default="train",
                        help="运行模式: train=训练, predict=预测")
    parser.add_argument("--graph", type=str, 
                        default="../data_collector/output/causal_graph.json",
                        help="因果图文件路径")
    parser.add_argument("--model", type=str, default="checkpoints/dqn_real_best.pt",
                        help="模型文件路径")
    parser.add_argument("--epochs", type=int, default=120, help="训练轮数")
    parser.add_argument("--output", type=str, default="../data_collector/output/pruned_graph.json",
                        help="裁剪后的图输出路径")
    
    args = parser.parse_args()
    
    if args.mode == "train":
        train_with_real_data(
            causal_graph_path=args.graph,
            epochs=args.epochs,
            save_path=args.model
        )
    elif args.mode == "predict":
        predict_attack_graph(
            model_path=args.model,
            causal_graph_path=args.graph,
            output_path=args.output
        )
