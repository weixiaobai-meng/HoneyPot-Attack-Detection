"""
第三步：DQN训练器
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import json
from typing import List

from .model import DynamicEdgeQNetwork
from .environment import AttackGraphEnv
from .graph_loader import load_graphs_for_training, load_graph_from_file, generate_synthetic_labels


def focal_loss(logits, targets, alpha=0.75, gamma=2.0):
    """Focal Loss"""
    p = torch.sigmoid(logits)
    p_t = p * targets + (1 - p) * (1 - targets)
    alpha_t = alpha * targets + (1 - alpha) * (1 - targets)
    return -(alpha_t * (1 - p_t) ** gamma * torch.log(p_t + 1e-8)).mean()


def compute_graph_metrics(model, data, device):
    """计算单个图的评估指标"""
    model.eval()
    with torch.no_grad():
        qv, _ = model(data.x.to(device), data.edge_index.to(device))
        actions = qv.argmax(dim=1).cpu()
        y = data.y.long()

        ckc = ((actions == 0) & (y == 1)).sum().item()
        cpr = ((actions == 1) & (y == 0)).sum().item()
        wpc = ((actions == 1) & (y == 1)).sum().item()
        wkr = ((actions == 0) & (y == 0)).sum().item()
        t = max(data.edge_index.size(1), 1)

        acc = (ckc + cpr) / t
        prec = cpr / max(cpr + wpc, 1)
        rec = cpr / max(cpr + wkr, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-8)
        cr = ckc / max(ckc + wpc, 1)

        return {
            'accuracy': acc, 'precision': prec, 'recall': rec,
            'f1': f1, 'core_recall': cr,
            'ckc': ckc, 'cpr': cpr, 'wpc': wpc, 'wkr': wkr
        }


class DQNTrainer:
    """DQN训练器"""
    
    def __init__(self, 
                 node_feat_dim=16,
                 hidden_dim=128,
                 out_dim=64,
                 lr=1e-3,
                 epochs=120,
                 patience=30,
                 device=None):
        
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.lr = lr
        self.epochs = epochs
        self.patience = patience
        
        # 初始化模型
        self.model = DynamicEdgeQNetwork(
            node_feat_dim=node_feat_dim,
            hidden_dim=hidden_dim,
            out_dim=out_dim
        ).to(self.device)
        
        print(f"[*] 设备: {self.device}")
        print(f"[*] 模型参数: {sum(p.numel() for p in self.model.parameters()):,}")
    
    def train(self, 
              train_graphs: List,
              val_graphs: List,
              save_path: str = "output/checkpoints/dqn_best.pt"):
        """
        训练模型
        
        Args:
            train_graphs: 训练图列表
            val_graphs: 验证图列表
            save_path: 模型保存路径
        """
        print(f"\n[*] 开始训练...")
        print(f"    训练集: {len(train_graphs)} 图")
        print(f"    验证集: {len(val_graphs)} 图")
        print(f"    epochs: {self.epochs}, lr: {self.lr}")
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        opt = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=self.epochs)
        
        best_val_f1 = 0.0
        best_state = None
        no_improve = 0
        
        for ep in range(1, self.epochs + 1):
            # 训练
            self.model.train()
            total_loss, n = 0.0, 0
            for g in train_graphs:
                g = g.to(self.device)
                qv, _ = self.model(g.x, g.edge_index)
                logits = qv[:, 0] - qv[:, 1]
                loss = focal_loss(logits, g.y, alpha=0.75, gamma=2.0)
                
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 3.0)
                opt.step()
                
                total_loss += loss.item()
                n += 1
            
            scheduler.step()
            
            # 评估
            if ep % 10 == 0 or ep == 1:
                val_m = self._evaluate(val_graphs)
                tr_m = self._evaluate(train_graphs[:10])
                
                print(f"  Ep {ep:3d}/{self.epochs} | Loss: {total_loss/n:.4f} | "
                      f"Tr F1: {tr_m['f1']:.3f} CR: {tr_m['core_recall']:.3f} | "
                      f"Val F1: {val_m['f1']:.3f} CR: {val_m['core_recall']:.3f}")
                
                if val_m['f1'] > best_val_f1 + 1e-4:
                    best_val_f1 = val_m['f1']
                    best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
                    no_improve = 0
                    torch.save(best_state, save_path)
                else:
                    no_improve += 1
                
                if no_improve >= self.patience:
                    print(f"  早停 ({self.patience} epochs 未提升)")
                    break
        
        if best_state:
            self.model.load_state_dict(best_state)
            print(f"  恢复最优 (Val F1: {best_val_f1:.3f})")
        
        return self.model
    
    def _evaluate(self, graphs):
        """评估一组图"""
        if not graphs:
            return {
                'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0,
                'f1': 0.0, 'core_recall': 0.0,
                'ckc': 0.0, 'cpr': 0.0, 'wpc': 0.0, 'wkr': 0.0
            }
        metrics = [compute_graph_metrics(self.model, g, self.device) for g in graphs]
        return {k: sum(m[k] for m in metrics) / len(metrics) for k in metrics[0]}
    
    def evaluate_on_test(self, test_graphs):
        """在测试集上评估"""
        print("\n[*] 测试集评估:")
        metrics = self._evaluate(test_graphs)
        print(f"  准确率:       {metrics['accuracy']:.4f}")
        print(f"  精确率:       {metrics['precision']:.4f}")
        print(f"  召回率:       {metrics['recall']:.4f}")
        print(f"  F1:           {metrics['f1']:.4f}")
        print(f"  核心边召回率: {metrics['core_recall']:.4f}")
        return metrics
    
    def predict_and_prune(self, graph_path: str, output_path: str):
        """预测并裁剪因果图"""
        # 加载模型
        self.model.eval()
        
        # 加载图
        data = load_graph_from_file(graph_path)
        data = generate_synthetic_labels(data)
        data = data.to(self.device)
        
        # 预测
        with torch.no_grad():
            qv, _ = self.model(data.x, data.edge_index)
            actions = qv.argmax(dim=1)
        
        # 统计
        num_edges = data.edge_index.size(1)
        keep_count = (actions == 0).sum().item()
        prune_count = (actions == 1).sum().item()
        
        print(f"\n[*] 裁剪结果:")
        print(f"  总边数: {num_edges}")
        if num_edges > 0:
            print(f"  保留: {keep_count} ({100*keep_count/num_edges:.1f}%)")
            print(f"  裁剪: {prune_count} ({100*prune_count/num_edges:.1f}%)")
        else:
            print("  保留: 0 (0.0%)")
            print("  裁剪: 0 (0.0%)")
        
        # 生成裁剪后的图
        with open(graph_path, 'r', encoding='utf-8') as f:
            graph_data = json.load(f)
        
        edges = graph_data.get("edges", [])
        kept_edges = [edge for i, edge in enumerate(edges) if i < len(actions) and actions[i].item() == 0]
        
        graph_data["edges"] = kept_edges
        graph_data["pruning_stats"] = {
            "original_edges": num_edges,
            "kept_edges": keep_count,
            "pruned_edges": prune_count,
            "compression_ratio": f"{(100*prune_count/num_edges):.1f}%" if num_edges > 0 else "0.0%"
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        
        print(f"  裁剪后的图已保存到: {output_path}")
        
        return graph_data
    
    def save_results(self, metrics, config, output_path):
        """保存训练结果"""
        results = {
            "config": config,
            "test_metrics": metrics
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"[+] 结果已保存到: {output_path}")
