import torch
import torch.nn as nn
import torch.optim as optim
import random
import os
from dqn_model import DynamicEdgeQNetwork
from data_utils import generate_dataset
from config import cfg


# ============================================================
#  Focal Loss
# ============================================================
def focal_loss(logits, targets, alpha=0.75, gamma=2.0):
    p = torch.sigmoid(logits)
    p_t = p * targets + (1 - p) * (1 - targets)
    alpha_t = alpha * targets + (1 - alpha) * (1 - targets)
    return -(alpha_t * (1 - p_t) ** gamma * torch.log(p_t + 1e-8)).mean()


# ============================================================
#  评估
# ============================================================
def compute_graph_metrics(model, data, device, epsilon=0.0):
    model.eval()
    with torch.no_grad():
        qv, _ = model(data.x, data.edge_index)
        E = data.edge_index.size(1)
        actions = []
        for i in range(E):
            if random.random() < epsilon:
                actions.append(random.randint(0, 1))
            else:
                actions.append(qv[i].argmax().item())
        actions = torch.tensor(actions)
        y = data.y.long()

        ckc = ((actions == 0) & (y == 1)).sum().item()
        cpr = ((actions == 1) & (y == 0)).sum().item()
        wpc = ((actions == 1) & (y == 1)).sum().item()
        wkr = ((actions == 0) & (y == 0)).sum().item()
        t = max(E, 1)

        acc = (ckc + cpr) / t
        prec = cpr / max(cpr + wpc, 1)
        rec = cpr / max(cpr + wkr, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-8)
        cr = ckc / max(ckc + wpc, 1)
        tr = (cpr * cfg.reward_prune_redundant + ckc * cfg.reward_keep_core
              + wpc * cfg.penalty_prune_core + wkr * cfg.penalty_keep_redundant)

        return {'accuracy': acc, 'precision': prec, 'recall': rec,
                'f1': f1, 'core_recall': cr, 'total_reward': tr,
                'ckc': ckc, 'cpr': cpr, 'wpc': wpc, 'wkr': wkr}


def evaluate_set(model, graphs, device):
    all_m = [compute_graph_metrics(model, g.to(device), device) for g in graphs]
    return {k: sum(m[k] for m in all_m) / len(all_m) for k in all_m[0]}


# ============================================================
#  Q-Network 训练 (监督: Focal Loss → Q 值即为策略)
# ============================================================
def train_q_network(model, train_graphs, val_graphs, device):
    """
    用 Focal Loss 训练 Q-Network。
    训练完成后, Q_keep > Q_prune 表示保留, 反之为裁剪。
    这等价于 gamma=0 的 DQN 最优策略 (Q(s,a) = E[r|s,a])。
    """
    print("\n[Q-Network 训练] Focal Loss + GAT Encoder")
    print(f"  核心边权重 α={cfg.focal_alpha}, γ={cfg.focal_gamma}")
    print(f"  学习率 {cfg.pretrain_lr}, {cfg.pretrain_epochs} epochs")

    opt = optim.AdamW(model.parameters(), lr=cfg.pretrain_lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=cfg.pretrain_epochs)
    best_val_f1 = 0.0
    best_state = None
    patience = 30
    no_improve = 0

    for ep in range(1, cfg.pretrain_epochs + 1):
        model.train()
        total_loss, n = 0.0, 0
        for g in train_graphs:
            g = g.to(device)
            qv, _ = model(g.x, g.edge_index)
            logits = qv[:, 0] - qv[:, 1]
            loss = focal_loss(logits, g.y, cfg.focal_alpha, cfg.focal_gamma)
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 3.0)
            opt.step()
            total_loss += loss.item(); n += 1
        scheduler.step()

        if ep % 10 == 0 or ep == 1:
            val_m = evaluate_set(model, val_graphs, device)
            tr_m = evaluate_set(model, train_graphs[:10], device)
            print(f"  Ep {ep:3d}/{cfg.pretrain_epochs} | Loss: {total_loss/n:.4f} | "
                  f"Tr F1: {tr_m['f1']:.3f} CR: {tr_m['core_recall']:.3f} | "
                  f"Val F1: {val_m['f1']:.3f} CR: {val_m['core_recall']:.3f}")

            if val_m['f1'] > best_val_f1 + 1e-4:
                best_val_f1 = val_m['f1']
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                no_improve = 0
            else:
                no_improve += 1

            if no_improve >= patience:
                print(f"  早停 ({patience} epochs 未提升)")
                break

    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"  恢复最优 (Val F1: {best_val_f1:.3f})")
    return model


# ============================================================
#  主训练入口
# ============================================================
def train():
    print("=" * 60)
    print("  DQN 攻击图谱裁剪 — 训练")
    print("  方法: GAT 编码器 + Q-Network (Focal Loss)")
    print("  推理: 每条边输出 Q_keep/Q_prune, argmax 决策")
    print("=" * 60)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"\n  设备: {device}")
    os.makedirs("checkpoints", exist_ok=True)

    # ==== 数据 ====
    print("\n[1/3] 生成数据...")
    train_g = generate_dataset(cfg.num_train_graphs)
    val_g = generate_dataset(cfg.num_val_graphs)
    test_g = generate_dataset(cfg.num_test_graphs)

    tc = sum(int(g.y.sum()) for g in train_g)
    te = sum(g.y.size(0) for g in train_g)
    print(f"  训练: {len(train_g)} | 验证: {len(val_g)} | 测试: {len(test_g)}")
    print(f"  核心边占比: {tc}/{te} = {100*tc/te:.1f}%")

    # 统计测试集分布
    test_core = sum(int(g.y.sum()) for g in test_g)
    test_total = sum(g.y.size(0) for g in test_g)
    print(f"  测试集核心边: {test_core}/{test_total} = {100*test_core/test_total:.1f}%")

    # ==== 模型 ====
    print("\n[2/3] 初始化模型 (GAT + Q-Network)...")
    model = DynamicEdgeQNetwork().to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"  参数: {n_params:,}")

    # ==== 训练 ====
    print("\n[3/3] 开始训练...")
    pt_graphs = train_g[:min(cfg.pretrain_graphs, len(train_g))]
    model = train_q_network(model, pt_graphs, val_g, device)

    # ==== 测试集评估 ====
    print("\n" + "=" * 60)
    print("  测试集最终评估")
    print("=" * 60)
    fm = evaluate_set(model, test_g, device)
    print(f"  准确率:         {fm['accuracy']:.4f}")
    print(f"  精确率:         {fm['precision']:.4f}")
    print(f"  召回率:         {fm['recall']:.4f}")
    print(f"  F1:             {fm['f1']:.4f}")
    print(f"  核心边召回率:   {fm['core_recall']:.4f}  <-- 最关键: 攻击链保留率")
    print(f"  正确保留核心:   {fm['ckc']:.1f}  (不该剪的攻击边)")
    print(f"  正确裁剪冗余:   {fm['cpr']:.1f} (该剪的噪音边)")
    print(f"  错误裁剪核心:   {fm['wpc']:.1f}  (剪错了! 攻击链断了)")
    print(f"  错误保留冗余:   {fm['wkr']:.1f} (没剪干净)")
    print(f"  总奖励:         {fm['total_reward']:.1f}")
    print("=" * 60)

    # 逐图展示几个例子
    print("\n--- 样例 ---")
    for i in range(3):
        g = test_g[i].to(device)
        m = compute_graph_metrics(model, g, device)
        n_nodes = g.x.size(0)
        n_edges = g.edge_index.size(1)
        n_core = int(g.y.sum())
        print(f"  Graph {i}: {n_nodes} nodes, {n_edges} edges ({n_core} core) | "
              f"Acc={m['accuracy']:.3f} F1={m['f1']:.3f} CR={m['core_recall']:.3f}")

    # 保存
    torch.save(model.state_dict(), cfg.model_save_path)
    print(f"\n  模型已保存: {cfg.model_save_path}")


if __name__ == "__main__":
    train()
