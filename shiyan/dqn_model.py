import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv
import random
from collections import deque
from config import cfg


class ResidualGATLayer(nn.Module):
    """带残差连接的 GAT 层"""
    def __init__(self, in_dim, out_dim, heads=4):
        super().__init__()
        self.gat = GATConv(in_dim, out_dim // heads, heads=heads, dropout=cfg.dropout)
        self.norm = nn.LayerNorm(out_dim)
        self.skip = nn.Linear(in_dim, out_dim) if in_dim != out_dim else nn.Identity()

    def forward(self, x, edge_index):
        h = self.gat(x, edge_index)
        h = self.norm(h + self.skip(x))
        return F.elu(h)


class GNNEncoder(nn.Module):
    """
    增强版 GNN: 4 层 GAT + 残差连接, 更强的图表征能力。
    """
    def __init__(self):
        super().__init__()
        dims = [cfg.node_feat_dim, 128, 128, 64, cfg.out_dim]
        self.layers = nn.ModuleList([
            ResidualGATLayer(dims[i], dims[i + 1], heads=4 if i < 2 else 2)
            for i in range(len(dims) - 1)
        ])
        self.dropout = nn.Dropout(cfg.dropout)

    def forward(self, x, edge_index):
        for i, layer in enumerate(self.layers):
            x = layer(x, edge_index)
            if i < len(self.layers) - 1:
                x = self.dropout(x)
        return x  # (N, out_dim)


class EdgeQNetwork(nn.Module):
    """
    边级 Q 网络 — 使用纯 GNN 边嵌入, 输出 [Q_keep, Q_prune]。
    架构: edge_emb → [256] → [128] → [64] → 2
    """
    def __init__(self):
        super().__init__()
        in_dim = cfg.out_dim * 2
        self.net = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Linear(64, 2),
        )

    def forward(self, edge_embs):
        return self.net(edge_embs)  # (E, 2)


class DynamicEdgeQNetwork(nn.Module):
    """
    DQN 边裁剪策略网络。
    - encoder: GAT 图编码器 → 节点嵌入
    - q_net:   边嵌入 → [Q_keep, Q_prune]
    - 决策: argmax(Q) → 0=保留, 1=裁剪
    """
    def __init__(self):
        super().__init__()
        self.encoder = GNNEncoder()
        self.q_net = EdgeQNetwork()

    def forward(self, x, edge_index):
        h = self.encoder(x, edge_index)
        src, dst = edge_index[0], edge_index[1]
        edge_embs = torch.cat([h[src], h[dst]], dim=-1)
        q_values = self.q_net(edge_embs)
        return q_values, h

    @torch.no_grad()
    def predict(self, data):
        """对一张图谱的所有边返回 keep/prune 决策。
        Args:
            data: torch_geometric Data (x, edge_index)
        Returns:
            actions: (E,) tensor, 0=保留, 1=裁剪
            q_values: (E, 2) tensor, [Q_keep, Q_prune]
        """
        self.eval()
        qv, _ = self.forward(data.x, data.edge_index)
        actions = qv.argmax(dim=1)
        return actions, qv


class BalancedReplayBuffer:
    def __init__(self, capacity):
        self.buf_core = deque(maxlen=capacity // 2)
        self.buf_red = deque(maxlen=capacity // 2)

    def push(self, state, action, reward, next_state, is_core):
        e = (state, action, reward, next_state)
        (self.buf_core if is_core else self.buf_red).append(e)

    def sample(self, batch_size):
        nc = min(batch_size // 2, len(self.buf_core))
        nr = min(batch_size - nc, len(self.buf_red))
        nc = min(batch_size - nr, len(self.buf_core))
        samples = list(self.buf_core)[:nc] + list(self.buf_red)[:nr]
        if not samples:
            return None
        random.shuffle(samples)
        s, a, r, ns = zip(*samples)
        return (torch.stack(s), torch.tensor(a, dtype=torch.long),
                torch.tensor(r, dtype=torch.float), torch.stack(ns))

    def __len__(self):
        return len(self.buf_core) + len(self.buf_red)
