"""
第三步：DQN模型
GAT编码器 + Q-Network
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv


class ResidualGATLayer(nn.Module):
    """带残差连接的GAT层"""
    def __init__(self, in_dim, out_dim, heads=4, dropout=0.15):
        super().__init__()
        self.gat = GATConv(in_dim, out_dim // heads, heads=heads, dropout=dropout)
        self.norm = nn.LayerNorm(out_dim)
        self.skip = nn.Linear(in_dim, out_dim) if in_dim != out_dim else nn.Identity()

    def forward(self, x, edge_index):
        h = self.gat(x, edge_index)
        h = self.norm(h + self.skip(x))
        return F.elu(h)


class GNNEncoder(nn.Module):
    """GAT图编码器"""
    def __init__(self, node_feat_dim=16, hidden_dim=128, out_dim=64, dropout=0.15):
        super().__init__()
        dims = [node_feat_dim, 128, 128, 64, out_dim]
        self.layers = nn.ModuleList([
            ResidualGATLayer(dims[i], dims[i + 1], heads=4 if i < 2 else 2, dropout=dropout)
            for i in range(len(dims) - 1)
        ])
        self.dropout = nn.Dropout(dropout)

    def forward(self, x, edge_index):
        for i, layer in enumerate(self.layers):
            x = layer(x, edge_index)
            if i < len(self.layers) - 1:
                x = self.dropout(x)
        return x


class EdgeQNetwork(nn.Module):
    """边级Q网络"""
    def __init__(self, in_dim=128, dropout=0.2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Linear(64, 2),
        )

    def forward(self, edge_embs):
        return self.net(edge_embs)


class DynamicEdgeQNetwork(nn.Module):
    """
    DQN边裁剪策略网络
    - encoder: GAT图编码器 → 节点嵌入
    - q_net: 边嵌入 → [Q_keep, Q_prune]
    - 决策: argmax(Q) → 0=保留, 1=裁剪
    """
    def __init__(self, node_feat_dim=16, hidden_dim=128, out_dim=64, dropout=0.15):
        super().__init__()
        self.encoder = GNNEncoder(node_feat_dim, hidden_dim, out_dim, dropout)
        self.q_net = EdgeQNetwork(out_dim * 2, dropout)

    def forward(self, x, edge_index):
        h = self.encoder(x, edge_index)
        src, dst = edge_index[0], edge_index[1]
        edge_embs = torch.cat([h[src], h[dst]], dim=-1)
        q_values = self.q_net(edge_embs)
        return q_values, h

    @torch.no_grad()
    def predict(self, data):
        """预测保留/裁剪"""
        self.eval()
        qv, _ = self.forward(data.x, data.edge_index)
        actions = qv.argmax(dim=1)
        return actions, qv
