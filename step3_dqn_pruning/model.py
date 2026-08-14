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
    def __init__(
        self,
        node_feat_dim=16,
        hidden_dim=128,
        out_dim=64,
        edge_attr_dim=0,
        state_feature_dim=2,
        dropout=0.15,
    ):
        super().__init__()
        self.edge_attr_dim = int(edge_attr_dim or 0)
        self.state_feature_dim = int(state_feature_dim or 0)
        self.encoder = GNNEncoder(node_feat_dim, hidden_dim, out_dim, dropout)
        self.q_net = EdgeQNetwork(
            out_dim * 2 + self.edge_attr_dim + self.state_feature_dim,
            dropout,
        )

    def _normalize_edge_attr(self, edge_attr, edge_count, device):
        if self.edge_attr_dim <= 0:
            return None
        if edge_attr is None:
            return torch.zeros(edge_count, self.edge_attr_dim, device=device)
        edge_attr = edge_attr.to(device=device, dtype=torch.float32)
        if edge_attr.dim() == 1:
            edge_attr = edge_attr.view(edge_count, -1)
        if edge_attr.size(0) != edge_count:
            raise ValueError(f"edge_attr row count {edge_attr.size(0)} != edge count {edge_count}")
        if edge_attr.size(1) == self.edge_attr_dim:
            return edge_attr
        if edge_attr.size(1) > self.edge_attr_dim:
            return edge_attr[:, :self.edge_attr_dim]
        padding = torch.zeros(edge_count, self.edge_attr_dim - edge_attr.size(1), device=device)
        return torch.cat([edge_attr, padding], dim=-1)

    def _edge_state_features(self, edge_mask, edge_count, device):
        if self.state_feature_dim <= 0:
            return None
        if edge_mask is None:
            edge_mask = torch.ones(edge_count, dtype=torch.bool, device=device)
        else:
            edge_mask = edge_mask.to(device=device, dtype=torch.bool)
        active = edge_mask.to(dtype=torch.float32).view(-1, 1)
        active_ratio = active.mean() if edge_count else torch.tensor(0.0, device=device)
        features = torch.cat([active, active_ratio.expand(edge_count, 1)], dim=1)
        if self.state_feature_dim == 2:
            return features
        if self.state_feature_dim < 2:
            return features[:, :self.state_feature_dim]
        padding = torch.zeros(edge_count, self.state_feature_dim - 2, device=device)
        return torch.cat([features, padding], dim=1)

    def forward(self, x, edge_index, edge_attr=None, edge_mask=None):
        if edge_mask is None:
            active_edge_index = edge_index
        else:
            active_edge_index = edge_index[:, edge_mask.to(device=edge_index.device, dtype=torch.bool)]
        h = self.encoder(x, active_edge_index)
        src, dst = edge_index[0], edge_index[1]
        edge_embs = torch.cat([h[src], h[dst]], dim=-1)
        normalized_edge_attr = self._normalize_edge_attr(edge_attr, edge_index.size(1), h.device)
        if normalized_edge_attr is not None:
            edge_embs = torch.cat([edge_embs, normalized_edge_attr], dim=-1)
        state_features = self._edge_state_features(edge_mask, edge_index.size(1), h.device)
        if state_features is not None:
            edge_embs = torch.cat([edge_embs, state_features], dim=-1)
        q_values = self.q_net(edge_embs)
        return q_values, h

    @torch.no_grad()
    def predict(self, data):
        """预测保留/裁剪"""
        self.eval()
        qv, _ = self.forward(
            data.x,
            data.edge_index,
            getattr(data, "edge_attr", None),
            getattr(data, "edge_mask", None),
        )
        actions = qv.argmax(dim=1)
        return actions, qv
