import torch
import torch.nn as nn
import random
import numpy as np
from dqn_model import DynamicEdgeQNetwork
from config import cfg


class AttackGraphEnv:
    """
    DQN 攻击图谱裁剪环境。

    马尔可夫决策过程:
      - 状态: 当前图谱 (节点特征 + 边索引 + 剩余边掩码)
      - 动作: 对当前考虑的一条边, 决定 0=保留 / 1=裁剪
      - 奖励: 根据真实标签和动作计算
      - 终止: 所有边都已决策

    决策顺序: 按边索引从 0 到 E-1 依次处理。
    """

    def __init__(self, data):
        """
        data: torch_geometric.data.Data
          - x:          节点特征 (N, node_feat_dim)
          - edge_index: 边索引 (2, E)
          - y:          边真实标签 (E,)  1=核心(必须保留), 0=冗余(应该裁剪)
        """
        self.x_orig = data.x.clone()
        self.edge_index_orig = data.edge_index.clone()
        self.edge_labels = data.y.clone()  # ground truth
        self.num_edges = data.edge_index.size(1)
        self.num_nodes = data.x.size(0)

        self.reset()

    def reset(self):
        """重置环境到初始状态, 返回初始观察"""
        self.x = self.x_orig.clone()
        self.edge_index = self.edge_index_orig.clone()
        # edge_mask: 1=仍在图中, 0=已裁剪. 初始全部为1.
        self.edge_mask = torch.ones(self.num_edges, dtype=torch.bool)
        self.step_idx = 0  # 当前处理到第几条边
        self.done = False
        self.total_reward = 0.0
        self.actions_taken = torch.full((self.num_edges,), -1, dtype=torch.long)  # -1 = 未决策
        return self._get_state()

    def _get_state(self):
        """返回当前状态: (x, edge_index, edge_mask, step_idx)"""
        return {
            'x': self.x.clone(),
            'edge_index': self.edge_index.clone(),
            'edge_mask': self.edge_mask.clone(),
            'step_idx': self.step_idx,
        }

    def step(self, action):
        """
        对当前边 (step_idx) 执行动作。

        action: int, 0=保留, 1=裁剪

        返回: (next_state, reward, done, info)
        """
        if self.done:
            return self._get_state(), 0.0, True, {}

        edge_idx = self.step_idx
        ground_truth = self.edge_labels[edge_idx].item()  # 1=核心, 0=冗余

        # ---- 计算奖励 ----
        if action == 0:  # 保留
            if ground_truth == 1:  # 正确保留核心边
                reward = cfg.reward_keep_core
            else:  # 错误保留冗余边
                reward = cfg.penalty_keep_redundant
        else:  # action == 1: 裁剪
            if ground_truth == 0:  # 正确裁剪冗余边
                reward = cfg.reward_prune_redundant
                # 实际裁剪: 从图中移除该边
                self.edge_mask[edge_idx] = False
            else:  # 错误裁剪核心边
                reward = cfg.penalty_prune_core
                # 仍然裁剪 (模拟错误决策的后果)
                self.edge_mask[edge_idx] = False

        self.actions_taken[edge_idx] = action
        self.total_reward += reward
        self.step_idx += 1

        if self.step_idx >= self.num_edges:
            self.done = True

        info = {
            'ground_truth': ground_truth,
            'edge_idx': edge_idx,
            'reward': reward,
        }

        return self._get_state(), reward, self.done, info


def compute_edge_embeddings(model, data):
    """
    用 GNN 编码器计算所有边的嵌入。
    返回 edge_embs: (E, out_dim*2)
    """
    model.eval()
    with torch.no_grad():
        x = data.x
        edge_index = data.edge_index
        h = model.encoder(x, edge_index)
        src, dst = edge_index[0], edge_index[1]
        edge_embs = torch.cat([h[src], h[dst]], dim=-1)
    return edge_embs
