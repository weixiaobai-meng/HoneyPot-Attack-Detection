"""
第三步：DQN环境
符合OpenAI Gym标准的攻击图裁剪环境
"""

import torch


class AttackGraphEnv:
    """
    DQN攻击图谱裁剪环境
    
    马尔可夫决策过程:
    - 状态: 当前图谱 (节点特征 + 边索引 + 剩余边掩码)
    - 动作: 对当前考虑的一条边, 决定 0=保留 / 1=裁剪
    - 奖励: 根据真实标签和动作计算
    - 终止: 所有边都已决策
    """
    
    # 奖励配置
    REWARD_KEEP_CORE = 5.0       # 正确保留核心边
    REWARD_PRUNE_REDUNDANT = 1.0 # 正确裁剪冗余边
    PENALTY_PRUNE_CORE = -10.0   # 错误裁剪核心边
    PENALTY_KEEP_REDUNDANT = -1.0 # 错误保留冗余边

    def __init__(self, data):
        """
        Args:
            data: torch_geometric.data.Data
                - x: 节点特征 (N, node_feat_dim)
                - edge_index: 边索引 (2, E)
                - y: 边真实标签 (E,)  1=核心, 0=冗余
        """
        self.x_orig = data.x.clone()
        self.edge_index_orig = data.edge_index.clone()
        self.edge_labels = data.y.clone()
        self.num_edges = data.edge_index.size(1)
        self.num_nodes = data.x.size(0)
        self.reset()

    def reset(self):
        """重置环境"""
        self.x = self.x_orig.clone()
        self.edge_index = self.edge_index_orig.clone()
        self.edge_mask = torch.ones(self.num_edges, dtype=torch.bool)
        self.step_idx = 0
        self.done = False
        self.total_reward = 0.0
        self.actions_taken = torch.full((self.num_edges,), -1, dtype=torch.long)
        return self._get_state()

    def _get_state(self):
        """返回当前状态"""
        return {
            'x': self.x.clone(),
            'edge_index': self.edge_index.clone(),
            'edge_mask': self.edge_mask.clone(),
            'step_idx': self.step_idx,
        }

    def step(self, action):
        """
        执行动作
        
        Args:
            action: 0=保留, 1=裁剪
            
        Returns:
            (next_state, reward, done, info)
        """
        if self.done:
            return self._get_state(), 0.0, True, {}

        edge_idx = self.step_idx
        ground_truth = self.edge_labels[edge_idx].item()

        # 计算奖励
        if action == 0:  # 保留
            if ground_truth == 1:
                reward = self.REWARD_KEEP_CORE
            else:
                reward = self.PENALTY_KEEP_REDUNDANT
        else:  # 裁剪
            if ground_truth == 0:
                reward = self.REWARD_PRUNE_REDUNDANT
                self.edge_mask[edge_idx] = False
            else:
                reward = self.PENALTY_PRUNE_CORE
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
