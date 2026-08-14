"""Sequential attack-graph pruning environment used by the DQN trainer."""

from typing import Iterable, Optional

import numpy as np
import torch

from .graph_loader import attack_origin_reasons, attack_origin_score


class AttackGraphEnv:
    """A finite-horizon MDP that decides whether to keep each graph edge.

    Labels are consumed only to produce rewards during training/evaluation. The
    policy observes graph tensors, the active-edge mask and leakage-free
    honeypot evidence features.
    """

    REWARD_KEEP_CORE = 3.0
    REWARD_PRUNE_REDUNDANT = 3.0
    PENALTY_PRUNE_CORE = -6.0
    PENALTY_KEEP_REDUNDANT = -2.0
    BONUS_KEEP_ORIGIN_EVIDENCE = 0.75
    BONUS_PRUNE_LOW_ORIGIN_NOISE = 0.5
    PENALTY_PRUNE_ORIGIN_EVIDENCE = -1.5
    TERMINAL_CORE_RECALL_WEIGHT = 3.0
    TERMINAL_NOISE_FILTER_WEIGHT = 1.5
    TERMINAL_COMPRESSION_WEIGHT = 0.5

    def __init__(
        self,
        data,
        edge_order: Optional[Iterable[int]] = None,
        shuffle_edges: bool = False,
        seed: int = 42,
        use_origin_reward: bool = True,
        use_terminal_reward: bool = True,
    ):
        self.x_orig = data.x.clone()
        self.edge_index_orig = data.edge_index.clone()
        self.edge_attr_orig = getattr(data, "edge_attr", None)
        if self.edge_attr_orig is not None:
            self.edge_attr_orig = self.edge_attr_orig.clone()
        self.edges_info = list(getattr(data, "edges_info", []))
        self.disabled_feature_groups = set(getattr(data, "disabled_feature_groups", []))
        self.use_origin_reward = bool(use_origin_reward) and "origin_score" not in self.disabled_feature_groups
        self.use_terminal_reward = bool(use_terminal_reward)
        labels = getattr(data, "y", None)
        if labels is None:
            raise ValueError("DQN training environment requires edge labels")
        self.edge_labels = labels.clone().to(dtype=torch.long, device="cpu")
        if (self.edge_labels < 0).any():
            raise ValueError("DQN training requires complete labels for every edge")

        self.num_edges = int(data.edge_index.size(1))
        self.num_nodes = int(data.x.size(0))
        if edge_order is None:
            order = list(range(self.num_edges))
        else:
            order = [int(index) for index in edge_order]
        if sorted(order) != list(range(self.num_edges)):
            raise ValueError("edge_order must contain every edge index exactly once")
        if shuffle_edges:
            np.random.RandomState(seed).shuffle(order)
        self.edge_order = order
        self.reset()

    def reset(self):
        self.edge_mask = torch.ones(self.num_edges, dtype=torch.bool)
        self.step_idx = 0
        self.done = self.num_edges == 0
        self.total_reward = 0.0
        self.actions_taken = torch.full((self.num_edges,), -1, dtype=torch.long)
        return self._get_state()

    @property
    def current_edge_idx(self) -> int:
        if self.done or self.step_idx >= len(self.edge_order):
            return -1
        return int(self.edge_order[self.step_idx])

    def _get_state(self):
        return {
            "x": self.x_orig.clone(),
            "edge_index": self.edge_index_orig.clone(),
            "edge_attr": self.edge_attr_orig.clone() if self.edge_attr_orig is not None else None,
            "edge_mask": self.edge_mask.clone(),
            "step_idx": self.step_idx,
            "current_edge_idx": self.current_edge_idx,
        }

    def _terminal_reward(self) -> float:
        core = self.edge_labels == 1
        noise = self.edge_labels == 0
        kept = self.actions_taken == 0
        pruned = self.actions_taken == 1
        core_recall = float((core & kept).sum().item()) / max(int(core.sum().item()), 1)
        noise_filter = float((noise & pruned).sum().item()) / max(int(noise.sum().item()), 1)
        compression = float(pruned.sum().item()) / max(self.num_edges, 1)
        return (
            self.TERMINAL_CORE_RECALL_WEIGHT * core_recall
            + self.TERMINAL_NOISE_FILTER_WEIGHT * noise_filter
            + self.TERMINAL_COMPRESSION_WEIGHT * compression
        )

    def step(self, action):
        if self.done:
            return self._get_state(), 0.0, True, {"reason": "episode_complete"}
        if int(action) not in (0, 1):
            raise ValueError("action must be 0=keep or 1=prune")

        edge_idx = self.current_edge_idx
        ground_truth = int(self.edge_labels[edge_idx].item())
        edge_info = self.edges_info[edge_idx] if edge_idx < len(self.edges_info) else {}
        origin_score = attack_origin_score(edge_info, self.disabled_feature_groups)
        origin_reasons = attack_origin_reasons(edge_info, self.disabled_feature_groups)

        if int(action) == 0:
            reward = self.REWARD_KEEP_CORE if ground_truth == 1 else self.PENALTY_KEEP_REDUNDANT
            if self.use_origin_reward and ground_truth == 1 and origin_score >= 3.0:
                reward += self.BONUS_KEEP_ORIGIN_EVIDENCE
        else:
            self.edge_mask[edge_idx] = False
            reward = self.REWARD_PRUNE_REDUNDANT if ground_truth == 0 else self.PENALTY_PRUNE_CORE
            if self.use_origin_reward and ground_truth == 0 and origin_score < 1.5:
                reward += self.BONUS_PRUNE_LOW_ORIGIN_NOISE
            if self.use_origin_reward and ground_truth == 1 and origin_score >= 3.0:
                reward += self.PENALTY_PRUNE_ORIGIN_EVIDENCE

        self.actions_taken[edge_idx] = int(action)
        self.step_idx += 1
        self.done = self.step_idx >= self.num_edges
        terminal_reward = self._terminal_reward() if self.done and self.use_terminal_reward else 0.0
        reward += terminal_reward
        self.total_reward += reward

        info = {
            "ground_truth": ground_truth,
            "edge_idx": edge_idx,
            "reward": reward,
            "terminal_reward": terminal_reward,
            "attack_origin_score": origin_score,
            "attack_origin_reasons": origin_reasons,
        }
        return self._get_state(), float(reward), self.done, info
