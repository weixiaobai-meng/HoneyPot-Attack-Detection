"""Replay-based DQN trainer for sequential attack-graph pruning."""

import copy
import json
import math
import os
import random
from collections import deque
from dataclasses import dataclass
from typing import List, Optional

import torch
import torch.nn.functional as F
import torch.optim as optim

from .environment import AttackGraphEnv
from .graph_loader import NUM_EDGE_FEATURES, is_protected_origin_edge, load_graph_from_file
from .model import DynamicEdgeQNetwork
from .scaling import edge_partition, partition_edge_indices


@dataclass
class ReplayTransition:
    graph_idx: int
    edge_mask: torch.Tensor
    edge_idx: int
    action: int
    reward: float
    next_edge_mask: torch.Tensor
    next_edge_idx: int
    done: bool


class ReplayBuffer:
    def __init__(self, capacity: int, seed: int = 42):
        self._items = deque(maxlen=int(capacity))
        self._rng = random.Random(seed)

    def push(self, transition: ReplayTransition) -> None:
        self._items.append(transition)

    def sample(self, batch_size: int):
        return self._rng.sample(list(self._items), min(int(batch_size), len(self._items)))

    def __len__(self):
        return len(self._items)


def pruning_metrics_from_actions(actions: torch.Tensor, labels: torch.Tensor):
    actions = actions.to(dtype=torch.long, device="cpu")
    labels = labels.to(dtype=torch.long, device="cpu")
    labeled = labels >= 0
    actions = actions[labeled]
    labels = labels[labeled]
    if labels.numel() == 0:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "noise_precision": 0.0,
            "noise_recall": 0.0,
            "noise_f1": 0.0,
            "core_recall": 0.0,
            "noise_filter_rate": 0.0,
            "compression_ratio": 0.0,
            "causal_score": 0.0,
            "ckc": 0.0,
            "cpr": 0.0,
            "wpc": 0.0,
            "wkr": 0.0,
            "labeled_edges": 0.0,
            "label_coverage": 0.0,
        }

    ckc = int(((actions == 0) & (labels == 1)).sum().item())
    cpr = int(((actions == 1) & (labels == 0)).sum().item())
    wpc = int(((actions == 1) & (labels == 1)).sum().item())
    wkr = int(((actions == 0) & (labels == 0)).sum().item())
    total = int(labels.numel())
    accuracy = (ckc + cpr) / max(total, 1)
    precision = cpr / max(cpr + wpc, 1)
    recall = cpr / max(cpr + wkr, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    core_recall = ckc / max(ckc + wpc, 1)
    compression = float((actions == 1).sum().item()) / max(total, 1)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "noise_precision": precision,
        "noise_recall": recall,
        "noise_f1": f1,
        "core_recall": core_recall,
        "noise_filter_rate": recall,
        "compression_ratio": compression,
        "causal_score": 0.65 * core_recall + 0.35 * f1,
        "ckc": float(ckc),
        "cpr": float(cpr),
        "wpc": float(wpc),
        "wkr": float(wkr),
        "labeled_edges": float(total),
        "label_coverage": float(total) / max(int(labeled.numel()), 1),
    }


def compute_graph_metrics(model, data, device):
    """Compatibility helper for legacy smoke-test scripts.

    It is a one-shot classifier-style evaluation and is intentionally not used
    by the scenario-isolated DQN benchmark.
    """
    model.eval()
    with torch.no_grad():
        edge_count = int(data.edge_index.size(1))
        edge_attr = getattr(data, "edge_attr", None)
        edge_mask = torch.ones(edge_count, dtype=torch.bool, device=device)
        q_values, _ = model(
            data.x.to(device),
            data.edge_index.to(device),
            edge_attr.to(device) if edge_attr is not None else None,
            edge_mask,
        )
    return pruning_metrics_from_actions(q_values.argmax(dim=1).cpu(), data.y.cpu())


def _mean_metrics(rows):
    if not rows:
        return pruning_metrics_from_actions(torch.tensor([]), torch.tensor([]))
    return {key: sum(float(row[key]) for row in rows) / len(rows) for key in rows[0]}


class DQNTrainer:
    """Train a sequential DQN with replay memory and a target network."""

    algorithm_name = "evidence_constrained_sequential_dqn"

    def __init__(
        self,
        node_feat_dim=16,
        hidden_dim=128,
        out_dim=64,
        edge_attr_dim=NUM_EDGE_FEATURES,
        lr=5e-4,
        epochs=40,
        patience=10,
        gamma=0.95,
        batch_size=16,
        replay_capacity=20000,
        min_replay_size=64,
        target_update_steps=100,
        train_frequency=4,
        epsilon_start=1.0,
        epsilon_end=0.05,
        epsilon_decay_steps=5000,
        use_dynamic_state=True,
        use_terminal_reward=True,
        use_origin_reward=True,
        shuffle_edges=True,
        seed=42,
        device=None,
    ):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.lr = float(lr)
        self.epochs = int(epochs)
        self.patience = int(patience)
        self.gamma = float(gamma)
        self.batch_size = int(batch_size)
        self.min_replay_size = int(min_replay_size)
        self.target_update_steps = int(target_update_steps)
        self.train_frequency = int(train_frequency)
        self.epsilon_start = float(epsilon_start)
        self.epsilon_end = float(epsilon_end)
        self.epsilon_decay_steps = max(int(epsilon_decay_steps), 1)
        self.use_dynamic_state = bool(use_dynamic_state)
        self.use_terminal_reward = bool(use_terminal_reward)
        self.use_origin_reward = bool(use_origin_reward)
        self.shuffle_edges = bool(shuffle_edges)
        self.seed = int(seed)
        self.edge_attr_dim = int(edge_attr_dim or 0)
        self.rng = random.Random(self.seed)
        torch.manual_seed(self.seed)

        self.model = DynamicEdgeQNetwork(
            node_feat_dim=node_feat_dim,
            hidden_dim=hidden_dim,
            out_dim=out_dim,
            edge_attr_dim=self.edge_attr_dim,
            state_feature_dim=2 if self.use_dynamic_state else 0,
        ).to(self.device)
        self.target_model = copy.deepcopy(self.model).to(self.device).eval()
        for parameter in self.target_model.parameters():
            parameter.requires_grad_(False)
        self.replay = ReplayBuffer(replay_capacity, seed=self.seed)
        self.training_history = []
        self.global_step = 0
        self.optimizer_steps = 0

    def _epsilon(self):
        fraction = math.exp(-self.global_step / self.epsilon_decay_steps)
        return self.epsilon_end + (self.epsilon_start - self.epsilon_end) * fraction

    def _model_q(self, model, graph, edge_mask):
        edge_attr = getattr(graph, "edge_attr", None)
        model_edge_mask = edge_mask.to(self.device) if self.use_dynamic_state else None
        q_values, _ = model(
            graph.x.to(self.device),
            graph.edge_index.to(self.device),
            edge_attr.to(self.device) if edge_attr is not None else None,
            model_edge_mask,
        )
        return q_values

    def _select_action(self, graph, edge_mask, edge_idx, explore=True):
        if explore and self.rng.random() < self._epsilon():
            return self.rng.randint(0, 1)
        self.model.eval()
        with torch.no_grad():
            q_values = self._model_q(self.model, graph, edge_mask)
            return int(q_values[int(edge_idx)].argmax().item())

    def _optimize(self, train_graphs):
        if len(self.replay) < self.min_replay_size:
            return None
        transitions = self.replay.sample(self.batch_size)
        predicted_values = []
        target_values = []
        self.model.train()

        for item in transitions:
            graph = train_graphs[item.graph_idx]
            q_values = self._model_q(self.model, graph, item.edge_mask)
            predicted_values.append(q_values[item.edge_idx, item.action])
            with torch.no_grad():
                reward = torch.tensor(item.reward, dtype=torch.float32, device=self.device)
                if item.done:
                    target = reward
                else:
                    next_q = self._model_q(self.target_model, graph, item.next_edge_mask)
                    target = reward + self.gamma * next_q[item.next_edge_idx].max()
                target_values.append(target)

        predicted = torch.stack(predicted_values)
        targets = torch.stack(target_values)
        loss = F.smooth_l1_loss(predicted, targets)
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
        self.optimizer.step()
        self.optimizer_steps += 1
        if self.optimizer_steps % self.target_update_steps == 0:
            self.target_model.load_state_dict(self.model.state_dict())
        return float(loss.item())

    @staticmethod
    def _validate_graphs(graphs, name):
        if not graphs:
            raise ValueError(f"{name} set is empty")
        for index, graph in enumerate(graphs):
            labels = getattr(graph, "y", None)
            if labels is None or labels.numel() != graph.edge_index.size(1):
                raise ValueError(f"{name}[{index}] has missing or misaligned edge labels")
            if (labels < 0).any():
                raise ValueError(f"{name}[{index}] has unlabeled edges; complete labels are required")

    def train(self, train_graphs: List, val_graphs: List, save_path="output/checkpoints/dqn_best.pt"):
        self._validate_graphs(train_graphs, "train")
        self._validate_graphs(val_graphs, "validation")
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        self.optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        best_score = -1.0
        best_state = None
        no_improve = 0

        for epoch in range(1, self.epochs + 1):
            graph_order = list(range(len(train_graphs)))
            self.rng.shuffle(graph_order)
            losses = []
            rewards = []
            for graph_idx in graph_order:
                graph = train_graphs[graph_idx]
                if graph.edge_index.size(1) == 0:
                    continue
                env = AttackGraphEnv(
                    graph,
                    shuffle_edges=self.shuffle_edges,
                    seed=self.seed + epoch * 1009 + graph_idx,
                    use_origin_reward=self.use_origin_reward,
                    use_terminal_reward=self.use_terminal_reward,
                )
                state = env.reset()
                episode_reward = 0.0
                while not env.done:
                    edge_idx = int(state["current_edge_idx"])
                    action = self._select_action(graph, state["edge_mask"], edge_idx, explore=True)
                    next_state, reward, done, _ = env.step(action)
                    self.replay.push(ReplayTransition(
                        graph_idx=graph_idx,
                        edge_mask=state["edge_mask"].clone().cpu(),
                        edge_idx=edge_idx,
                        action=action,
                        reward=float(reward),
                        next_edge_mask=next_state["edge_mask"].clone().cpu(),
                        next_edge_idx=int(next_state["current_edge_idx"]),
                        done=bool(done),
                    ))
                    self.global_step += 1
                    episode_reward += float(reward)
                    if self.global_step % self.train_frequency == 0:
                        loss = self._optimize(train_graphs)
                        if loss is not None:
                            losses.append(loss)
                    state = next_state
                rewards.append(episode_reward)

            val_metrics = self._evaluate(val_graphs, evidence_guardrail=False)
            row = {
                "epoch": epoch,
                "loss": sum(losses) / max(len(losses), 1),
                "episode_reward": sum(rewards) / max(len(rewards), 1),
                "epsilon": self._epsilon(),
                "validation": val_metrics,
            }
            self.training_history.append(row)
            score = val_metrics["causal_score"]
            if score > best_score + 1e-4:
                best_score = score
                best_state = {key: value.detach().cpu().clone() for key, value in self.model.state_dict().items()}
                torch.save(best_state, save_path)
                no_improve = 0
            else:
                no_improve += 1
            if no_improve >= self.patience:
                break

        if best_state is None:
            best_state = {key: value.detach().cpu().clone() for key, value in self.model.state_dict().items()}
            torch.save(best_state, save_path)
        self.model.load_state_dict(best_state)
        self.target_model.load_state_dict(best_state)
        return self.model

    def _predict_actions_single(self, data, evidence_guardrail=False, decision_batch_size=1):
        edge_count = int(data.edge_index.size(1))
        actions = torch.zeros(edge_count, dtype=torch.long)
        raw_actions = torch.zeros(edge_count, dtype=torch.long)
        edge_mask = torch.ones(edge_count, dtype=torch.bool)
        overrides = []
        self.model.eval()
        decision_batch_size = max(int(decision_batch_size), 1)
        for batch_start in range(0, edge_count, decision_batch_size):
            with torch.no_grad():
                q_values = self._model_q(self.model, data, edge_mask)
            batch_end = min(batch_start + decision_batch_size, edge_count)
            for edge_idx in range(batch_start, batch_end):
                action = int(q_values[edge_idx].argmax().item())
                raw_actions[edge_idx] = action
                edge = data.edges_info[edge_idx] if edge_idx < len(getattr(data, "edges_info", [])) else {}
                disabled_groups = getattr(data, "disabled_feature_groups", [])
                if (
                    evidence_guardrail
                    and action == 1
                    and is_protected_origin_edge(edge, disabled_feature_groups=disabled_groups)
                ):
                    action = 0
                    overrides.append(edge_idx)
                actions[edge_idx] = action
                if action == 1:
                    edge_mask[edge_idx] = False
        return actions, {
            "raw_actions": raw_actions,
            "evidence_constraint_overrides": overrides,
            "decision_batch_size": decision_batch_size,
        }

    def predict_actions(
        self,
        data,
        evidence_guardrail=False,
        max_edges_per_partition=512,
        decision_batch_size=1,
    ):
        edge_count = int(data.edge_index.size(1))
        if not max_edges_per_partition or edge_count <= int(max_edges_per_partition):
            actions, details = self._predict_actions_single(
                data,
                evidence_guardrail=evidence_guardrail,
                decision_batch_size=decision_batch_size,
            )
            details["partition_count"] = 1 if edge_count else 0
            details["max_edges_per_partition"] = int(max_edges_per_partition or edge_count or 1)
            return actions, details

        actions = torch.zeros(edge_count, dtype=torch.long)
        raw_actions = torch.zeros(edge_count, dtype=torch.long)
        overrides = []
        partitions = partition_edge_indices(data, max_edges=int(max_edges_per_partition))
        for indices in partitions:
            subset = edge_partition(data, indices)
            local_actions, local_details = self._predict_actions_single(
                subset,
                evidence_guardrail=evidence_guardrail,
                decision_batch_size=decision_batch_size,
            )
            for local_idx, original_idx in enumerate(indices):
                actions[original_idx] = local_actions[local_idx]
                raw_actions[original_idx] = local_details["raw_actions"][local_idx]
            overrides.extend(indices[local_idx] for local_idx in local_details["evidence_constraint_overrides"])
        return actions, {
            "raw_actions": raw_actions,
            "evidence_constraint_overrides": overrides,
            "partition_count": len(partitions),
            "max_edges_per_partition": int(max_edges_per_partition),
            "decision_batch_size": int(decision_batch_size),
        }

    def _evaluate(self, graphs, evidence_guardrail=False):
        rows = []
        for graph in graphs:
            actions, _ = self.predict_actions(graph, evidence_guardrail=evidence_guardrail)
            rows.append(pruning_metrics_from_actions(actions, graph.y))
        return _mean_metrics(rows)

    def evaluate_on_test(self, test_graphs, evidence_guardrail=False):
        self._validate_graphs(test_graphs, "test")
        return self._evaluate(test_graphs, evidence_guardrail=evidence_guardrail)

    def predict_and_prune(
        self,
        graph_path: str,
        output_path: str,
        evidence_guardrail=True,
        max_edges_per_partition=512,
        decision_batch_size=16,
    ):
        data = load_graph_from_file(graph_path)
        actions, details = self.predict_actions(
            data,
            evidence_guardrail=evidence_guardrail,
            max_edges_per_partition=max_edges_per_partition,
            decision_batch_size=decision_batch_size,
        )
        with open(graph_path, "r", encoding="utf-8") as handle:
            graph_data = json.load(handle)
        edges = graph_data.get("edges", [])
        kept_edges = [edge for idx, edge in enumerate(edges) if idx < len(actions) and int(actions[idx]) == 0]
        original_edges = len(edges)
        pruned_edges = original_edges - len(kept_edges)
        graph_data["edges"] = kept_edges
        graph_data["pruning_stats"] = {
            "algorithm": self.algorithm_name,
            "original_edges": original_edges,
            "kept_edges": len(kept_edges),
            "pruned_edges": pruned_edges,
            "compression_ratio": f"{100 * pruned_edges / max(original_edges, 1):.1f}%",
            "edge_feature_dim": self.edge_attr_dim,
            "feature_source": "observable_honeypot_origin_evidence",
            "sequential_state_updates": True,
            "dynamic_state_observed": self.use_dynamic_state,
            "experience_replay": True,
            "target_network": True,
            "bellman_discount": self.gamma,
            "terminal_reward_enabled": self.use_terminal_reward,
            "origin_reward_enabled": self.use_origin_reward,
            "training_edge_order_shuffled": self.shuffle_edges,
            "test_labels_used_for_inference": False,
            "evidence_constraint_enabled": bool(evidence_guardrail),
            "evidence_constraint_overrides": len(details["evidence_constraint_overrides"]),
            "partition_count": details["partition_count"],
            "max_edges_per_partition": details["max_edges_per_partition"],
            "decision_batch_size": details["decision_batch_size"],
        }
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(graph_data, handle, indent=2, ensure_ascii=False)
        return graph_data

    def save_results(self, metrics, config, output_path):
        payload = {
            "algorithm": self.algorithm_name,
            "config": config,
            "test_metrics": metrics,
            "training_history": self.training_history,
        }
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
