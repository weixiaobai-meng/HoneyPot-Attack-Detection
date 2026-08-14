"""Supervised GAT edge-classification baseline for DQN comparisons."""

import copy
import os
import random

import torch
import torch.nn.functional as F
import torch.optim as optim

from .graph_loader import NUM_EDGE_FEATURES, is_protected_origin_edge
from .model import DynamicEdgeQNetwork
from .trainer import _mean_metrics, pruning_metrics_from_actions


class SupervisedGATTrainer:
    algorithm_name = "supervised_gat_edge_classifier"

    def __init__(
        self,
        node_feat_dim=16,
        hidden_dim=128,
        out_dim=64,
        edge_attr_dim=NUM_EDGE_FEATURES,
        lr=5e-4,
        epochs=80,
        patience=15,
        seed=42,
        device=None,
    ):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.lr = float(lr)
        self.epochs = int(epochs)
        self.patience = int(patience)
        self.seed = int(seed)
        random.seed(self.seed)
        torch.manual_seed(self.seed)
        self.model = DynamicEdgeQNetwork(
            node_feat_dim=node_feat_dim,
            hidden_dim=hidden_dim,
            out_dim=out_dim,
            edge_attr_dim=edge_attr_dim,
        ).to(self.device)
        self.training_history = []

    def _forward(self, graph):
        edge_attr = getattr(graph, "edge_attr", None)
        edge_mask = torch.ones(graph.edge_index.size(1), dtype=torch.bool, device=self.device)
        logits, _ = self.model(
            graph.x.to(self.device),
            graph.edge_index.to(self.device),
            edge_attr.to(self.device) if edge_attr is not None else None,
            edge_mask,
        )
        return logits

    @staticmethod
    def _action_targets(labels):
        return (1 - labels.to(dtype=torch.long)).clamp(0, 1)

    def train(self, train_graphs, val_graphs, save_path="output/checkpoints/supervised_gat_best.pt"):
        if not train_graphs or not val_graphs:
            raise ValueError("supervised baseline requires non-empty train and validation sets")
        optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        best_score = -1.0
        best_state = None
        no_improve = 0
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)

        for epoch in range(1, self.epochs + 1):
            self.model.train()
            losses = []
            for graph in train_graphs:
                if graph.edge_index.size(1) == 0:
                    continue
                labels = graph.y.to(self.device)
                if (labels < 0).any():
                    raise ValueError("supervised baseline requires complete edge labels")
                logits = self._forward(graph)
                targets = self._action_targets(labels)
                core = max(int((labels == 1).sum().item()), 1)
                noise = max(int((labels == 0).sum().item()), 1)
                total = core + noise
                class_weights = torch.tensor(
                    [total / (2 * core), total / (2 * noise)],
                    dtype=torch.float32,
                    device=self.device,
                )
                loss = F.cross_entropy(logits, targets, weight=class_weights)
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
                optimizer.step()
                losses.append(float(loss.item()))

            metrics = self._evaluate(val_graphs)
            self.training_history.append({
                "epoch": epoch,
                "loss": sum(losses) / max(len(losses), 1),
                "validation": metrics,
            })
            score = metrics["causal_score"]
            if score > best_score + 1e-4:
                best_score = score
                best_state = copy.deepcopy({key: value.detach().cpu() for key, value in self.model.state_dict().items()})
                torch.save(best_state, save_path)
                no_improve = 0
            else:
                no_improve += 1
            if no_improve >= self.patience:
                break

        if best_state is None:
            best_state = {key: value.detach().cpu() for key, value in self.model.state_dict().items()}
            torch.save(best_state, save_path)
        self.model.load_state_dict(best_state)
        return self.model

    def predict_actions(self, graph, evidence_guardrail=False):
        self.model.eval()
        with torch.no_grad():
            actions = self._forward(graph).argmax(dim=1).cpu()
        overrides = []
        disabled_groups = getattr(graph, "disabled_feature_groups", [])
        if evidence_guardrail:
            for edge_idx, edge in enumerate(getattr(graph, "edges_info", [])):
                if (
                    int(actions[edge_idx]) == 1
                    and is_protected_origin_edge(edge, disabled_feature_groups=disabled_groups)
                ):
                    actions[edge_idx] = 0
                    overrides.append(edge_idx)
        return actions, {"evidence_constraint_overrides": overrides}

    def _evaluate(self, graphs, evidence_guardrail=False):
        rows = []
        for graph in graphs:
            actions, _ = self.predict_actions(graph, evidence_guardrail=evidence_guardrail)
            rows.append(pruning_metrics_from_actions(actions, graph.y))
        return _mean_metrics(rows)

    def evaluate_on_test(self, graphs, evidence_guardrail=False):
        return self._evaluate(graphs, evidence_guardrail=evidence_guardrail)
