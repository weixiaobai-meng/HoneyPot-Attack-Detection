"""
Step 3: DQN trainer for attack-graph pruning.
"""

import json
import os
from typing import List

import torch
import torch.optim as optim

from .graph_loader import load_graph_from_file
from .model import DynamicEdgeQNetwork


def focal_loss(logits, targets, alpha=None, gamma=3.0):
    """
    Balanced focal loss.

    The target convention is:
    - 1: keep / core edge
    - 0: prune / redundant edge
    """
    p = torch.sigmoid(logits)
    p_t = p * targets + (1 - p) * (1 - targets)

    if alpha is None:
        pos_ratio = targets.mean().clamp(0.01, 0.99)
        alpha_t = (1 - pos_ratio) * targets + pos_ratio * (1 - targets)
    else:
        alpha_t = alpha * targets + (1 - alpha) * (1 - targets)

    return -(alpha_t * (1 - p_t) ** gamma * torch.log(p_t + 1e-8)).mean()


def compute_graph_metrics(model, data, device):
    """Compute metrics for one graph."""
    model.eval()
    with torch.no_grad():
        q_values, _ = model(data.x.to(device), data.edge_index.to(device))
        actions = q_values.argmax(dim=1).cpu()
        y = data.y.long().cpu()

        labeled_mask = y >= 0
        if labeled_mask.sum().item() == 0:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "core_recall": 0.0,
                "causal_score": 0.0,
                "ckc": 0.0,
                "cpr": 0.0,
                "wpc": 0.0,
                "wkr": 0.0,
                "labeled_edges": 0.0,
                "label_coverage": 0.0,
            }

        actions = actions[labeled_mask]
        y = y[labeled_mask]

        # keep core correctly
        ckc = ((actions == 0) & (y == 1)).sum().item()
        # prune redundant correctly
        cpr = ((actions == 1) & (y == 0)).sum().item()
        # wrongly prune core
        wpc = ((actions == 1) & (y == 1)).sum().item()
        # wrongly keep redundant
        wkr = ((actions == 0) & (y == 0)).sum().item()
        total = max(int(labeled_mask.sum().item()), 1)

        accuracy = (ckc + cpr) / total
        precision = cpr / max(cpr + wpc, 1)
        recall = cpr / max(cpr + wkr, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-8)
        core_recall = ckc / max(ckc + wpc, 1)

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "core_recall": core_recall,
            "causal_score": 0.65 * core_recall + 0.35 * f1,
            "ckc": ckc,
            "cpr": cpr,
            "wpc": wpc,
            "wkr": wkr,
            "labeled_edges": float(total),
            "label_coverage": float(total) / max(data.edge_index.size(1), 1),
        }


class DQNTrainer:
    """Train and apply the DQN-based graph-pruning model."""

    def __init__(
        self,
        node_feat_dim=16,
        hidden_dim=128,
        out_dim=64,
        lr=1e-3,
        epochs=120,
        patience=30,
        device=None,
    ):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.lr = lr
        self.epochs = epochs
        self.patience = patience
        self.model = DynamicEdgeQNetwork(
            node_feat_dim=node_feat_dim,
            hidden_dim=hidden_dim,
            out_dim=out_dim,
        ).to(self.device)

        print(f"[*] device: {self.device}")
        print(f"[*] model params: {sum(p.numel() for p in self.model.parameters()):,}")

    def train(
        self,
        train_graphs: List,
        val_graphs: List,
        save_path: str = "output/checkpoints/dqn_best.pt",
    ):
        """Train the model and save the best checkpoint."""
        print("\n[*] start DQN training")
        print(f"    train graphs: {len(train_graphs)}")
        print(f"    val graphs: {len(val_graphs)}")
        print(f"    epochs: {self.epochs}, lr: {self.lr}")

        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=self.epochs)

        best_val_f1 = 0.0
        best_val_score = -1.0
        best_state = None
        no_improve = 0

        for epoch in range(1, self.epochs + 1):
            self.model.train()
            total_loss = 0.0
            sample_count = 0

            for graph in train_graphs:
                graph = graph.to(self.device)
                q_values, _ = self.model(graph.x, graph.edge_index)
                logits = q_values[:, 0] - q_values[:, 1]

                targets = graph.y
                if targets.device != logits.device:
                    targets = targets.to(logits.device)
                labeled_mask = targets >= 0
                if labeled_mask.sum().item() == 0:
                    continue

                loss = focal_loss(logits[labeled_mask], targets[labeled_mask], gamma=3.0)

                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 3.0)
                optimizer.step()

                total_loss += loss.item()
                sample_count += 1

            scheduler.step()

            if epoch % 10 == 0 or epoch == 1:
                val_metrics = self._evaluate(val_graphs)
                train_metrics = self._evaluate(train_graphs[:10])
                avg_loss = total_loss / max(sample_count, 1)
                print(
                    f"  Epoch {epoch:3d}/{self.epochs} | "
                    f"Loss: {avg_loss:.4f} | "
                    f"Train F1: {train_metrics['f1']:.3f} CR: {train_metrics['core_recall']:.3f} | "
                    f"Val F1: {val_metrics['f1']:.3f} CR: {val_metrics['core_recall']:.3f} "
                    f"CS: {val_metrics['causal_score']:.3f}"
                )

                val_score = val_metrics["causal_score"]
                if val_score > best_val_score + 1e-4:
                    best_val_f1 = val_metrics["f1"]
                    best_val_score = val_score
                    best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
                    no_improve = 0
                    torch.save(best_state, save_path)
                else:
                    no_improve += 1

                if no_improve >= self.patience:
                    print(f"  early stop after {self.patience} validation stalls")
                    break

        if best_state:
            self.model.load_state_dict(best_state)
            print(f"  restored best checkpoint (Val F1: {best_val_f1:.3f}, causal score: {best_val_score:.3f})")
        else:
            torch.save(self.model.state_dict(), save_path)
            print("  validation did not improve; saved final checkpoint")

        return self.model

    def _evaluate(self, graphs):
        """Evaluate a graph list."""
        if not graphs:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "core_recall": 0.0,
                "causal_score": 0.0,
                "ckc": 0.0,
                "cpr": 0.0,
                "wpc": 0.0,
                "wkr": 0.0,
                "labeled_edges": 0.0,
                "label_coverage": 0.0,
            }
        metrics = [compute_graph_metrics(self.model, graph, self.device) for graph in graphs]
        return {key: sum(item[key] for item in metrics) / len(metrics) for key in metrics[0]}

    def evaluate_on_test(self, test_graphs):
        """Evaluate on the test set."""
        print("\n[*] test evaluation")
        metrics = self._evaluate(test_graphs)
        print(f"  accuracy:      {metrics['accuracy']:.4f}")
        print(f"  precision:     {metrics['precision']:.4f}")
        print(f"  recall:        {metrics['recall']:.4f}")
        print(f"  f1:            {metrics['f1']:.4f}")
        print(f"  core recall:   {metrics['core_recall']:.4f}")
        print(f"  label coverage:{metrics['label_coverage']:.4f}")
        return metrics

    def predict_and_prune(self, graph_path: str, output_path: str):
        """Predict keep/prune decisions and export the pruned graph."""
        self.model.eval()

        data = load_graph_from_file(graph_path)
        if not hasattr(data, "y") or data.y is None:
            data.y = torch.full((data.edge_index.size(1),), -1.0)
        data = data.to(self.device)

        with torch.no_grad():
            q_values, _ = self.model(data.x, data.edge_index)
            actions = q_values.argmax(dim=1)

        num_edges = data.edge_index.size(1)
        keep_count = int((actions == 0).sum().item())
        prune_count = int((actions == 1).sum().item())

        print("\n[*] pruning result:")
        print(f"  total edges: {num_edges}")
        if num_edges > 0:
            print(f"  kept:   {keep_count} ({100 * keep_count / num_edges:.1f}%)")
            print(f"  pruned: {prune_count} ({100 * prune_count / num_edges:.1f}%)")
        else:
            print("  kept:   0 (0.0%)")
            print("  pruned: 0 (0.0%)")

        with open(graph_path, "r", encoding="utf-8") as f:
            graph_data = json.load(f)

        edges = graph_data.get("edges", [])
        kept_edges = [edge for idx, edge in enumerate(edges) if idx < len(actions) and actions[idx].item() == 0]

        graph_data["edges"] = kept_edges
        graph_data["pruning_stats"] = {
            "original_edges": num_edges,
            "kept_edges": keep_count,
            "pruned_edges": prune_count,
            "compression_ratio": f"{(100 * prune_count / num_edges):.1f}%" if num_edges > 0 else "0.0%",
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)

        print(f"  saved pruned graph to: {output_path}")
        return graph_data

    def save_results(self, metrics, config, output_path):
        """Save evaluation results."""
        results = {
            "config": config,
            "test_metrics": metrics,
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[+] saved results to: {output_path}")
