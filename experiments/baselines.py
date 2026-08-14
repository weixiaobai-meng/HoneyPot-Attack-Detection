"""Non-learning pruning baselines used by the benchmark runner."""

import random

import torch

from step3_dqn_pruning.graph_loader import attack_origin_score, is_protected_origin_edge


def keep_all_actions(graph):
    return torch.zeros(graph.edge_index.size(1), dtype=torch.long)


def random_matched_actions(graph, prune_count, seed=42):
    edge_count = int(graph.edge_index.size(1))
    prune_count = max(0, min(int(prune_count), edge_count))
    indices = list(range(edge_count))
    random.Random(int(seed)).shuffle(indices)
    actions = torch.zeros(edge_count, dtype=torch.long)
    if prune_count:
        actions[torch.tensor(indices[:prune_count], dtype=torch.long)] = 1
    return actions


def evidence_rule_actions(graph, score_threshold=2.0):
    actions = []
    for edge in getattr(graph, "edges_info", []):
        keep = is_protected_origin_edge(edge) or attack_origin_score(edge) >= float(score_threshold)
        actions.append(0 if keep else 1)
    return torch.tensor(actions, dtype=torch.long)
