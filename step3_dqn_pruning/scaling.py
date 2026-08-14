"""Deterministic graph partitioning for bounded-memory DQN inference."""

from typing import Iterable, List

import torch
from torch_geometric.data import Data


class _UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, value):
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left, right):
        left = self.find(left)
        right = self.find(right)
        if left == right:
            return
        if self.rank[left] < self.rank[right]:
            left, right = right, left
        self.parent[right] = left
        if self.rank[left] == self.rank[right]:
            self.rank[left] += 1


def partition_edge_indices(data, max_edges=512) -> List[List[int]]:
    """Pack weakly connected edge components into bounded partitions.

    Oversized components are split in original edge order. The split policy is
    deterministic so repeated experiments use identical partitions.
    """
    max_edges = int(max_edges)
    if max_edges <= 0:
        raise ValueError("max_edges must be positive")
    edge_count = int(data.edge_index.size(1))
    if edge_count <= max_edges:
        return [list(range(edge_count))] if edge_count else []

    node_count = int(data.x.size(0))
    union_find = _UnionFind(node_count)
    for edge_idx in range(edge_count):
        source = int(data.edge_index[0, edge_idx])
        target = int(data.edge_index[1, edge_idx])
        union_find.union(source, target)

    components = {}
    for edge_idx in range(edge_count):
        source = int(data.edge_index[0, edge_idx])
        root = union_find.find(source)
        components.setdefault(root, []).append(edge_idx)

    pieces = []
    for indices in sorted(components.values(), key=lambda values: values[0]):
        for start in range(0, len(indices), max_edges):
            pieces.append(indices[start:start + max_edges])

    partitions = []
    current = []
    for piece in pieces:
        if current and len(current) + len(piece) > max_edges:
            partitions.append(current)
            current = []
        current.extend(piece)
    if current:
        partitions.append(current)
    return partitions


def edge_partition(data, indices: Iterable[int]):
    indices = [int(index) for index in indices]
    tensor_indices = torch.tensor(indices, dtype=torch.long, device=data.edge_index.device)
    kwargs = {
        "x": data.x,
        "edge_index": data.edge_index.index_select(1, tensor_indices),
        "num_nodes": int(data.x.size(0)),
    }
    edge_attr = getattr(data, "edge_attr", None)
    if edge_attr is not None:
        kwargs["edge_attr"] = edge_attr.index_select(0, tensor_indices.to(edge_attr.device))
    labels = getattr(data, "y", None)
    if labels is not None:
        kwargs["y"] = labels.index_select(0, tensor_indices.to(labels.device))
    subset = Data(**kwargs)
    edges_info = list(getattr(data, "edges_info", []))
    subset.edges_info = [edges_info[index] for index in indices]
    subset.original_edge_indices = indices
    subset.edge_feature_names = getattr(data, "edge_feature_names", [])
    subset.edge_attr_dim = getattr(data, "edge_attr_dim", 0)
    subset.disabled_feature_groups = getattr(data, "disabled_feature_groups", [])
    for name in ("scenario_id", "dataset_split", "source_type", "trigger_mode"):
        if hasattr(data, name):
            setattr(subset, name, getattr(data, name))
    return subset


def partition_graphs(graphs, max_edges=256):
    result = []
    for graph in graphs:
        partitions = partition_edge_indices(graph, max_edges=max_edges)
        result.extend(edge_partition(graph, indices) for indices in partitions)
    return result
