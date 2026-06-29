"""
第三步：因果图数据加载器
将因果图JSON转换为PyTorch Geometric格式
"""

import copy
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
from torch_geometric.data import Data


# 节点类型映射
NODE_TYPE_MAP = {
    "network": 0,
    "file": 1,
    "process": 2,
    "browser": 3,
    "url": 4,
    "service": 5,
    "event": 6,
    "unknown": 7
}

# 边类型映射
EDGE_ACTION_MAP = {
    "ssh_login": 0,
    "file_access": 1,
    "url_access": 2,
    "openat": 3,
    "read": 4,
    "write": 5,
    "execve": 6,
    "fork": 7,
    "connect": 8,
    "unlink": 9,
    "rename": 10,
    "chmod": 11,
    "vpn_connect": 12,
    "mkdir": 13,
    "correlates_to": 14,
    "unknown": 15
}

NUM_NODE_TYPES = len(NODE_TYPE_MAP)
NUM_EDGE_ACTIONS = len(EDGE_ACTION_MAP)


def load_graph_from_file(filepath: str) -> Data:
    """从文件加载因果图并转换为PyG格式"""
    with open(filepath, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    return causal_graph_to_pyg(graph_data)


def causal_graph_to_pyg(graph_data: Dict) -> Data:
    """将因果图转换为PyG Data对象"""
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    # 创建节点ID映射
    node_id_map = {node["id"]: i for i, node in enumerate(nodes)}
    num_nodes = len(node_id_map)
    
    # 构建节点特征
    feat_dim = 16
    x = torch.zeros(num_nodes, feat_dim)
    for node in nodes:
        node_id = node.get("id")
        if node_id in node_id_map:
            idx = node_id_map[node_id]
            node_type = node.get("type", "unknown")
            type_idx = NODE_TYPE_MAP.get(node_type, 3)
            x[idx, type_idx] = 1.0
    
    # 构建边索引和特征
    valid_edges = [e for e in edges if e.get("source") in node_id_map and e.get("target") in node_id_map]
    num_edges = len(valid_edges)
    
    edge_index = torch.zeros(2, num_edges, dtype=torch.long)
    edge_attr = torch.zeros(num_edges, NUM_EDGE_ACTIONS)
    
    for i, edge in enumerate(valid_edges):
        source = edge.get("source")
        target = edge.get("target")
        action = edge.get("action", "unknown")
        
        edge_index[0, i] = node_id_map[source]
        edge_index[1, i] = node_id_map[target]
        
        action_idx = EDGE_ACTION_MAP.get(action, EDGE_ACTION_MAP["unknown"])
        edge_attr[i, action_idx] = 1.0
    
    data = Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        num_nodes=num_nodes
    )
    
    data.node_id_map = node_id_map
    data.edges_info = valid_edges
    
    return data


def _edge_hash(seed: int, idx: int) -> float:
    """基于种子和边索引的确定性伪随机数 [0, 1)"""
    import hashlib
    h = hashlib.md5(f"{seed}_{idx}".encode()).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def generate_synthetic_labels(data: Data, core_ratio: float = 0.25,
                              seed: int = 42) -> Data:
    """
    生成合成标签（确定性）

    相同 seed + 相同边列表 → 相同标签，保证训练/测试/裁剪一致。
    core_ratio 控制非关键边类型的核心比例，默认 0.25 以保持类别平衡。
    """
    num_edges = data.edge_index.size(1)
    labels = torch.zeros(num_edges)

    edges_info = data.edges_info if hasattr(data, 'edges_info') else []

    for i, edge in enumerate(edges_info):
        action = edge.get("action", "unknown")
        relation_type = edge.get("relation_type", "")
        r = _edge_hash(seed, i)

        if action in ["ssh_login", "file_access", "url_access"]:
            labels[i] = 1.0
        elif relation_type in {
            "web_to_account",
            "account_to_file",
            "web_to_file",
            "stage_transition",
            "controlled_chain_member",
            "same_fingerprint",
            "same_session",
        }:
            labels[i] = 1.0
        elif action in ["execve", "fork", "connect"]:
            if r < 0.3:
                labels[i] = 1.0
        else:
            if r < core_ratio:
                labels[i] = 1.0

    data.y = labels
    return data


def load_manual_labels(label_path: str) -> Dict[str, float]:
    """
    Load human-labeled edge decisions.

    Supported formats:
    1. {"edge_id": 1, "edge_id_2": 0}
    2. [{"edge_id": "...", "label": 1}, ...]
    """
    with open(label_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    labels: Dict[str, float] = {}
    if isinstance(payload, dict):
        for edge_id, label in payload.items():
            labels[str(edge_id)] = float(label)
        return labels

    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            edge_id = item.get("edge_id")
            if edge_id in (None, ""):
                continue
            label = item.get("label")
            if label is None:
                continue
            labels[str(edge_id)] = float(label)
    return labels


def attach_manual_labels(data: Data, label_path: str, strict: bool = False) -> Data:
    """
    Attach human labels to current graph edges by edge_id.

    Label semantics:
    - 1: keep / core edge
    - 0: prune / redundant edge
    """
    labels_by_edge = load_manual_labels(label_path)
    edges_info = data.edges_info if hasattr(data, "edges_info") else []
    labels = torch.full((len(edges_info),), -1.0)
    missing = []

    for idx, edge in enumerate(edges_info):
        edge_id = str(edge.get("edge_id") or "")
        if edge_id and edge_id in labels_by_edge:
            labels[idx] = float(labels_by_edge[edge_id])
        else:
            missing.append(edge_id or f"index:{idx}")

    if strict and missing:
        raise ValueError(
            f"manual labels missing for {len(missing)} edges, first few: {missing[:10]}"
        )

    data.y = labels
    data.manual_label_path = str(Path(label_path).resolve())
    data.manual_label_coverage = float((labels >= 0).sum().item()) / max(len(edges_info), 1)
    return data


def load_graphs_for_training(filepath: str, num_graphs: int = 100,
                             augment: bool = True, base_seed: int = 42) -> List[Data]:
    """加载并生成训练数据（确定性标签）"""
    with open(filepath, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    graphs = []
    for i in range(num_graphs):
        if augment:
            aug_data = augment_graph(graph_data, seed=base_seed + i)
        else:
            aug_data = copy.deepcopy(graph_data)
        
        data = causal_graph_to_pyg(aug_data)
        # 每个样本用不同 seed，但整体确定性可复现
        core_r = 0.2 + _edge_hash(base_seed, i) * 0.2  # 0.2 ~ 0.4
        data = generate_synthetic_labels(data, core_ratio=core_r,
                                         seed=base_seed + i)
        graphs.append(data)
    
    return graphs


def augment_graph(graph_data: Dict, drop_ratio: float = 0.1,
                  seed: int = 0) -> Dict:
    """图数据增强（确定性）"""
    aug_data = copy.deepcopy(graph_data)
    
    edges = aug_data.get("edges", [])
    if len(edges) > 2:
        num_drop = max(1, int(len(edges) * drop_ratio))
        rng = np.random.RandomState(seed)
        drop_indices = rng.choice(len(edges), num_drop, replace=False)
        aug_data["edges"] = [e for i, e in enumerate(edges) if i not in drop_indices]
    
    return aug_data


def get_graph_statistics(filepath: str) -> Dict:
    """获取图统计信息"""
    with open(filepath, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    stats = {
        "num_nodes": len(graph_data.get("nodes", [])),
        "num_edges": len(graph_data.get("edges", [])),
        "node_types": {},
        "edge_types": {}
    }
    
    for node in graph_data.get("nodes", []):
        node_type = node.get("type", "unknown")
        stats["node_types"][node_type] = stats["node_types"].get(node_type, 0) + 1
    
    for edge in graph_data.get("edges", []):
        action = edge.get("action", "unknown")
        stats["edge_types"][action] = stats["edge_types"].get(action, 0) + 1
    
    return stats
