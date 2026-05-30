"""
第三步：因果图数据加载器
将因果图JSON转换为PyTorch Geometric格式
"""

import json
import torch
import numpy as np
from torch_geometric.data import Data
from typing import List, Dict, Tuple


# 节点类型映射
NODE_TYPE_MAP = {
    "network": 0,
    "file": 1,
    "process": 2,
    "unknown": 3
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
    "unknown": 12
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
        
        action_idx = EDGE_ACTION_MAP.get(action, 12)
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


def generate_synthetic_labels(data: Data, core_ratio: float = 0.3) -> Data:
    """生成合成标签"""
    num_edges = data.edge_index.size(1)
    labels = torch.zeros(num_edges)
    
    edges_info = data.edges_info if hasattr(data, 'edges_info') else []
    
    for i, edge in enumerate(edges_info):
        action = edge.get("action", "unknown")
        
        if action in ["ssh_login", "file_access", "url_access"]:
            labels[i] = 1.0
        elif action in ["execve", "fork", "connect"]:
            if np.random.random() < 0.5:
                labels[i] = 1.0
        else:
            if np.random.random() < core_ratio:
                labels[i] = 1.0
    
    data.y = labels
    return data


def load_graphs_for_training(filepath: str, num_graphs: int = 100, augment: bool = True) -> List[Data]:
    """加载并生成训练数据"""
    with open(filepath, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    graphs = []
    for i in range(num_graphs):
        if augment:
            aug_data = augment_graph(graph_data)
        else:
            aug_data = graph_data.copy()
        
        data = causal_graph_to_pyg(aug_data)
        data = generate_synthetic_labels(data, core_ratio=0.2 + np.random.random() * 0.2)
        graphs.append(data)
    
    return graphs


def augment_graph(graph_data: Dict, drop_ratio: float = 0.1) -> Dict:
    """图数据增强"""
    import copy
    aug_data = copy.deepcopy(graph_data)
    
    edges = aug_data.get("edges", [])
    if len(edges) > 2:
        num_drop = max(1, int(len(edges) * drop_ratio))
        drop_indices = np.random.choice(len(edges), num_drop, replace=False)
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
