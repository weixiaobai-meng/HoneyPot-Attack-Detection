"""
因果图数据加载器
将 data_collector/output/causal_graph.json 转换为 PyTorch Geometric 格式
用于 DQN 训练
"""

import json
import torch
import numpy as np
from torch_geometric.data import Data
from typing import List, Dict, Tuple
from datetime import datetime


# 节点类型映射
NODE_TYPE_MAP = {
    "network": 0,
    "file": 1,
    "process": 2,
    "unknown": 3
}

# 边类型（动作）映射
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


def load_causal_graph(filepath: str) -> Dict:
    """加载因果图JSON文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def build_node_features(nodes: List[Dict], node_id_map: Dict[str, int]) -> torch.Tensor:
    """
    构建节点特征矩阵
    
    特征维度:
    - node_type one-hot (4维)
    - degree (1维)
    - pagerank_approx (1维)
    - 其他填充 (10维)
    总计: 16维
    """
    num_nodes = len(node_id_map)
    feat_dim = 16
    features = torch.zeros(num_nodes, feat_dim)
    
    # 统计度数
    in_degree = {i: 0 for i in range(num_nodes)}
    out_degree = {i: 0 for i in range(num_nodes)}
    
    for node in nodes:
        node_id = node.get("id")
        if node_id in node_id_map:
            idx = node_id_map[node_id]
            
            # 节点类型 one-hot
            node_type = node.get("type", "unknown")
            type_idx = NODE_TYPE_MAP.get(node_type, 3)
            features[idx, type_idx] = 1.0
    
    return features


def build_edge_index(edges: List[Dict], node_id_map: Dict[str, int]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """
    构建边索引和边特征
    
    返回:
    - edge_index: (2, E) 边索引
    - edge_attr: (E, NUM_EDGE_ACTIONS) 边类型one-hot
    - edge_labels: (E,) 边标签 (用于训练时的ground truth)
    """
    valid_edges = []
    
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        
        if source in node_id_map and target in node_id_map:
            valid_edges.append(edge)
    
    num_edges = len(valid_edges)
    edge_index = torch.zeros(2, num_edges, dtype=torch.long)
    edge_attr = torch.zeros(num_edges, NUM_EDGE_ACTIONS)
    edge_labels = torch.zeros(num_edges)  # 默认标签
    
    for i, edge in enumerate(valid_edges):
        source = edge.get("source")
        target = edge.get("target")
        action = edge.get("action", "unknown")
        
        edge_index[0, i] = node_id_map[source]
        edge_index[1, i] = node_id_map[target]
        
        # 边类型 one-hot
        action_idx = EDGE_ACTION_MAP.get(action, 12)
        edge_attr[i, action_idx] = 1.0
    
    return edge_index, edge_attr, edge_labels


def causal_graph_to_pyg(graph_data: Dict, label_key: str = None) -> Data:
    """
    将因果图转换为 PyTorch Geometric Data 对象
    
    Args:
        graph_data: 因果图字典
        label_key: 用于生成边标签的字段名 (如果有)
    
    Returns:
        PyG Data 对象
    """
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    # 创建节点ID映射
    node_id_map = {node["id"]: i for i, node in enumerate(nodes)}
    
    # 构建节点特征
    x = build_node_features(nodes, node_id_map)
    
    # 构建边索引和特征
    edge_index, edge_attr, edge_labels = build_edge_index(edges, node_id_map)
    
    # 统计边类型
    for edge in edges:
        action = edge.get("action", "unknown")
        action_idx = EDGE_ACTION_MAP.get(action, 12)
    
    data = Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=edge_labels,
        num_nodes=len(nodes)
    )
    
    # 保存原始信息
    data.node_id_map = node_id_map
    data.nodes_info = nodes
    data.edges_info = edges
    
    return data


def load_graph_from_file(filepath: str) -> Data:
    """从文件加载因果图并转换为PyG格式"""
    graph_data = load_causal_graph(filepath)
    return causal_graph_to_pyg(graph_data)


def generate_synthetic_labels(data: Data, core_ratio: float = 0.3) -> Data:
    """
    为因果图生成合成标签 (用于无真实标签的情况)
    
    策略:
    - 与蜜点直接相关的边标记为核心 (1)
    - 其他边按比例随机标记
    
    Args:
        data: PyG Data 对象
        core_ratio: 核心边比例
    """
    num_edges = data.edge_index.size(1)
    labels = torch.zeros(num_edges)
    
    # 获取边信息
    edges_info = data.edges_info if hasattr(data, 'edges_info') else []
    
    for i, edge in enumerate(edges_info):
        action = edge.get("action", "unknown")
        
        # 与蜜点相关的动作标记为核心
        if action in ["ssh_login", "file_access", "url_access"]:
            labels[i] = 1.0
        elif action in ["execve", "fork", "connect"]:
            # 进程相关动作有一定概率是核心
            if np.random.random() < 0.5:
                labels[i] = 1.0
        else:
            # 其他动作按比例随机
            if np.random.random() < core_ratio:
                labels[i] = 1.0
    
    data.y = labels
    return data


def load_graphs_for_training(filepath: str, num_graphs: int = 100, augment: bool = True) -> List[Data]:
    """
    加载因果图并生成多个训练样本
    
    通过数据增强从单个图生成多个变体
    
    Args:
        filepath: 因果图文件路径
        num_graphs: 生成的图数量
        augment: 是否进行数据增强
    """
    graph_data = load_causal_graph(filepath)
    graphs = []
    
    for i in range(num_graphs):
        if augment:
            # 数据增强: 随机删除部分边、添加噪声
            aug_data = augment_graph(graph_data)
        else:
            aug_data = graph_data.copy()
        
        # 转换为PyG格式
        data = causal_graph_to_pyg(aug_data)
        
        # 生成合成标签
        data = generate_synthetic_labels(data, core_ratio=0.2 + np.random.random() * 0.2)
        
        graphs.append(data)
    
    return graphs


def augment_graph(graph_data: Dict, drop_ratio: float = 0.1, noise_ratio: float = 0.05) -> Dict:
    """
    图数据增强
    
    Args:
        graph_data: 原始图数据
        drop_ratio: 随机删除边的比例
        noise_ratio: 添加噪声节点的比例
    """
    import copy
    aug_data = copy.deepcopy(graph_data)
    
    # 随机删除部分边
    edges = aug_data.get("edges", [])
    if len(edges) > 2:
        num_drop = max(1, int(len(edges) * drop_ratio))
        drop_indices = np.random.choice(len(edges), num_drop, replace=False)
        aug_data["edges"] = [e for i, e in enumerate(edges) if i not in drop_indices]
    
    return aug_data


def get_graph_statistics(filepath: str) -> Dict:
    """获取因果图统计信息"""
    graph_data = load_causal_graph(filepath)
    
    stats = {
        "num_nodes": len(graph_data.get("nodes", [])),
        "num_edges": len(graph_data.get("edges", [])),
        "node_types": {},
        "edge_types": {}
    }
    
    # 统计节点类型
    for node in graph_data.get("nodes", []):
        node_type = node.get("type", "unknown")
        stats["node_types"][node_type] = stats["node_types"].get(node_type, 0) + 1
    
    # 统计边类型
    for edge in graph_data.get("edges", []):
        action = edge.get("action", "unknown")
        stats["edge_types"][action] = stats["edge_types"].get(action, 0) + 1
    
    return stats


if __name__ == "__main__":
    import os
    
    # 测试加载因果图
    graph_file = "../data_collector/output/causal_graph.json"
    
    if os.path.exists(graph_file):
        print("[*] 加载因果图...")
        stats = get_graph_statistics(graph_file)
        print(f"  节点数: {stats['num_nodes']}")
        print(f"  边数: {stats['num_edges']}")
        print(f"  节点类型: {stats['node_types']}")
        print(f"  边类型: {stats['edge_types']}")
        
        print("\n[*] 转换为PyG格式...")
        data = load_graph_from_file(graph_file)
        print(f"  x shape: {data.x.shape}")
        print(f"  edge_index shape: {data.edge_index.shape}")
        print(f"  edge_attr shape: {data.edge_attr.shape}")
        
        # 生成带标签的训练数据
        print("\n[*] 生成训练数据...")
        data = generate_synthetic_labels(data)
        print(f"  核心边数量: {data.y.sum().item()}/{data.y.size(0)}")
    else:
        print(f"[-] 因果图文件不存在: {graph_file}")
        print("[*] 请先运行 data_collector/main.py demo 生成因果图")
