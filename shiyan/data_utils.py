import torch
import random
from torch_geometric.data import Data
from config import cfg


def generate_attack_graph(n_nodes=None, n_edges=None):
    """
    生成一张带标注的合成攻击溯源图。

    攻击链模拟真实 APT 攻击:
      entry_node → recon_scan → exploit → lateral → C2 → exfil
    非核心节点为正常业务流量 / 误报。

    节点特征:
      - is_core:        该节点是否在攻击链上 (1.0 或 0.0)
      - anomaly_score:  攻击链节点 0.6~1.0, 非核心节点 0~0.2
      - node_type:      0=external_IP, 1=internal_host, 2=process, 3=file, 4=user
      - pagerank_approx:度数的平方根归一化 (模拟 PageRank)
      - in_degree / out_degree: 有向度特征
    """

    n_nodes = n_nodes or random.randint(15, cfg.max_nodes)
    n_edges = n_edges or random.randint(30, min(n_nodes * 3, 120))

    # ---- 1. 构建节点 ----
    chain_len = random.randint(5, max(6, n_nodes // 4))
    chain_nodes = random.sample(range(n_nodes), chain_len)

    # 攻击链节点按顺序排列 (模拟攻击阶段)
    chain_nodes.sort(key=lambda x: x)  # 保持 ID 顺序作为时间顺序

    # ---- 2. 构建边 ----
    edges = []
    core_mask = []
    edge_set = set()

    def add_edge(u, v, is_core):
        if u == v or (u, v) in edge_set:
            return
        edges.append((u, v))
        core_mask.append(is_core)
        edge_set.add((u, v))

    # 2a. 主攻击链 (核心边, 必须保留)
    for i in range(chain_len - 1):
        add_edge(chain_nodes[i], chain_nodes[i + 1], is_core=True)

    # 2b. 攻击链旁路 (横向移动 / 多步跳转)
    for i in range(chain_len - 2):
        if random.random() < 0.35:
            add_edge(chain_nodes[i], chain_nodes[i + 2], is_core=True)

    # 2c. C2 回连 / 横向移动分支 (链上索引 i → j, j > i+1)
    if chain_len >= 3 and random.random() < 0.6:
        for _ in range(max(1, chain_len // 3)):
            i = random.randint(0, chain_len - 3)
            j = random.randint(i + 2, chain_len - 1)
            u, v = chain_nodes[i], chain_nodes[j]
            if (u, v) not in edge_set:
                add_edge(u, v, is_core=True)

    # 2d. 冗余噪声边
    n_redundant_needed = n_edges - len(edges)
    attempts = 0
    core_set = set(chain_nodes)

    while len(edges) < n_edges and attempts < n_nodes * n_nodes:
        u = random.randint(0, n_nodes - 1)
        v = random.randint(0, n_nodes - 1)
        # 偏向: 避免在非核心节点间生成过多边 (模拟真实环境中噪音稀疏)
        if u in core_set and v in core_set and not (u, v) in edge_set:
            pass  # 如果是核心节点对但不在攻击链中, 算作冗余
        add_edge(u, v, is_core=False)
        attempts += 1

    # ---- 3. 构建节点特征 ----
    core_set = set(chain_nodes)

    # 3a. is_core 标识
    is_core = torch.zeros(n_nodes)
    for nd in chain_nodes:
        is_core[nd] = 1.0

    # 3b. 异常分数 — 核心节点极高, 非核心极低
    anomaly_score = torch.zeros(n_nodes)
    for nd in range(n_nodes):
        if nd in core_set:
            anomaly_score[nd] = 0.65 + 0.35 * random.random()
        else:
            anomaly_score[nd] = random.random() * 0.15

    # 3c. 节点类型 — 攻击链节点偏向 process/file (常见 APT 载体)
    node_types = torch.zeros(n_nodes, dtype=torch.long)
    for nd in range(n_nodes):
        if nd in core_set:
            # 核心链: 偏向 2=process, 3=file
            node_types[nd] = random.choices(
                [0, 1, 2, 3, 4], weights=[0.05, 0.10, 0.40, 0.35, 0.10]
            )[0]
        else:
            # 非核心: 均匀分布
            node_types[nd] = random.randint(0, cfg.num_node_types - 1)

    # 3d. 度数特征
    out_degree = torch.zeros(n_nodes)
    in_degree = torch.zeros(n_nodes)
    for u, v in edges:
        out_degree[u] += 1
        in_degree[v] += 1

    max_out = max(out_degree.max().item(), 1.0)
    max_in = max(in_degree.max().item(), 1.0)
    out_deg_norm = out_degree / max_out
    in_deg_norm = in_degree / max_in
    pagerank_approx = torch.sqrt(out_degree + in_degree + 1)
    pagerank_approx = pagerank_approx / max(pagerank_approx.max().item(), 1.0)

    # 3e. 拼接节点特征
    node_type_onehot = torch.nn.functional.one_hot(
        node_types, num_classes=cfg.num_node_types
    ).float()

    x = torch.cat([
        is_core.unsqueeze(1),
        anomaly_score.unsqueeze(1),
        out_deg_norm.unsqueeze(1),
        in_deg_norm.unsqueeze(1),
        pagerank_approx.unsqueeze(1),
        node_type_onehot,
        # 剩余维度填小噪声
        torch.randn(n_nodes, max(0, cfg.node_feat_dim - 5 - cfg.num_node_types)) * 0.05,
    ], dim=1)

    # ---- 4. 构建 Data ----
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    y = torch.tensor(core_mask, dtype=torch.float)

    data = Data(
        x=x,
        edge_index=edge_index,
        y=y,
        node_type=node_types,
        num_nodes=n_nodes,
    )
    return data


def generate_dataset(n_graphs):
    dataset = []
    for _ in range(n_graphs):
        data = generate_attack_graph()
        dataset.append(data)
    return dataset
