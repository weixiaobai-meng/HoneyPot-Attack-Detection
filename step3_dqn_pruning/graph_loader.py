"""
第三步：因果图数据加载器
将因果图JSON转换为PyTorch Geometric格式
"""

import copy
import json
import math
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

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


# 关系类型映射：把 Step2 图谱中由蜜点证据生成的边显式送入 DQN。
# 这些关系不是装饰字段，而是“攻击本源”判断依据：
# 同源身份、跨蜜点阶段转移和时序因果。
EDGE_RELATION_MAP = {
    "subject_action_object": 0,
    "same_source_ip": 1,
    "same_fingerprint": 2,
    "same_session": 3,
    "same_campaign": 4,
    "same_account_probe": 5,
    "same_attack_path": 6,
    "stage_transition": 7,
    "web_to_account": 8,
    "account_to_file": 9,
    "web_to_file": 10,
    "account_to_web_followup": 11,
    "file_to_account_followup": 12,
    "file_to_web_followup": 13,
    "controlled_chain_member": 14,
    "web_to_account_causal": 15,
    "account_to_file_causal": 16,
    "web_to_file_causal": 17,
    "account_to_web_followup_causal": 18,
    "file_to_account_followup_causal": 19,
    "file_to_web_followup_causal": 20,
    "same_actor_stage_transition": 21,
    "same_actor_temporal": 22,
    "unknown": 23,
}

EDGE_KIND_MAP = {
    "event": 0,
    "correlation": 1,
    "unknown": 2,
}

HONEYPOT_HINT_MAP = {
    "account": 0,
    "file": 1,
    "parasitic": 2,
    "cross_honeypot": 3,
    "unknown": 4,
}

SEVERITY_SCORE = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

CORE_ATTACK_ORIGIN_RELATIONS = {
    "web_to_account",
    "account_to_file",
    "web_to_file",
    "stage_transition",
    "same_fingerprint",
    "same_session",
    "same_campaign",
    "web_to_account_causal",
    "account_to_file_causal",
    "web_to_file_causal",
    "same_actor_stage_transition",
}

# These fields and relations are experiment annotations. They may be used to
# build labels, but must never affect model features, rewards or deployment
# constraints. Keeping this deny-list close to feature construction makes the
# no-leakage boundary testable.
LABEL_ONLY_FIELDS = {
    "scenario_id",
    "scenario_role",
    "ground_truth",
    "label",
}
LABEL_ONLY_RELATIONS = {"controlled_chain_member"}

CROSS_HONEYPOT_RELATIONS = {
    "web_to_account",
    "account_to_file",
    "web_to_file",
    "account_to_web_followup",
    "file_to_account_followup",
    "file_to_web_followup",
    "web_to_account_causal",
    "account_to_file_causal",
    "web_to_file_causal",
    "account_to_web_followup_causal",
    "file_to_account_followup_causal",
    "file_to_web_followup_causal",
}

IDENTITY_RELATIONS = {
    "same_source_ip",
    "same_fingerprint",
    "same_session",
    "same_campaign",
    "same_account_probe",
}

TEMPORAL_RELATIONS = {"same_actor_temporal"}

IDENTITY_EVIDENCE_PREFIXES = {
    "same_ip:",
    "same_fingerprint:",
    "same_session:",
    "same_campaign:",
    "same_attacker:",
    "same_username:",
}

EVIDENCE_FEATURES = [
    "shared_same_ip",
    "shared_same_fingerprint",
    "shared_same_session",
    "shared_same_campaign",
    "shared_same_attacker",
    "shared_same_username",
    "has_campaign_id",
    "is_cross_honeypot",
    "is_stage_transition",
    "is_identity_relation",
    "has_token_or_file_evidence",
    "has_browser_fingerprint_evidence",
    "is_temporal_correlation",
    "confidence",
    "severity_score",
    "time_delta_log",
    "attack_origin_score",
]

EDGE_FEATURE_NAMES = (
    [f"action:{name}" for name in EDGE_ACTION_MAP]
    + [f"relation:{name}" for name in EDGE_RELATION_MAP]
    + [f"edge_kind:{name}" for name in EDGE_KIND_MAP]
    + [f"honeypot_hint:{name}" for name in HONEYPOT_HINT_MAP]
    + EVIDENCE_FEATURES
)

NUM_EDGE_FEATURES = len(EDGE_FEATURE_NAMES)

FEATURE_GROUPS = {
    "identity": {
        "shared_same_ip",
        "shared_same_fingerprint",
        "shared_same_session",
        "shared_same_campaign",
        "shared_same_attacker",
        "shared_same_username",
        "has_campaign_id",
        "is_identity_relation",
        "has_browser_fingerprint_evidence",
    },
    "cross_honeypot": {
        "is_cross_honeypot",
        "is_stage_transition",
        "has_token_or_file_evidence",
    },
    "temporal": {"is_temporal_correlation", "time_delta_log"},
    "origin_score": {"attack_origin_score"},
}


def load_graph_from_file(filepath: str, disabled_feature_groups: Optional[Iterable[str]] = None) -> Data:
    """从文件加载因果图并转换为PyG格式"""
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        graph_data = json.load(f)
    return causal_graph_to_pyg(graph_data, disabled_feature_groups=disabled_feature_groups)


def causal_graph_to_pyg(
    graph_data: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> Data:
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
    edge_attr = torch.zeros(num_edges, NUM_EDGE_FEATURES)
    
    for i, edge in enumerate(valid_edges):
        source = edge.get("source")
        target = edge.get("target")
        edge_index[0, i] = node_id_map[source]
        edge_index[1, i] = node_id_map[target]

        edge_attr[i] = torch.tensor(
            build_edge_feature_vector(edge, disabled_feature_groups=disabled_feature_groups),
            dtype=torch.float32,
        )
    
    data = Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        num_nodes=num_nodes
    )
    
    data.node_id_map = node_id_map
    data.edges_info = valid_edges
    data.edge_feature_names = EDGE_FEATURE_NAMES
    data.edge_attr_dim = NUM_EDGE_FEATURES
    data.disabled_feature_groups = sorted(set(disabled_feature_groups or []))
    
    return data


def _disabled_groups(disabled_feature_groups: Optional[Iterable[str]]) -> Set[str]:
    groups = set(disabled_feature_groups or [])
    unknown = groups - set(FEATURE_GROUPS)
    if unknown:
        raise ValueError(f"unknown feature groups: {sorted(unknown)}")
    return groups


def _relation(edge: Dict, disabled_feature_groups: Optional[Iterable[str]] = None) -> str:
    relation = str(edge.get("relation_type") or "unknown")
    if relation in LABEL_ONLY_RELATIONS:
        return "unknown"
    groups = _disabled_groups(disabled_feature_groups)
    if "identity" in groups and relation in IDENTITY_RELATIONS:
        return "unknown"
    if "cross_honeypot" in groups and relation in CROSS_HONEYPOT_RELATIONS:
        return "unknown"
    if "temporal" in groups and relation in TEMPORAL_RELATIONS:
        return "unknown"
    return relation if relation in EDGE_RELATION_MAP else "unknown"


def _action(edge: Dict) -> str:
    action = str(edge.get("action") or "unknown")
    return action if action in EDGE_ACTION_MAP else "unknown"


def _shared_evidence(
    edge: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> List[str]:
    values = edge.get("shared_evidence") or []
    if isinstance(values, str):
        values = [values]
    result = [str(item) for item in values if str(item)]
    groups = _disabled_groups(disabled_feature_groups)
    if "identity" in groups:
        result = [
            item for item in result
            if not any(item.startswith(prefix) for prefix in IDENTITY_EVIDENCE_PREFIXES)
        ]
    return result


def _has_shared(
    edge: Dict,
    prefix: str,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> bool:
    return any(
        item.startswith(prefix)
        for item in _shared_evidence(edge, disabled_feature_groups=disabled_feature_groups)
    )


def infer_honeypot_hint(
    edge: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> str:
    """Infer which honeypot evidence family an edge mainly represents."""
    relation = _relation(edge, disabled_feature_groups=disabled_feature_groups)
    action = _action(edge)
    subject_type = str(edge.get("subject_type") or "")
    object_type = str(edge.get("object_type") or "")

    if relation in CROSS_HONEYPOT_RELATIONS:
        return "cross_honeypot"
    if action in {"ssh_login", "vpn_connect"} or object_type == "service":
        return "account"
    if action in {"file_access", "openat", "read", "write"} or object_type == "file":
        return "file"
    if action == "url_access" or object_type == "url" or subject_type == "browser":
        return "parasitic"
    return "unknown"


def attack_origin_score(
    edge: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> float:
    """Score how strongly an edge is tied to attack-origin evidence.

    Only evidence observable at inference time is allowed here. Controlled
    scenario ids/roles and manual labels are intentionally ignored.
    """
    groups = _disabled_groups(disabled_feature_groups)
    if "origin_score" in groups:
        return 0.0
    relation = _relation(edge, disabled_feature_groups=groups)
    score = 0.0

    if relation in CORE_ATTACK_ORIGIN_RELATIONS:
        score += 2.0
    if relation in CROSS_HONEYPOT_RELATIONS:
        score += 1.5
    if relation in IDENTITY_RELATIONS:
        score += 1.0

    if "identity" not in groups and edge.get("campaign_id"):
        score += 1.2

    if _has_shared(edge, "same_fingerprint:", groups):
        score += 1.3
    if _has_shared(edge, "same_session:", groups):
        score += 1.2
    if _has_shared(edge, "same_campaign:", groups):
        score += 1.5
    if _has_shared(edge, "same_ip:", groups):
        score += 0.7
    if _has_shared(edge, "same_attacker:", groups):
        score += 0.6

    confidence = float(edge.get("confidence") or 0.0)
    if confidence >= 0.9:
        score += 0.6
    elif confidence >= 0.8:
        score += 0.3

    time_delta = edge.get("time_delta_seconds")
    if (
        "temporal" not in groups
        and isinstance(time_delta, (int, float))
        and 0 <= float(time_delta) <= 45 * 60
    ):
        score += 0.4

    return max(score, 0.0)


def attack_origin_reasons(
    edge: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> List[str]:
    """Human-readable deployment evidence, excluding experiment annotations."""
    groups = _disabled_groups(disabled_feature_groups)
    relation = _relation(edge, disabled_feature_groups=groups)
    reasons = []
    if relation in CROSS_HONEYPOT_RELATIONS:
        reasons.append("跨蜜点阶段转移")
    if relation in IDENTITY_RELATIONS:
        reasons.append("同源主体证据")
    if "identity" not in groups and edge.get("campaign_id"):
        reasons.append("campaign_id 锚点")
    for prefix, label in [
        ("same_fingerprint:", "同浏览器指纹"),
        ("same_session:", "同会话"),
        ("same_campaign:", "同实验批次"),
        ("same_ip:", "同源 IP"),
    ]:
        if _has_shared(edge, prefix, groups):
            reasons.append(label)
    if not reasons and float(edge.get("confidence") or 0.0) >= 0.9:
        reasons.append("高置信边")
    return sorted(set(reasons))


def _disabled_evidence_features(disabled_feature_groups: Optional[Iterable[str]]) -> Set[str]:
    disabled = set()
    for group in disabled_feature_groups or []:
        if group not in FEATURE_GROUPS:
            raise ValueError(
                f"unknown feature group {group!r}; expected one of {sorted(FEATURE_GROUPS)}"
            )
        disabled.update(FEATURE_GROUPS[group])
    return disabled


def build_edge_feature_vector(
    edge: Dict,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> List[float]:
    """Build a leakage-free edge feature vector for pruning models."""
    values = [0.0] * NUM_EDGE_FEATURES
    offset = 0

    values[offset + EDGE_ACTION_MAP[_action(edge)]] = 1.0
    offset += len(EDGE_ACTION_MAP)

    groups = _disabled_groups(disabled_feature_groups)
    values[offset + EDGE_RELATION_MAP[_relation(edge, groups)]] = 1.0
    offset += len(EDGE_RELATION_MAP)

    edge_kind = str(edge.get("edge_kind") or "unknown")
    if edge_kind not in EDGE_KIND_MAP:
        edge_kind = "unknown"
    values[offset + EDGE_KIND_MAP[edge_kind]] = 1.0
    offset += len(EDGE_KIND_MAP)

    values[offset + HONEYPOT_HINT_MAP[infer_honeypot_hint(edge, groups)]] = 1.0
    offset += len(HONEYPOT_HINT_MAP)

    confidence = max(0.0, min(float(edge.get("confidence") or 0.0), 1.0))
    severity = str(edge.get("severity") or "medium").lower()
    time_delta = edge.get("time_delta_seconds")
    time_delta_log = 0.0
    if isinstance(time_delta, (int, float)) and float(time_delta) >= 0:
        time_delta_log = min(math.log1p(float(time_delta)) / math.log1p(3600.0), 1.0)

    evidence_values = {
        "shared_same_ip": float(_has_shared(edge, "same_ip:", groups)),
        "shared_same_fingerprint": float(_has_shared(edge, "same_fingerprint:", groups)),
        "shared_same_session": float(_has_shared(edge, "same_session:", groups)),
        "shared_same_campaign": float(_has_shared(edge, "same_campaign:", groups)),
        "shared_same_attacker": float(_has_shared(edge, "same_attacker:", groups)),
        "shared_same_username": float(_has_shared(edge, "same_username:", groups)),
        "has_campaign_id": float("identity" not in groups and bool(edge.get("campaign_id"))),
        "is_cross_honeypot": float(_relation(edge, groups) in CROSS_HONEYPOT_RELATIONS),
        "is_stage_transition": float(
            _relation(edge, groups) in {"stage_transition", "same_actor_stage_transition"}
        ),
        "is_identity_relation": float(_relation(edge, groups) in IDENTITY_RELATIONS),
        "has_token_or_file_evidence": float(
            "token" in json.dumps(edge, ensure_ascii=False).lower()
            or infer_honeypot_hint(edge, groups) == "file"
        ),
        "has_browser_fingerprint_evidence": float(
            _has_shared(edge, "same_fingerprint:", groups)
            or infer_honeypot_hint(edge, groups) == "parasitic"
        ),
        "is_temporal_correlation": float(edge_kind == "correlation" and time_delta is not None),
        "confidence": confidence,
        "severity_score": SEVERITY_SCORE.get(severity, 0.5),
        "time_delta_log": time_delta_log,
        "attack_origin_score": min(attack_origin_score(edge, groups) / 8.0, 1.0),
    }

    disabled_features = _disabled_evidence_features(disabled_feature_groups)
    for name in EVIDENCE_FEATURES:
        values[offset] = 0.0 if name in disabled_features else evidence_values[name]
        offset += 1

    return values


def is_protected_origin_edge(
    edge: Dict,
    threshold: float = 4.0,
    disabled_feature_groups: Optional[Iterable[str]] = None,
) -> bool:
    """Return whether observable evidence requires retaining an edge.

    This is a deployment constraint, not a label guardrail. Scenario metadata
    cannot make an edge protected.
    """
    groups = _disabled_groups(disabled_feature_groups)
    relation = _relation(edge, disabled_feature_groups=groups)
    strong_identity = any(
        _has_shared(edge, prefix, groups)
        for prefix in ("same_fingerprint:", "same_session:", "same_campaign:")
    )
    cross_stage = relation in CROSS_HONEYPOT_RELATIONS
    return attack_origin_score(edge, groups) >= threshold and (strong_identity or cross_stage)


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
        origin_score = attack_origin_score(edge)
        r = _edge_hash(seed, i)

        if str(edge.get("scenario_role") or "") == "controlled_chain":
            labels[i] = 1.0
        elif str(edge.get("scenario_role") or "") == "controlled_noise":
            labels[i] = 0.0
        elif origin_score >= 3.0:
            labels[i] = 1.0
        elif relation_type in {
            "web_to_account",
            "account_to_file",
            "web_to_file",
            "stage_transition",
            "controlled_chain_member",
            "same_fingerprint",
            "same_session",
            "same_campaign",
        }:
            labels[i] = 1.0
        elif action in ["file_access", "url_access"] and origin_score >= 1.5:
            labels[i] = 1.0
        elif action in ["ssh_login"] and origin_score >= 2.0:
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
    with open(label_path, "r", encoding="utf-8-sig") as f:
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
                             augment: bool = True, base_seed: int = 42,
                             allow_weak_label_smoke_test: bool = False) -> List[Data]:
    """Generate weak-label graph copies for explicit software smoke tests.

    These copies are not independent attack scenarios and must never be used to
    report thesis train/validation/test performance.
    """
    if not allow_weak_label_smoke_test:
        raise RuntimeError(
            "weak-label same-graph augmentation is disabled for scientific experiments; "
            "use experiments.dataset.ScenarioDataset with independently split scenarios"
        )
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
        "edge_feature_dim": NUM_EDGE_FEATURES,
        "edge_feature_names": EDGE_FEATURE_NAMES,
        "node_types": {},
        "edge_types": {},
        "relation_types": {},
        "attack_origin_evidence": {
            "cross_honeypot_edges": 0,
            "identity_edges": 0,
            "campaign_edges": 0,
            "high_origin_score_edges": 0,
        },
    }
    
    for node in graph_data.get("nodes", []):
        node_type = node.get("type", "unknown")
        stats["node_types"][node_type] = stats["node_types"].get(node_type, 0) + 1
    
    for edge in graph_data.get("edges", []):
        action = edge.get("action", "unknown")
        stats["edge_types"][action] = stats["edge_types"].get(action, 0) + 1
        relation = edge.get("relation_type", "unknown")
        stats["relation_types"][relation] = stats["relation_types"].get(relation, 0) + 1
        evidence = stats["attack_origin_evidence"]
        if _relation(edge) in CROSS_HONEYPOT_RELATIONS:
            evidence["cross_honeypot_edges"] += 1
        if _relation(edge) in IDENTITY_RELATIONS:
            evidence["identity_edges"] += 1
        if edge.get("campaign_id"):
            evidence["campaign_edges"] += 1
        if attack_origin_score(edge) >= 3.0:
            evidence["high_origin_score_edges"] += 1
    
    return stats
