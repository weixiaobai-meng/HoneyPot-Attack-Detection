"""Strict inference loading for known checkpoint architectures; never reshape weights."""
import hashlib
from pathlib import Path

import torch

from .graph_loader import NUM_EDGE_FEATURES
from .trainer import DQNTrainer


def load_inference_checkpoint(path, *, device="cpu", allow_legacy=False):
    path = Path(path)
    state = torch.load(path, map_location=device, weights_only=True)
    if not isinstance(state, dict) or not all(isinstance(value, torch.Tensor) for value in state.values()):
        raise ValueError("unsupported checkpoint format: expected an unmodified state_dict")
    weight = state.get("q_net.net.0.weight")
    if weight is None or weight.ndim != 2:
        raise ValueError("checkpoint has no valid Q input layer")
    input_dim = int(weight.shape[1])
    current_dim = 128 + NUM_EDGE_FEATURES + 2
    legacy = input_dim == 128
    if input_dim != current_dim and not (legacy and allow_legacy):
        raise ValueError(f"checkpoint input dimension {input_dim} unsupported; current={current_dim}, legacy128 requires explicit opt-in")
    trainer = DQNTrainer(device=device, edge_attr_dim=0 if legacy else NUM_EDGE_FEATURES,
                         use_dynamic_state=not legacy, use_path_constraints=True)
    # Missing/unexpected keys and any other incompatible tensor must fail closed.
    trainer.model.load_state_dict(state, strict=True)
    trainer.target_model.load_state_dict(state, strict=True)
    trainer.model.eval()
    metadata = {
        "mode": "legacy_dqn_checkpoint" if legacy else "dqn_checkpoint",
        "checkpoint_architecture": "legacy_node_pair_128" if legacy else "evidence_dynamic_198",
        "checkpoint_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "checkpoint_input_dim": input_dim,
        "edge_feature_dim": 0 if legacy else NUM_EDGE_FEATURES,
        "dynamic_state_observed": not legacy,
        "model_weights_modified": False,
        "checkpoint_load_strict": True,
        "training_provenance_verified": False,
        "formal_evaluation_ready": False,
        "compatibility_note": (
            "旧版128维权重按原结构执行；不使用新增边特征或动态状态。训练来源未验证，不代表新版方法或正式论文效果。"
            if legacy else "当前结构权重已严格加载；加载成功不等于训练来源与正式实验效果已验证。"
        ),
    }
    return trainer, metadata
