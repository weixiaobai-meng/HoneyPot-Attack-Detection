"""Apply a trained policy and export evidence-consistent graph views."""

import argparse
import json
from pathlib import Path
import torch

from step3_dqn_pruning.trainer import DQNTrainer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--partition-edges", type=int, default=512)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    graph = json.loads(Path(args.graph).read_text(encoding="utf-8-sig"))
    meta = graph.get("graph_meta", {})
    if meta.get("evidence_contract_version") != 1 or meta.get("experiment_anchors_used") is not False:
        raise ValueError("rebuild graph using the current unannotated evidence contract")
    trainer = DQNTrainer(device=args.device, use_path_constraints=True)
    state = torch.load(args.checkpoint, map_location=trainer.device, weights_only=True)
    trainer.model.load_state_dict(state)
    trainer.predict_and_prune(args.graph, args.output, evidence_guardrail=False,
                              max_edges_per_partition=args.partition_edges,
                              decision_batch_size=args.batch_size)


if __name__ == "__main__":
    main()
