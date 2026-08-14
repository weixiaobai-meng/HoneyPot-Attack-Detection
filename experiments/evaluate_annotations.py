"""Measure independent edge-label agreement and prepare adjudication rows."""

import argparse
import itertools
import json
import statistics
from pathlib import Path

from experiments.dataset import VALID_LABELS, cohen_kappa
from step3_dqn_pruning.graph_loader import load_manual_labels


def evaluate(graph_path, rater_paths):
    with open(graph_path, "r", encoding="utf-8-sig") as handle:
        graph = json.load(handle)
    edge_ids = [str(edge.get("edge_id") or "") for edge in graph.get("edges", [])]
    if not edge_ids or any(not edge_id for edge_id in edge_ids):
        raise ValueError("graph must contain non-empty edge_id values")
    if len(set(edge_ids)) != len(edge_ids):
        raise ValueError("graph contains duplicate edge_id values")
    if len(rater_paths) < 2:
        raise ValueError("at least two independent rater files are required")

    raters = []
    for path in rater_paths:
        labels = load_manual_labels(str(path))
        missing = sorted(set(edge_ids) - set(labels))
        invalid = sorted({value for value in labels.values() if value not in VALID_LABELS})
        if missing:
            raise ValueError(f"{path} is missing {len(missing)} graph edges")
        if invalid:
            raise ValueError(f"{path} contains invalid labels {invalid}")
        raters.append({edge_id: int(labels[edge_id]) for edge_id in edge_ids})

    pairwise = []
    for left, right in itertools.combinations(range(len(raters)), 2):
        agreement = cohen_kappa(
            (raters[left][edge_id], raters[right][edge_id]) for edge_id in edge_ids
        )
        pairwise.append({
            "rater_left": left + 1,
            "rater_right": right + 1,
            **agreement,
        })

    disagreements = []
    for edge_id in edge_ids:
        labels = [rater[edge_id] for rater in raters]
        if len(set(labels)) > 1:
            disagreements.append({
                "edge_id": edge_id,
                "rater_labels": labels,
                "adjudicated_label": None,
                "adjudication_note": "",
            })

    kappas = [row["cohen_kappa"] for row in pairwise if row["cohen_kappa"] is not None]
    return {
        "graph": str(Path(graph_path).resolve()),
        "rater_files": [str(Path(path).resolve()) for path in rater_paths],
        "edge_count": len(edge_ids),
        "rater_count": len(raters),
        "pairwise": pairwise,
        "mean_pairwise_cohen_kappa": statistics.fmean(kappas) if kappas else None,
        "disagreement_count": len(disagreements),
        "disagreement_rate": len(disagreements) / len(edge_ids),
        "adjudication_template": disagreements,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate independent edge-label agreement")
    parser.add_argument("--graph", required=True)
    parser.add_argument("--rater", action="append", required=True, help="repeat for every rater label JSON")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = evaluate(args.graph, args.rater)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
