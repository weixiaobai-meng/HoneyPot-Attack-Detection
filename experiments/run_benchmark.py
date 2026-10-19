"""Run reproducible baselines, DQN comparisons and feature ablations."""

import argparse
import csv
import itertools
import json
import math
import random
import statistics
import hashlib
import platform
import subprocess
from pathlib import Path

import numpy as np
import torch

from experiments.baselines import evidence_rule_actions, keep_all_actions, random_matched_actions
from experiments.dataset import ScenarioDataset
from step3_dqn_pruning import DQNTrainer, SupervisedGATTrainer, partition_graphs
from step3_dqn_pruning.trainer import pruning_metrics_from_actions
from step3_dqn_pruning.constraints import EvidencePathGuard
from step2_causal_graph.graph_views import selected_edge_view
from experiments.evaluate_paths import evaluate as evaluate_paths


METRIC_NAMES = [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "noise_precision",
    "noise_recall",
    "noise_f1",
    "core_recall",
    "noise_filter_rate",
    "compression_ratio",
    "causal_score",
    "protected_edge_count",
    "protected_edges_kept",
    "required_path_count",
    "required_paths_kept",
    "complete_path_recall",
    "path_edge_recall",
]

COMPARISON_METRICS = ["f1", "core_recall", "noise_filter_rate", "causal_score", "complete_path_recall"]
MECHANISM_ABLATIONS = {
    "dynamic_state": {"use_dynamic_state": False},
    "terminal_reward": {"use_terminal_reward": False},
    "shuffled_order": {"shuffle_edges": False},
}


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _scenario_id(graph, fallback):
    return str(getattr(graph, "scenario_id", fallback))


def _metric_row(method, seed, graph, actions, fallback_id, output_dir=None):
    metrics = pruning_metrics_from_actions(actions, graph.y)
    metrics.update(EvidencePathGuard(graph).metrics(actions))
    if getattr(graph, "source_graph_path", None):
        original = json.loads(Path(graph.source_graph_path).read_text(encoding="utf-8-sig"))
        pruned = selected_edge_view(original, [edge for i, edge in enumerate(original["edges"]) if int(actions[i]) == 0])
        if getattr(graph, "path_gold_path", ""):
            gold = json.loads(Path(graph.path_gold_path).read_text(encoding="utf-8-sig"))
            path_metrics = evaluate_paths(original, pruned, gold)
            metrics.update({key: path_metrics[key] for key in ("complete_path_recall", "path_edge_recall")})
        if output_dir is not None:
            case_key = hashlib.sha256(str(graph.scenario_id).encode()).hexdigest()[:16]
            destination = Path(output_dir) / "graphs" / str(seed) / method / case_key
            destination.mkdir(parents=True, exist_ok=True)
            pruned["pruning_stats"] = {"method": method, "seed": seed, "scenario_id": graph.scenario_id,
                                       "source_graph": graph.source_graph_path,
                                       "constraint_audit": EvidencePathGuard(graph).metrics(actions)}
            (destination / "pruned.json").write_text(json.dumps(pruned, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "method": method,
        "seed": int(seed),
        "scenario_id": _scenario_id(graph, fallback_id),
        "edge_count": int(graph.edge_index.size(1)),
        **{name: float(metrics[name]) for name in METRIC_NAMES if name in metrics},
    }


def _percentile(values, probability):
    values = sorted(float(value) for value in values)
    if not values:
        return 0.0
    position = (len(values) - 1) * float(probability)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return values[lower]
    fraction = position - lower
    return values[lower] * (1.0 - fraction) + values[upper] * fraction


def _bootstrap_mean_ci(values, seed=20260714, iterations=2000):
    values = [float(value) for value in values]
    if not values:
        return [0.0, 0.0]
    if len(values) == 1:
        return [values[0], values[0]]
    rng = random.Random(int(seed))
    means = [
        statistics.fmean(rng.choice(values) for _ in values)
        for _ in range(int(iterations))
    ]
    return [_percentile(means, 0.025), _percentile(means, 0.975)]


def _scenario_metric_values(rows, method, metric):
    grouped = {}
    for row in rows:
        if row["method"] == method:
            grouped.setdefault(row["scenario_id"], []).append(float(row[metric]))
    return {scenario_id: statistics.fmean(values) for scenario_id, values in grouped.items()}


def _aggregate(rows):
    result = {}
    methods = sorted({row["method"] for row in rows})
    for method_index, method in enumerate(methods):
        method_rows = [row for row in rows if row["method"] == method]
        scenario_ids = sorted({row["scenario_id"] for row in method_rows})
        seeds = sorted({int(row["seed"]) for row in method_rows})
        summary = {
            "scenario_count": len(scenario_ids),
            "seed_count": len(seeds),
            "raw_rows": len(method_rows),
            "aggregation_unit": "scenario_mean_over_seeds",
        }
        for metric_index, metric in enumerate(METRIC_NAMES):
            if not all(metric in row for row in method_rows):
                continue
            scenario_values = list(_scenario_metric_values(rows, method, metric).values())
            summary[f"{metric}_mean"] = statistics.fmean(scenario_values) if scenario_values else 0.0
            summary[f"{metric}_std"] = statistics.stdev(scenario_values) if len(scenario_values) > 1 else 0.0
            summary[f"{metric}_ci95"] = _bootstrap_mean_ci(
                scenario_values,
                seed=20260714 + method_index * 101 + metric_index,
            )
        result[method] = summary
    return result


def _paired_randomization_pvalue(differences, seed=20260714, iterations=20000):
    differences = [float(value) for value in differences]
    if not differences:
        return None
    observed = abs(statistics.fmean(differences))
    if all(abs(value) < 1e-12 for value in differences):
        return 1.0
    if len(differences) <= 16:
        signs = itertools.product((-1.0, 1.0), repeat=len(differences))
        randomized = [
            abs(statistics.fmean(sign * value for sign, value in zip(pattern, differences)))
            for pattern in signs
        ]
        return sum(value >= observed - 1e-12 for value in randomized) / len(randomized)
    rng = random.Random(int(seed))
    extreme = 0
    for _ in range(int(iterations)):
        value = abs(statistics.fmean(
            difference * (-1.0 if rng.random() < 0.5 else 1.0)
            for difference in differences
        ))
        extreme += value >= observed - 1e-12
    return (extreme + 1) / (int(iterations) + 1)


def _paired_comparison(rows, reference, candidate, metric, seed=20260714):
    reference_values = _scenario_metric_values(rows, reference, metric)
    candidate_values = _scenario_metric_values(rows, candidate, metric)
    scenario_ids = sorted(set(reference_values) & set(candidate_values))
    differences = [reference_values[item] - candidate_values[item] for item in scenario_ids]
    return {
        "reference": reference,
        "candidate": candidate,
        "metric": metric,
        "paired_scenarios": len(scenario_ids),
        "mean_difference": statistics.fmean(differences) if differences else None,
        "difference_ci95": _bootstrap_mean_ci(differences, seed=seed) if differences else None,
        "paired_randomization_pvalue": _paired_randomization_pvalue(differences, seed=seed),
    }


def _comparisons(rows):
    methods = sorted({row["method"] for row in rows})
    pairs = []
    primary = "dqn_path_constrained"
    for candidate in methods:
        if candidate == primary or "_no_" in candidate:
            continue
        pairs.append((primary, candidate))
    for candidate in methods:
        if "_no_" not in candidate:
            continue
        base = candidate.split("_no_", 1)[0]
        if base in methods:
            pairs.append((base, candidate))
    result = []
    for pair_index, (reference, candidate) in enumerate(sorted(set(pairs))):
        for metric_index, metric in enumerate(COMPARISON_METRICS):
            if not all(metric in row for row in rows if row["method"] in (reference, candidate)):
                continue
            result.append(_paired_comparison(
                rows,
                reference,
                candidate,
                metric,
                seed=20260714 + pair_index * 101 + metric_index,
            ))
    valid = sorted((row for row in result if row["paired_randomization_pvalue"] is not None),
                   key=lambda row: row["paired_randomization_pvalue"])
    previous = 0.0
    for index, row in enumerate(valid):
        previous = max(previous, min(1.0, (len(valid) - index) * row["paired_randomization_pvalue"]))
        row["holm_adjusted_pvalue"] = previous
    return result


def _train_and_evaluate(
    dataset,
    output_dir,
    seed,
    epochs,
    disabled_feature_groups=None,
    method_suffix="",
    dqn_options=None,
    include_baselines=False,
    device="cpu",
):
    set_seed(seed)
    train_graphs = dataset.load_split("train", disabled_feature_groups=disabled_feature_groups)
    val_graphs = dataset.load_split("validation", disabled_feature_groups=disabled_feature_groups)
    test_graphs = dataset.load_split("test", disabled_feature_groups=disabled_feature_groups)
    train_partitions = partition_graphs(train_graphs, max_edges=256)
    val_partitions = partition_graphs(val_graphs, max_edges=256)

    checkpoint_dir = output_dir / "checkpoints" / f"seed_{seed}{method_suffix}"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    dqn = DQNTrainer(
        epochs=epochs,
        patience=max(5, epochs // 4),
        seed=seed,
        device=device,
        **(dqn_options or {}),
    )
    dqn.train(train_partitions, val_partitions, save_path=str(checkpoint_dir / "dqn.pt"))

    constrained = DQNTrainer(
        epochs=epochs, patience=max(5, epochs // 4), seed=seed, device=device,
        use_path_constraints=True, **(dqn_options or {}),
    )
    constrained.train(train_partitions, val_partitions,
                      save_path=str(checkpoint_dir / "dqn_path_constrained.pt"))

    supervised = None
    if include_baselines:
        supervised = SupervisedGATTrainer(
            epochs=epochs,
            patience=max(5, epochs // 4),
            seed=seed,
            device=device,
        )
        supervised.train(
            train_partitions,
            val_partitions,
            save_path=str(checkpoint_dir / "supervised_gat.pt"),
        )

    rows = []
    suffix = method_suffix
    def record(method, seed, graph, actions, index):
        return _metric_row(method, seed, graph, actions, index, output_dir=output_dir)
    for graph_index, graph in enumerate(test_graphs):
        raw_actions, _ = dqn.predict_actions(graph, evidence_guardrail=False)
        constrained_actions, _ = dqn.predict_actions(graph, evidence_guardrail=True)
        path_actions, _ = constrained.predict_actions(graph, evidence_guardrail=False)
        rows.append(record(f"dqn_path_constrained{suffix}", seed, graph, path_actions, graph_index))
        rows.append(record(f"dqn{suffix}", seed, graph, raw_actions, graph_index))
        rows.append(record(
            f"dqn_evidence_constraint{suffix}",
            seed,
            graph,
            constrained_actions,
            graph_index,
        ))

        if supervised is not None:
            supervised_actions, _ = supervised.predict_actions(graph, evidence_guardrail=False)
            guard = EvidencePathGuard(graph)
            rule_guarded, _ = guard.filter_actions(evidence_rule_actions(graph))
            supervised_guarded, _ = guard.filter_actions(supervised_actions)
            rows.append(record("evidence_rule_path_constrained", seed, graph, rule_guarded, graph_index))
            rows.append(record("supervised_gat_path_constrained", seed, graph, supervised_guarded, graph_index))
            rows.append(record("supervised_gat", seed, graph, supervised_actions, graph_index))
            rows.append(record("keep_all", seed, graph, keep_all_actions(graph), graph_index))
            rows.append(record(
                "evidence_rule",
                seed,
                graph,
                evidence_rule_actions(graph),
                graph_index,
            ))
            prune_count = int((path_actions == 1).sum().item())
            rows.append(record(
                "random_matched_compression",
                seed,
                graph,
                random_matched_actions(graph, prune_count, seed=seed * 1000 + graph_index),
                graph_index,
            ))
    return rows


def run_benchmark(
    manifest,
    output_dir,
    seeds,
    epochs,
    feature_ablations,
    device,
    mechanism_ablations=(),
):
    dataset = ScenarioDataset(
        manifest,
        require_complete_labels=True,
        require_double_annotation=True,
        require_raw_alerts=True,
        minimum_split_counts={"train": 6, "validation": 2, "test": 2},
    )
    validation = dataset.assert_valid(require_all_splits=True)
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for seed in seeds:
        rows.extend(_train_and_evaluate(
            dataset,
            output_dir,
            seed,
            epochs,
            include_baselines=True,
            device=device,
        ))
        for group in feature_ablations:
            rows.extend(_train_and_evaluate(
                dataset,
                output_dir,
                seed,
                epochs,
                disabled_feature_groups=[group],
                method_suffix=f"_no_{group}",
                device=device,
            ))
        for mechanism in mechanism_ablations:
            if mechanism not in MECHANISM_ABLATIONS:
                raise ValueError(
                    f"unknown mechanism ablation {mechanism!r}; "
                    f"expected one of {sorted(MECHANISM_ABLATIONS)}"
                )
            rows.extend(_train_and_evaluate(
                dataset,
                output_dir,
                seed,
                epochs,
                dqn_options=MECHANISM_ABLATIONS[mechanism],
                method_suffix=f"_no_{mechanism}",
                device=device,
            ))

    payload = {
        "experiment": "attack_graph_pruning_benchmark_v1",
        "reproducibility": {
            "python": platform.python_version(), "torch": torch.__version__,
            "git_revision": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
            "working_tree_dirty": bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout.strip()),
            "manifest_sha256": hashlib.sha256(Path(manifest).read_bytes()).hexdigest(),
            "input_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                             for record in dataset.records
                             for path in (record.graph_path, record.label_path, record.raw_alerts_path, record.path_gold_path)
                             if path is not None},
        },
        "manifest": str(Path(manifest).resolve()),
        "dataset_validation": validation,
        "config": {
            "seeds": list(seeds),
            "epochs": int(epochs),
            "feature_ablations": list(feature_ablations),
            "mechanism_ablations": list(mechanism_ablations),
            "device": device,
            "formal_dataset_requirements_enforced": True,
            "test_labels_used_for_inference": False,
            "split_unit": "independent_attack_scenario",
        },
        "aggregate": _aggregate(rows),
        "paired_comparisons": _comparisons(rows),
        "per_scenario": rows,
    }
    with open(output_dir / "benchmark_results.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    with open(output_dir / "benchmark_results.csv", "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dict.fromkeys(key for row in rows for key in row)) if rows else ["method"])
        writer.writeheader()
        writer.writerows(rows)
    return payload


def main():
    parser = argparse.ArgumentParser(description="Run scenario-isolated graph-pruning benchmarks")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seeds", default="42,43,44,45,46")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument(
        "--feature-ablations",
        default="",
        help="comma-separated feature groups: identity,cross_honeypot,temporal,origin_score",
    )
    parser.add_argument(
        "--mechanism-ablations",
        default="",
        help="comma-separated DQN mechanisms: dynamic_state,terminal_reward,shuffled_order",
    )
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
    feature_ablations = [
        value.strip() for value in args.feature_ablations.split(",") if value.strip()
    ]
    mechanism_ablations = [
        value.strip() for value in args.mechanism_ablations.split(",") if value.strip()
    ]
    payload = run_benchmark(
        args.manifest,
        args.output_dir,
        seeds,
        args.epochs,
        feature_ablations,
        args.device,
        mechanism_ablations=mechanism_ablations,
    )
    print(json.dumps(payload["aggregate"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
