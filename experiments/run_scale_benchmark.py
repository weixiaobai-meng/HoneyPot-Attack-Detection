"""Measure pruning quality and resource use on real scenario graph sizes."""

import argparse
import csv
import json
import os
import statistics
import time
from pathlib import Path

import torch

from experiments.dataset import ScenarioDataset
from step3_dqn_pruning import DQNTrainer
from step3_dqn_pruning.trainer import pruning_metrics_from_actions


def _rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except ImportError:
        return None


def _as_list(value):
    if isinstance(value, (list, tuple)):
        return [int(item) for item in value]
    return [int(value)]


def _aggregate(rows):
    grouped = {}
    for row in rows:
        if row.get("status") != "ok":
            continue
        key = (row["partition_edges"], row["decision_batch_size"])
        grouped.setdefault(key, []).append(row)
    result = []
    for (partition_edges, batch_size), values in sorted(grouped.items()):
        deltas = [
            row["core_recall_delta_vs_full"]
            for row in values
            if row.get("core_recall_delta_vs_full") is not None
        ]
        result.append({
            "partition_edges": partition_edges,
            "decision_batch_size": batch_size,
            "scenario_count": len(values),
            "latency_ms_median": statistics.median(row["latency_ms_median"] for row in values),
            "edges_per_second_median": statistics.median(row["edges_per_second"] for row in values),
            "core_recall_mean": statistics.fmean(row["core_recall"] for row in values),
            "noise_filter_rate_mean": statistics.fmean(row["noise_filter_rate"] for row in values),
            "f1_mean": statistics.fmean(row["f1"] for row in values),
            "compression_ratio_mean": statistics.fmean(row["compression_ratio"] for row in values),
            "core_recall_delta_vs_full_mean": statistics.fmean(deltas) if deltas else None,
        })
    return result


def run(
    manifest,
    checkpoint,
    output,
    split,
    partition_edges,
    decision_batch_sizes,
    device,
    repeats=3,
    warmup=1,
    allow_small_dataset_smoke_test=False,
):
    dataset = ScenarioDataset(
        manifest,
        require_complete_labels=True,
        require_double_annotation=not allow_small_dataset_smoke_test,
        require_raw_alerts=not allow_small_dataset_smoke_test,
        minimum_split_counts=None if allow_small_dataset_smoke_test else {"train": 6, "validation": 2, "test": 2},
    )
    validation = dataset.assert_valid(require_all_splits=True)
    graphs = dataset.load_split(split)
    trainer = DQNTrainer(device=device)
    state = torch.load(checkpoint, map_location=trainer.device, weights_only=True)
    trainer.model.load_state_dict(state)
    trainer.target_model.load_state_dict(state)

    partition_values = _as_list(partition_edges)
    batch_values = _as_list(decision_batch_sizes)
    if any(value < 0 for value in partition_values):
        raise ValueError("partition edge limits must be zero (full graph) or positive")
    if any(value <= 0 for value in batch_values):
        raise ValueError("decision batch sizes must be positive")

    rows = []
    for index, graph in enumerate(graphs):
        scenario_rows = []
        for partition_limit in partition_values:
            for batch_size in batch_values:
                try:
                    for _ in range(max(int(warmup), 0)):
                        trainer.predict_actions(
                            graph,
                            evidence_guardrail=True,
                            max_edges_per_partition=partition_limit or None,
                            decision_batch_size=batch_size,
                        )
                    timings = []
                    before_rss = _rss_mb()
                    if trainer.device.type == "cuda":
                        torch.cuda.reset_peak_memory_stats(trainer.device)
                    actions = None
                    details = None
                    for _ in range(max(int(repeats), 1)):
                        if trainer.device.type == "cuda":
                            torch.cuda.synchronize(trainer.device)
                        started = time.perf_counter()
                        actions, details = trainer.predict_actions(
                            graph,
                            evidence_guardrail=True,
                            max_edges_per_partition=partition_limit or None,
                            decision_batch_size=batch_size,
                        )
                        if trainer.device.type == "cuda":
                            torch.cuda.synchronize(trainer.device)
                        timings.append((time.perf_counter() - started) * 1000)
                    after_rss = _rss_mb()
                    elapsed_ms = statistics.median(timings)
                    metrics = pruning_metrics_from_actions(actions, graph.y)
                    scenario_rows.append({
                        "status": "ok",
                        "scenario_id": str(getattr(graph, "scenario_id", index)),
                        "edge_count": int(graph.edge_index.size(1)),
                        "node_count": int(graph.x.size(0)),
                        "latency_ms_median": elapsed_ms,
                        "latency_ms_runs": timings,
                        "edges_per_second": int(graph.edge_index.size(1)) / max(elapsed_ms / 1000, 1e-8),
                        "rss_before_mb": before_rss,
                        "rss_after_mb": after_rss,
                        "rss_delta_mb": None if before_rss is None or after_rss is None else after_rss - before_rss,
                        "cuda_peak_mb": (
                            torch.cuda.max_memory_allocated(trainer.device) / (1024 * 1024)
                            if trainer.device.type == "cuda" else None
                        ),
                        "partition_count": details["partition_count"],
                        "partition_edges": partition_limit,
                        "decision_batch_size": batch_size,
                        "core_recall": metrics["core_recall"],
                        "noise_filter_rate": metrics["noise_filter_rate"],
                        "f1": metrics["f1"],
                        "compression_ratio": metrics["compression_ratio"],
                    })
                except RuntimeError as exc:
                    scenario_rows.append({
                        "status": "runtime_error",
                        "scenario_id": str(getattr(graph, "scenario_id", index)),
                        "edge_count": int(graph.edge_index.size(1)),
                        "node_count": int(graph.x.size(0)),
                        "partition_edges": partition_limit,
                        "decision_batch_size": batch_size,
                        "error": str(exc),
                    })
        full_reference = next((
            row for row in scenario_rows
            if row.get("status") == "ok"
            and row["partition_edges"] == 0
            and row["decision_batch_size"] == 1
        ), None)
        for row in scenario_rows:
            if row.get("status") == "ok":
                row["core_recall_delta_vs_full"] = (
                    row["core_recall"] - full_reference["core_recall"] if full_reference else None
                )
                row["f1_delta_vs_full"] = (
                    row["f1"] - full_reference["f1"] if full_reference else None
                )
        rows.extend(scenario_rows)

    payload = {
        "experiment": "real_graph_scale_benchmark_v1",
        "manifest": str(Path(manifest).resolve()),
        "checkpoint": str(Path(checkpoint).resolve()),
        "dataset_validation": validation,
        "config": {
            "split": split,
            "partition_edges": partition_values,
            "decision_batch_sizes": batch_values,
            "repeats": int(repeats),
            "warmup": int(warmup),
            "device": device,
            "data_repetition_or_synthetic_scaling": False,
            "formal_dataset_requirements_enforced": not allow_small_dataset_smoke_test,
        },
        "aggregate": _aggregate(rows),
        "results": rows,
    }
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    csv_path = output.with_suffix(".csv")
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as handle:
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["scenario_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return payload


def main():
    parser = argparse.ArgumentParser(description="Benchmark DQN pruning on actual graph scales")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--split", default="test", choices=["train", "validation", "test"])
    parser.add_argument("--partition-edges", default="0,128,256,512,1024")
    parser.add_argument("--decision-batch-sizes", default="1,8,16")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--allow-small-dataset-smoke-test", action="store_true")
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    result = run(
        args.manifest,
        args.checkpoint,
        args.output,
        args.split,
        [int(value) for value in args.partition_edges.split(",") if value.strip()],
        [int(value) for value in args.decision_batch_sizes.split(",") if value.strip()],
        args.device,
        repeats=args.repeats,
        warmup=args.warmup,
        allow_small_dataset_smoke_test=args.allow_small_dataset_smoke_test,
    )
    print(json.dumps(result["results"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
