"""Collect real alerts and prepare scientifically valid experiment inputs.

This entry point deliberately does not manufacture weak labels or report model
accuracy from augmented copies of one graph. Model benchmarking starts only
after an independent scenario manifest has been validated.
"""

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

from deployment.export_alerts_to_step1 import build_live_analysis_collector_config
from experiments.run_benchmark import run_benchmark
from step1_data_collection import DataCollector
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_run_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name.strip())
    return cleaned or datetime.now().strftime("run_%Y%m%d_%H%M%S")


def run_step1(run_dir: Path, hours: int):
    start = datetime.now() - timedelta(hours=hours)
    end = datetime.now()
    collector = DataCollector(config=build_live_analysis_collector_config())
    alerts = collector.collect_all(start, end)
    out_file = run_dir / "step1_unified_alerts.json"
    collector.save_alerts(alerts, str(out_file))
    return {
        "file": str(out_file),
        "count": len(alerts),
        "analysis_source_mode": "systemwire2_unified_only",
        "time_range": {"start": start.isoformat(), "end": end.isoformat()},
    }


def run_step2(run_dir: Path, step1_file: Path):
    with open(step1_file, "r", encoding="utf-8") as handle:
        alerts = json.load(handle)
    graph_data = CausalGraphBuilder().build_from_alerts(alerts)
    outputs = {
        "json": run_dir / "step2_causal_graph.json",
        "mermaid": run_dir / "step2_causal_graph.mmd",
        "triples_json": run_dir / "step2_standard_triples.json",
        "event_sequence_json": run_dir / "step2_event_sequence.json",
        "provenance_chains_json": run_dir / "step2_provenance_chains.json",
    }
    for key, field in [
        ("json", None),
        ("triples_json", "triples"),
        ("event_sequence_json", "event_sequence"),
        ("provenance_chains_json", "provenance_chains"),
    ]:
        payload = graph_data if field is None else graph_data.get(field, [])
        with open(outputs[key], "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
    CausalGraphVisualizer.save_mermaid(graph_data, str(outputs["mermaid"]), "Experiment Causal Graph")
    return {
        **{key: str(value) for key, value in outputs.items()},
        "nodes": len(graph_data.get("nodes", [])),
        "edges": len(graph_data.get("edges", [])),
        "triples": len(graph_data.get("triples", [])),
    }


def create_edge_label_template(graph_path: Path, output_path: Path):
    with open(graph_path, "r", encoding="utf-8") as handle:
        graph = json.load(handle)
    rows = []
    for edge in graph.get("edges", []):
        rows.append({
            "edge_id": edge.get("edge_id"),
            "label": None,
            "annotation_note": "",
            "source": edge.get("source"),
            "action": edge.get("action"),
            "target": edge.get("target"),
            "relation_type": edge.get("relation_type"),
            "timestamp": edge.get("timestamp"),
            "confidence": edge.get("confidence"),
            "shared_evidence": edge.get("shared_evidence") or [],
        })
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)
    return {"file": str(output_path), "rows": len(rows), "labels_completed": 0}


def run_pipeline(
    run_name: str,
    hours: int,
    dataset_manifest=None,
    epochs=40,
    seeds=(42, 43, 44, 45, 46),
    feature_ablations=(),
    mechanism_ablations=(),
    device="cpu",
):
    base_dir = Path(__file__).parent
    run_root = base_dir / "experiments" / "runs" / datetime.now().strftime("%Y-%m-%d")
    run_dir = run_root / safe_run_name(run_name)
    ensure_dir(run_dir)
    step1 = run_step1(run_dir, hours)
    step2 = run_step2(run_dir, Path(step1["file"]))
    annotation = create_edge_label_template(
        Path(step2["json"]),
        run_dir / "edge_labels.annotation_template.json",
    )

    benchmark = None
    if dataset_manifest:
        benchmark = run_benchmark(
            dataset_manifest,
            run_dir / "benchmark",
            seeds,
            epochs,
            feature_ablations,
            device,
            mechanism_ablations=mechanism_ablations,
        )
    summary = {
        "project": "协同蜜点攻击图谱裁剪与语义分析实验",
        "run_name": run_dir.name,
        "generated_at": datetime.now().isoformat(),
        "status": "benchmark_complete" if benchmark else "awaiting_manual_labels_and_scenario_manifest",
        "scientific_validity": {
            "synthetic_labels_used": False,
            "same_graph_augmentation_metrics_reported": False,
            "test_labels_used_for_inference": False,
        },
        "step1": step1,
        "step2": step2,
        "annotation_template": annotation,
        "benchmark": benchmark,
    }
    summary_file = run_dir / "experiment_summary.json"
    with open(summary_file, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
    print(f"experiment preparation complete: {summary_file}")
    return summary_file


def main():
    parser = argparse.ArgumentParser(description="Prepare real-data thesis experiments")
    parser.add_argument("--run-name", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--dataset-manifest")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--seeds", default="42,43,44,45,46")
    parser.add_argument("--feature-ablations", default="")
    parser.add_argument("--mechanism-ablations", default="")
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    run_pipeline(
        args.run_name,
        args.hours,
        dataset_manifest=args.dataset_manifest,
        epochs=args.epochs,
        seeds=tuple(int(value) for value in args.seeds.split(",") if value.strip()),
        feature_ablations=tuple(
            value.strip() for value in args.feature_ablations.split(",") if value.strip()
        ),
        mechanism_ablations=tuple(
            value.strip() for value in args.mechanism_ablations.split(",") if value.strip()
        ),
        device=args.device,
    )


if __name__ == "__main__":
    main()
