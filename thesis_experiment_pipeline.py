"""
论文实验专用流水线（不含LLM在线推理）

目标：
1. 固化 step1-step4 流程，减少目录混乱；
2. 每次运行单独产出到 experiments/runs/<run_name>/；
3. 生成可写入论文的实验摘要 JSON。
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

import numpy as np
import torch

from deployment.export_alerts_to_step1 import build_live_analysis_collector_config
from step1_data_collection import DataCollector
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
from step3_dqn_pruning import DQNTrainer, load_graphs_for_training, get_graph_statistics
from step4_graph_to_text import GraphToTextConverter


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_run_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name.strip())
    return cleaned or datetime.now().strftime("run_%Y%m%d_%H%M%S")


def run_step1(run_dir: Path, hours: int) -> Dict:
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
        "time_range": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
    }


def run_step2(run_dir: Path, step1_file: Path) -> Dict:
    with open(step1_file, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(alerts)

    graph_json = run_dir / "step2_causal_graph.json"
    graph_mmd = run_dir / "step2_causal_graph.mmd"
    triples_json = run_dir / "step2_standard_triples.json"
    sequence_json = run_dir / "step2_event_sequence.json"
    provenance_json = run_dir / "step2_provenance_chains.json"

    with open(graph_json, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, ensure_ascii=False, indent=2)
    with open(triples_json, "w", encoding="utf-8") as f:
        json.dump(graph_data.get("triples", []), f, ensure_ascii=False, indent=2)
    with open(sequence_json, "w", encoding="utf-8") as f:
        json.dump(graph_data.get("event_sequence", []), f, ensure_ascii=False, indent=2)
    with open(provenance_json, "w", encoding="utf-8") as f:
        json.dump(graph_data.get("provenance_chains", []), f, ensure_ascii=False, indent=2)
    CausalGraphVisualizer.save_mermaid(graph_data, str(graph_mmd), "Thesis Causal Graph")

    return {
        "json": str(graph_json),
        "mermaid": str(graph_mmd),
        "triples_json": str(triples_json),
        "event_sequence_json": str(sequence_json),
        "provenance_chains_json": str(provenance_json),
        "nodes": len(graph_data.get("nodes", [])),
        "edges": len(graph_data.get("edges", [])),
        "triples": len(graph_data.get("triples", [])),
        "provenance_chains": len(graph_data.get("provenance_chains", [])),
    }


def run_step3(run_dir: Path, graph_json: Path, epochs: int, seed: int = 42) -> Dict:
    stats_before = get_graph_statistics(str(graph_json))

    train_graphs = load_graphs_for_training(str(graph_json), num_graphs=120, augment=True, base_seed=seed)
    val_graphs = load_graphs_for_training(str(graph_json), num_graphs=24, augment=True, base_seed=seed + 1000)
    test_graphs = load_graphs_for_training(str(graph_json), num_graphs=36, augment=False, base_seed=seed + 2000)

    ckpt_dir = run_dir / "checkpoints"
    ensure_dir(ckpt_dir)
    ckpt = ckpt_dir / "dqn_best.pt"

    trainer = DQNTrainer(epochs=epochs, patience=20)
    trainer.train(train_graphs, val_graphs, save_path=str(ckpt))
    metrics = trainer.evaluate_on_test(test_graphs)

    pruned_json = run_dir / "step3_pruned_graph.json"
    pruned_data = trainer.predict_and_prune(str(graph_json), str(pruned_json))

    pruning_stats = pruned_data.get("pruning_stats", {})
    return {
        "input_stats": stats_before,
        "checkpoint": str(ckpt),
        "output_graph": str(pruned_json),
        "metrics": metrics,
        "pruning_stats": pruning_stats,
    }


def run_step4(run_dir: Path, pruned_json: Path) -> Dict:
    with open(pruned_json, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    converter = GraphToTextConverter()
    outputs = {}
    for task in ("intent_analysis", "ttp_mapping", "report"):
        text = converter.convert_to_llm_prompt(graph_data, task)
        out_file = run_dir / f"step4_prompt_{task}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(text)
        outputs[task] = {
            "file": str(out_file),
            "chars": len(text),
        }
    return outputs


def run_pipeline(run_name: str, hours: int, epochs: int, seed: int) -> Path:
    set_seed(seed)

    base_dir = Path(__file__).parent
    run_root = base_dir / "experiments" / "runs" / datetime.now().strftime("%Y-%m-%d")
    ensure_dir(run_root)
    run_dir = run_root / safe_run_name(run_name)
    ensure_dir(run_dir)

    print("=" * 70)
    print("  论文实验流水线（Step1-Step4）")
    print("=" * 70)
    print(f"  输出目录: {run_dir}")
    print(f"  seed: {seed}, hours: {hours}, epochs: {epochs}")

    step1 = run_step1(run_dir, hours)
    step2 = run_step2(run_dir, Path(step1["file"]))
    step3 = run_step3(run_dir, Path(step2["json"]), epochs, seed)
    step4 = run_step4(run_dir, Path(step3["output_graph"]))

    summary = {
        "project": "基于蜜点技术的APT攻击检测与意图推理系统",
        "run_name": run_dir.name,
        "generated_at": datetime.now().isoformat(),
        "config": {
            "hours": hours,
            "epochs": epochs,
            "seed": seed,
            "llm_inference": False,
        },
        "step1": step1,
        "step2": step2,
        "step3": step3,
        "step4": step4,
    }

    summary_file = run_dir / "experiment_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 70)
    print("  运行完成")
    print("=" * 70)
    print(f"  实验摘要: {summary_file}")
    return summary_file


def main() -> None:
    parser = argparse.ArgumentParser(description="论文实验专用流水线")
    parser.add_argument("--run-name", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    parser.add_argument("--hours", type=int, default=24, help="Step1 时间窗口（小时）")
    parser.add_argument("--epochs", type=int, default=80, help="Step3 训练轮数")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    args = parser.parse_args()

    run_pipeline(args.run_name, args.hours, args.epochs, args.seed)


if __name__ == "__main__":
    main()
