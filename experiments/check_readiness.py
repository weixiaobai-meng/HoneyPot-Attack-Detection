"""Check experiment artifact completeness, not university degree eligibility."""

import argparse
import json
from pathlib import Path


def check(benchmark, scale, llm):
    errors = []
    config = benchmark.get("config", {})
    validation = benchmark.get("dataset_validation", {})
    if not config.get("formal_dataset_requirements_enforced") or not validation.get("valid"):
        errors.append("benchmark must pass formal dataset validation; diagnostics do not count")
    if len(set(config.get("seeds", []))) < 5:
        errors.append("at least five seeds required by this experiment protocol")
    required = {"keep_all", "random_matched_compression", "evidence_rule", "supervised_gat", "dqn",
                "dqn_evidence_constraint", "dqn_path_constrained", "evidence_rule_path_constrained",
                "supervised_gat_path_constrained"}
    aggregates = benchmark.get("aggregate", {})
    if not required <= set(aggregates):
        errors.append("missing comparison methods")
    if not config.get("feature_ablations") or not config.get("mechanism_ablations"):
        errors.append("feature and mechanism ablations are required")
    rows = benchmark.get("per_scenario", [])
    if not rows or any("complete_path_recall" not in row for row in rows):
        errors.append("independent path-gold metrics are missing")
    for row in rows:
        if row.get("method") == "dqn_path_constrained":
            if row.get("required_paths_kept") != row.get("required_path_count") or row.get("protected_edges_kept") != row.get("protected_edge_count"):
                errors.append("primary method violates an input constraint")
                break
    scale_rows = scale.get("results", [])
    if not scale.get("config", {}).get("formal_dataset_requirements_enforced"):
        errors.append("scale results must use formal data")
    if not scale_rows or any(row.get("status") != "ok" for row in scale_rows):
        errors.append("scale sweep has missing or failed runs")
    if any(
        row.get("status") == "ok"
        and (
            not row.get("constraints_satisfied")
            or row.get("required_paths_kept") != row.get("required_path_count")
        )
        for row in scale_rows
    ):
        errors.append("scale sweep contains a path-constraint violation")
    sizes = {row.get("edge_count") for row in scale_rows if row.get("status") == "ok"}
    if len(sizes) < 3:
        errors.append("at least three real graph sizes required by this protocol")
    if not any(row.get("partition_edges") == 0 and row.get("decision_batch_size") == 1 for row in scale_rows):
        errors.append("missing full-graph sequential reference")
    if llm.get("errors") or set(llm.get("aggregate", {})) != {"raw_alerts", "full_graph", "pruned_graph"}:
        errors.append("LLM matched-condition evaluation is incomplete")
    if not llm.get("intent_evaluation_available"):
        errors.append("independent intent gold is missing")
    return {"protocol_artifacts_complete": not errors, "errors": errors,
            "scope": "artifact checks only; novelty, result interpretation and graduation require human review"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("benchmark", "scale", "llm", "output"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    load = lambda path: json.loads(Path(path).read_text(encoding="utf-8-sig"))
    report = check(load(args.benchmark), load(args.scale), load(args.llm))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
