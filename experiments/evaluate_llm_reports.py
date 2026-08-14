"""Evaluate structured LLM outputs and optional blinded human ratings."""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def _normalize(value):
    return " ".join(str(value).strip().lower().split())


def _items(case, field):
    values = case.get(field) or []
    result = set()
    for value in values:
        if isinstance(value, dict):
            value = value.get("id") or value.get("text") or value.get("name") or ""
        normalized = _normalize(value)
        if normalized:
            result.add(normalized)
    return result


def _set_metrics(predicted, gold):
    true_positive = len(predicted & gold)
    precision = true_positive / max(len(predicted), 1)
    recall = true_positive / max(len(gold), 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "supported": true_positive,
        "predicted": len(predicted),
        "gold": len(gold),
        "unsupported": len(predicted - gold),
    }


def evaluate_structured(prediction_payload, gold_payload, expected_conditions=None):
    gold_by_id = {str(case["case_id"]): case for case in gold_payload.get("cases", [])}
    rows = []
    errors = []
    seen = set()
    for case in prediction_payload.get("cases", []):
        case_id = str(case.get("case_id") or "")
        condition = str(case.get("condition") or "unknown")
        key = (case_id, condition)
        if key in seen:
            errors.append(f"duplicate prediction for case/condition {case_id!r}/{condition!r}")
            continue
        seen.add(key)
        if case_id not in gold_by_id:
            errors.append(f"prediction case {case_id!r} has no gold case")
            continue
        gold = gold_by_id[case_id]
        fact = _set_metrics(_items(case, "facts"), _items(gold, "facts"))
        ttp = _set_metrics(_items(case, "ttps"), _items(gold, "ttps"))
        stage = _set_metrics(_items(case, "attack_stages"), _items(gold, "attack_stages"))
        rows.append({
            "case_id": case_id,
            "condition": condition,
            "fact_precision": fact["precision"],
            "fact_recall": fact["recall"],
            "fact_f1": fact["f1"],
            "hallucination_count": fact["unsupported"],
            "ttp_precision": ttp["precision"],
            "ttp_recall": ttp["recall"],
            "ttp_f1": ttp["f1"],
            "stage_f1": stage["f1"],
            "input_tokens": float(case.get("input_tokens") or 0),
            "output_tokens": float(case.get("output_tokens") or 0),
            "latency_ms": float(case.get("latency_ms") or 0),
        })
    expected_conditions = [str(value) for value in (expected_conditions or []) if str(value)]
    for case_id in sorted(gold_by_id):
        for condition in expected_conditions:
            if (case_id, condition) not in seen:
                errors.append(f"missing prediction for case/condition {case_id!r}/{condition!r}")
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["condition"]].append(row)
    aggregate = {}
    metric_names = [key for key in rows[0] if key not in {"case_id", "condition"}] if rows else []
    for condition, condition_rows in grouped.items():
        aggregate[condition] = {"cases": len(condition_rows)}
        for metric in metric_names:
            values = [float(row[metric]) for row in condition_rows]
            aggregate[condition][f"{metric}_mean"] = statistics.fmean(values)
            aggregate[condition][f"{metric}_std"] = statistics.stdev(values) if len(values) > 1 else 0.0
    return {"errors": errors, "aggregate": aggregate, "per_case": rows}


def _quadratic_weighted_kappa(pairs, minimum=1, maximum=5):
    pairs = [(int(round(left)), int(round(right))) for left, right in pairs]
    if not pairs:
        return None
    categories = list(range(int(minimum), int(maximum) + 1))
    size = len(categories)
    index = {value: idx for idx, value in enumerate(categories)}
    confusion = [[0.0] * size for _ in range(size)]
    left_counts = [0.0] * size
    right_counts = [0.0] * size
    for left, right in pairs:
        if left not in index or right not in index:
            raise ValueError(f"rating values must be in [{minimum}, {maximum}]")
        i = index[left]
        j = index[right]
        confusion[i][j] += 1.0
        left_counts[i] += 1.0
        right_counts[j] += 1.0
    total = float(len(pairs))
    denominator = max((size - 1) ** 2, 1)
    observed = 0.0
    expected = 0.0
    for i in range(size):
        for j in range(size):
            weight = ((i - j) ** 2) / denominator
            observed += weight * confusion[i][j] / total
            expected += weight * (left_counts[i] * right_counts[j]) / (total * total)
    if expected < 1e-12:
        return 1.0 if observed < 1e-12 else 0.0
    return 1.0 - observed / expected


def evaluate_human_ratings(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"case_id", "condition", "rater_id", "factuality", "chain_coverage", "ttp_correctness", "readability"}
    missing = sorted(required - set(rows[0] if rows else []))
    if missing:
        raise ValueError(f"human rating CSV missing columns: {missing}")
    metrics = ["factuality", "chain_coverage", "ttp_correctness", "readability"]
    grouped = defaultdict(list)
    by_item = defaultdict(list)
    for row in rows:
        condition = row["condition"]
        numeric = {metric: float(row[metric]) for metric in metrics}
        grouped[condition].append(numeric)
        by_item[(row["case_id"], condition)].append((row["rater_id"], numeric))
    aggregate = {}
    for condition, values in grouped.items():
        aggregate[condition] = {"ratings": len(values)}
        for metric in metrics:
            scores = [row[metric] for row in values]
            aggregate[condition][f"{metric}_mean"] = statistics.fmean(scores)
            aggregate[condition][f"{metric}_std"] = statistics.stdev(scores) if len(scores) > 1 else 0.0
    agreement = {}
    for metric in metrics:
        differences = []
        pairs = []
        for values in by_item.values():
            if len(values) >= 2:
                ordered = [item[1] for item in sorted(values, key=lambda item: item[0])]
                scores = [row[metric] for row in ordered]
                differences.append(max(scores) - min(scores))
                pairs.append((scores[0], scores[1]))
        agreement[metric] = {
            "rated_items": len(differences),
            "mean_score_range": statistics.fmean(differences) if differences else None,
            "quadratic_weighted_kappa": _quadratic_weighted_kappa(pairs),
        }
    insufficient = [f"{case_id}/{condition}" for (case_id, condition), values in by_item.items() if len(values) < 2]
    return {"aggregate": aggregate, "agreement": agreement, "items_with_fewer_than_two_raters": insufficient}


def main():
    parser = argparse.ArgumentParser(description="Evaluate graph-constrained LLM analysis")
    parser.add_argument("--predictions", required=True, help="structured LLM case JSON")
    parser.add_argument("--gold", required=True, help="gold facts/TTP/stages JSON")
    parser.add_argument("--ratings", help="optional blinded human rating CSV")
    parser.add_argument(
        "--conditions",
        default="raw_alerts,full_graph,pruned_graph",
        help="comma-separated conditions required for every gold case",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with open(args.predictions, "r", encoding="utf-8") as handle:
        predictions = json.load(handle)
    with open(args.gold, "r", encoding="utf-8") as handle:
        gold = json.load(handle)
    conditions = [value.strip() for value in args.conditions.split(",") if value.strip()]
    result = {"structured": evaluate_structured(predictions, gold, expected_conditions=conditions)}
    if args.ratings:
        result["human_ratings"] = evaluate_human_ratings(args.ratings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
