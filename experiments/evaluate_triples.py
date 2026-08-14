"""Evaluate extracted S-A-O triples against a manually corrected gold file."""

import argparse
import json
from collections import Counter
from pathlib import Path


def _entity_key(entity):
    entity = entity or {}
    return str(entity.get("type") or ""), str(entity.get("id") or entity.get("label") or "")


def _triple_key(item):
    return _entity_key(item.get("subject")), str(item.get("predicate") or ""), _entity_key(item.get("object"))


def _set_metrics(predicted, gold):
    predicted = set(predicted)
    gold = set(gold)
    true_positive = len(predicted & gold)
    precision = true_positive / max(len(predicted), 1)
    recall = true_positive / max(len(gold), 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    return {
        "true_positive": true_positive,
        "predicted": len(predicted),
        "gold": len(gold),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def evaluate(predicted_rows, gold_rows):
    exact = _set_metrics(map(_triple_key, predicted_rows), map(_triple_key, gold_rows))
    subjects = _set_metrics(
        (_entity_key(item.get("subject")) for item in predicted_rows),
        (_entity_key(item.get("subject")) for item in gold_rows),
    )
    objects = _set_metrics(
        (_entity_key(item.get("object")) for item in predicted_rows),
        (_entity_key(item.get("object")) for item in gold_rows),
    )
    predicates = _set_metrics(
        (str(item.get("predicate") or "") for item in predicted_rows),
        (str(item.get("predicate") or "") for item in gold_rows),
    )

    predicted_by_id = {str(item.get("triple_id") or ""): item for item in predicted_rows}
    gold_by_id = {str(item.get("triple_id") or ""): item for item in gold_rows}
    aligned_ids = (set(predicted_by_id) & set(gold_by_id)) - {""}
    field_names = ["timestamp", "stage", "tactic", "technique", "relation_type"]
    field_accuracy = {}
    for field in field_names:
        comparable = [
            triple_id for triple_id in aligned_ids
            if gold_by_id[triple_id].get(field) not in (None, "")
        ]
        correct = sum(
            predicted_by_id[triple_id].get(field) == gold_by_id[triple_id].get(field)
            for triple_id in comparable
        )
        field_accuracy[field] = {
            "correct": correct,
            "evaluated": len(comparable),
            "accuracy": correct / max(len(comparable), 1),
        }
    return {
        "exact_triple": exact,
        "subject_entity": subjects,
        "predicate": predicates,
        "object_entity": objects,
        "aligned_triple_ids": len(aligned_ids),
        "field_accuracy": field_accuracy,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate extracted triples")
    parser.add_argument("--predicted", required=True)
    parser.add_argument("--gold", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with open(args.predicted, "r", encoding="utf-8") as handle:
        predicted = json.load(handle)
    with open(args.gold, "r", encoding="utf-8") as handle:
        gold = json.load(handle)
    result = evaluate(predicted, gold)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
