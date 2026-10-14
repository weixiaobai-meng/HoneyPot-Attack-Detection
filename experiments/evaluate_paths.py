"""Evaluate manually adjudicated path edges; gold is never a model input."""

import argparse
import json
from pathlib import Path


def evaluate(original, pruned, gold):
    original_ids = {row["edge_id"] for row in original["edges"]}
    kept_ids = {row["edge_id"] for row in pruned["edges"]}
    if not kept_ids <= original_ids:
        raise ValueError("pruned graph introduces edges absent from original")
    rows = []
    for path in gold.get("paths", []):
        ids = path.get("edge_ids", [])
        if not ids or len(ids) != len(set(ids)) or not set(ids) <= original_ids:
            raise ValueError("gold path has missing, duplicate or unknown edge IDs")
        edge_map = {edge["edge_id"]: edge for edge in original["edges"]}
        if any(edge_map[left]["target"] != edge_map[right]["source"]
               for left, right in zip(ids, ids[1:])):
            raise ValueError("gold edge sequence is not a contiguous directed path")
        retained = sum(edge_id in kept_ids for edge_id in ids)
        rows.append({"path_id": path["path_id"], "edge_count": len(ids),
                     "retained_edges": retained, "complete": retained == len(ids)})
    if not rows:
        raise ValueError("path gold must contain independently reviewed paths")
    return {"gold_path_count": len(rows),
            "complete_path_recall": sum(row["complete"] for row in rows) / len(rows),
            "path_edge_recall": sum(row["retained_edges"] for row in rows) / sum(row["edge_count"] for row in rows),
            "per_path": rows,
            "definition": "exact reviewed path preservation, not attacker attribution"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("original", "pruned", "gold", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    load = lambda value: json.loads(Path(value).read_text(encoding="utf-8-sig"))
    result = evaluate(load(args.original), load(args.pruned), load(args.gold))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
