"""Create a human-review template for attack-graph edge labels."""

import argparse
import json
from pathlib import Path

def create_edge_label_template(graph_path, output_path):
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
            "shared_evidence": edge.get("shared_evidence") or [],
        })
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)
    return {"file": str(output), "rows": len(rows), "labels_completed": 0}


def main():
    parser = argparse.ArgumentParser(description="Create edge-label annotation template")
    parser.add_argument("--graph", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = create_edge_label_template(args.graph, args.output)
    print(f"created {result['rows']} edge-label rows: {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
