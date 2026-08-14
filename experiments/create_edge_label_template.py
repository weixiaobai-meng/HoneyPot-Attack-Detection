"""Create a human-review template for attack-graph edge labels."""

import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Create edge-label annotation template")
    parser.add_argument("--graph", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with open(args.graph, "r", encoding="utf-8") as handle:
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
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)
    print(f"created {len(rows)} edge-label rows: {output.resolve()}")


if __name__ == "__main__":
    main()
