"""Keep graph exports consistent with the currently selected edges."""

from collections import Counter, defaultdict
from copy import deepcopy


def selected_edge_view(graph, edges):
    result = deepcopy(graph)
    result["edges"] = deepcopy(edges)
    edge_ids = {edge["edge_id"] for edge in edges}
    node_ids = {edge[key] for edge in edges for key in ("source", "target")}
    event_ids = {
        edge.get("event_id") for edge in edges if edge.get("edge_kind") == "event"
    }
    result["nodes"] = [node for node in result.get("nodes", []) if node["id"] in node_ids]
    result["triples"] = [
        triple for triple in result.get("triples", []) if triple.get("triple_id") in edge_ids
    ]
    result["event_sequence"] = [
        event for event in result.get("event_sequence", []) if event.get("event_id") in event_ids
    ]
    # Filtering event lists cannot prove that a cached path still exists.
    for key in ("attack_paths", "provenance_chains", "attacker_groups"):
        result[key] = []
    adjacency = defaultdict(list)
    for edge in edges:
        adjacency[edge["source"]].append(edge)
    for index, required in enumerate(graph.get("required_paths", [])):
        queue = [required["source"]]
        parent = {required["source"]: None}
        for node in queue:
            if node == required["target"]:
                break
            for edge in adjacency[node]:
                if edge["target"] not in parent:
                    parent[edge["target"]] = edge
                    queue.append(edge["target"])
        if required["target"] not in parent:
            continue
        path_edges, cursor = [], required["target"]
        while parent[cursor] is not None:
            edge = parent[cursor]
            path_edges.append(edge)
            cursor = edge["source"]
        path_edges.reverse()
        result["attack_paths"].append({
            "path_id": f"retained_{index}", "event_count": len(path_edges) + 1,
            "edge_ids": [edge["edge_id"] for edge in path_edges],
            "node_ids": [required["source"]] + [edge["target"] for edge in path_edges],
            "basis": "retained_modeled_reachability", "causality_verified": False,
        })
    for key in ("controlled_scenarios", "controlled_label_eval"):
        result.pop(key, None)
    meta = result.setdefault("graph_meta", {})
    meta.update({
        "node_count": len(result["nodes"]),
        "edge_count": len(edges),
        "event_edge_count": sum(edge.get("edge_kind") == "event" for edge in edges),
        "correlation_edge_count": sum(edge.get("edge_kind") == "correlation" for edge in edges),
        "triple_count": len(result["triples"]),
        "relation_counts": dict(Counter(edge.get("relation_type", "unknown") for edge in edges)),
        "attacker_count": 0,
        "path_count": len(result["attack_paths"]),
        "provenance_chain_count": 0,
        "strong_provenance_chain_count": 0,
        "controlled_scenario_count": 0,
        "cached_path_summaries_invalidated": True,
    })
    return result
