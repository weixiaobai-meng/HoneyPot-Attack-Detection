"""Observable evidence contract, independent of experiment labels."""

from collections import defaultdict, deque

EVIDENCE_VERSION = 1
STRONG_PREFIXES = ("same_session:", "same_fingerprint:", "same_object_instance:")


def annotate_evidence(edges):
    for edge in edges:
        shared = edge.get("shared_evidence") or []
        strong = [value for value in shared if str(value).startswith(STRONG_PREFIXES)]
        observed = edge.get("edge_kind") == "event" and bool(edge.get("event_id"))
        edge["evidence_basis"] = (
            "observed_event" if observed else "supported_association" if strong else "inferred_association"
        )
        edge["evidence_reasons"] = ["direct_event_record"] if observed else strong
        edge["evidence_contract_version"] = EVIDENCE_VERSION
        # Even a shared session supports association, not attribution to a person.
        edge["causality_verified"] = False


def derive_required_paths(edges):
    """Preserve modeled reachability between each path group's boundaries.

    These constraints are computed without labels. They are not gold attack paths.
    This is a structural graph constraint, not proof of real attack causality.
    Cyclic groups have no natural boundary and are reported rather than invented.
    """
    groups = defaultdict(list)
    for edge in edges:
        if edge.get("edge_kind") == "correlation" and edge.get("path_id"):
            groups[edge["path_id"]].append(edge)
    paths, skipped = [], []
    for group_id, rows in sorted(groups.items()):
        adjacency = defaultdict(list)
        sources, targets = set(), set()
        for row in rows:
            adjacency[row["source"]].append(row["target"])
            sources.add(row["source"])
            targets.add(row["target"])
        starts, ends = sorted(sources - targets), targets - sources
        if not starts or not ends:
            skipped.append(group_id)
            continue
        for start in starts:
            queue, seen = deque([start]), {start}
            while queue:
                node = queue.popleft()
                for target in adjacency[node]:
                    if target not in seen:
                        seen.add(target)
                        queue.append(target)
            for end in sorted(ends & seen):
                paths.append({"source": start, "target": end, "path_id": group_id,
                              "basis": "original_modeled_reachability"})
    return paths, skipped


def restore_required_evidence(graph, selected_edges):
    """Repair a rule fallback using observable evidence, without ML dependencies."""
    edges = graph.get("edges", [])
    kept = {edge["edge_id"] for edge in selected_edges}
    proposed = set(kept)
    adjacency = defaultdict(list)
    for edge in edges:
        adjacency[edge["source"]].append(edge)
        if (edge.get("evidence_basis") == "observed_event"
                and edge.get("event_id") and edge.get("source_event_ids")):
            kept.add(edge["edge_id"])

    def find_path(source, target, allowed=None):
        queue, parent = deque([source]), {source: None}
        while queue:
            node = queue.popleft()
            if node == target:
                result = []
                while parent[node] is not None:
                    edge = parent[node]
                    result.append(edge["edge_id"])
                    node = edge["source"]
                return result
            for edge in adjacency[node]:
                if allowed is not None and edge["edge_id"] not in allowed:
                    continue
                if edge["target"] not in parent:
                    parent[edge["target"]] = edge
                    queue.append(edge["target"])
        return None

    for path in graph.get("required_paths", []):
        if find_path(path["source"], path["target"], kept) is not None:
            continue
        restored = find_path(path["source"], path["target"])
        if restored is None:
            raise ValueError("required path is unreachable in the input graph")
        kept.update(restored)
    return [edge for edge in edges if edge["edge_id"] in kept], {
        "constraints_satisfied": True,
        "restored_edge_ids": sorted(kept - proposed),
        "required_path_count": len(graph.get("required_paths", [])),
    }
