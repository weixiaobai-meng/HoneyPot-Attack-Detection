"""Label-free evidence and reachability checks for sequential pruning."""

from collections import defaultdict, deque
import torch


class EvidencePathGuard:
    def __init__(self, data):
        self.edges = list(data.edges_info)
        self.protected = {
            i for i, edge in enumerate(self.edges)
            if edge.get("evidence_basis") == "observed_event"
            and edge.get("event_id") and edge.get("source_event_ids")
        }
        self.paths = list(getattr(data, "required_paths", []))
        self.outgoing = defaultdict(list)
        for i, edge in enumerate(self.edges):
            self.outgoing[edge["source"]].append((edge["target"], i))
        full_mask = [True] * len(self.edges)
        self.witnesses = []
        for path in self.paths:
            witness = self._find_path(full_mask, path["source"], path["target"])
            if witness is None:
                raise ValueError("required path is unreachable in the input graph")
            self.witnesses.append(witness)

    def _find_path(self, mask, source, target, excluded=-1):
        if isinstance(mask, torch.Tensor):
            mask = mask.tolist()
        queue, parent = deque([source]), {source: None}
        while queue:
            node = queue.popleft()
            if node == target:
                witness = []
                while parent[node] is not None:
                    previous, index = parent[node]
                    witness.append(index)
                    node = previous
                return tuple(reversed(witness))
            for neighbor, index in self.outgoing[node]:
                if index != excluded and bool(mask[index]) and neighbor not in parent:
                    parent[neighbor] = (node, index)
                    queue.append(neighbor)
        return None

    def reachable(self, mask, source, target, excluded=-1):
        return self._find_path(mask, source, target, excluded) is not None

    def rejection_reason(self, mask, edge_index):
        if edge_index in self.protected:
            return "observed_evidence"
        if isinstance(mask, torch.Tensor):
            mask = mask.tolist()
        for index, path in enumerate(self.paths):
            witness = self.witnesses[index]
            if edge_index not in witness and all(mask[item] for item in witness):
                continue
            replacement = self._find_path(mask, path["source"], path["target"], excluded=edge_index)
            if replacement is None:
                return "required_reachability"
            self.witnesses[index] = replacement
        return None

    def filter_actions(self, proposed):
        if len(proposed) != len(self.edges):
            raise ValueError("action count differs from graph edge count")
        mask = [True] * len(self.edges)
        actions = proposed.clone().cpu()
        rejected = []
        for index, action in enumerate(actions):
            if int(action) != 1:
                continue
            reason = self.rejection_reason(mask, index)
            if reason:
                actions[index] = 0
                rejected.append({"edge_id": self.edges[index]["edge_id"], "reason": reason})
            else:
                mask[index] = False
        return actions, {"constraint_overrides": rejected, **self.metrics(actions)}

    def metrics(self, actions):
        mask = (actions.cpu() == 0).tolist()
        kept = sum(bool(mask[i]) for i in self.protected)
        reachable = sum(self.reachable(mask, path["source"], path["target"]) for path in self.paths)
        return {
            "protected_edge_count": len(self.protected),
            "protected_edges_kept": kept,
            "required_path_count": len(self.paths),
            "required_paths_kept": reachable,
            "protected_evidence_retention": kept / len(self.protected) if self.protected else None,
            "modeled_path_retention": reachable / len(self.paths) if self.paths else None,
            "constraints_satisfied": kept == len(self.protected) and reachable == len(self.paths),
        }
