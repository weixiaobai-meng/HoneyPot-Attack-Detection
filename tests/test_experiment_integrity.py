import copy
import json
import tempfile
import unittest
from pathlib import Path

import torch

from experiments.dataset import ScenarioDataset, cohen_kappa
from experiments.evaluate_llm_reports import evaluate_structured
from experiments.evaluate_triples import evaluate as evaluate_triples
from experiments.run_benchmark import _aggregate, _comparisons
from step3_dqn_pruning.environment import AttackGraphEnv
from step3_dqn_pruning.graph_loader import (
    attack_origin_score,
    build_edge_feature_vector,
    causal_graph_to_pyg,
    EDGE_FEATURE_NAMES,
    is_protected_origin_edge,
    load_graphs_for_training,
)
from step3_dqn_pruning.scaling import partition_edge_indices


def toy_graph(suffix="a"):
    return {
        "nodes": [
            {"id": f"network:{suffix}", "type": "network", "label": "source"},
            {"id": f"file:{suffix}", "type": "file", "label": "bait"},
            {"id": f"url:{suffix}", "type": "url", "label": "page"},
        ],
        "edges": [
            {
                "edge_id": f"core_{suffix}",
                "source": f"network:{suffix}",
                "target": f"file:{suffix}",
                "action": "file_access",
                "relation_type": "account_to_file",
                "edge_kind": "correlation",
                "shared_evidence": ["same_session:s1"],
                "confidence": 0.95,
                "scenario_id": f"scenario_{suffix}",
                "scenario_role": "controlled_chain",
            },
            {
                "edge_id": f"noise_{suffix}",
                "source": f"network:{suffix}",
                "target": f"url:{suffix}",
                "action": "write",
                "relation_type": "subject_action_object",
                "edge_kind": "event",
                "confidence": 0.2,
                "scenario_id": f"scenario_{suffix}",
                "scenario_role": "controlled_noise",
            },
        ],
    }


class FeatureLeakageTests(unittest.TestCase):
    def test_scenario_answers_do_not_change_features_or_origin_score(self):
        edge = toy_graph()["edges"][0]
        changed = copy.deepcopy(edge)
        changed["scenario_id"] = "different"
        changed["scenario_role"] = "controlled_noise"
        changed["shared_evidence"].append("same_scenario:different")
        self.assertEqual(build_edge_feature_vector(edge), build_edge_feature_vector(changed))
        self.assertEqual(attack_origin_score(edge), attack_origin_score(changed))
        self.assertEqual(is_protected_origin_edge(edge), is_protected_origin_edge(changed))

    def test_controlled_chain_relation_is_masked(self):
        edge = toy_graph()["edges"][0]
        changed = copy.deepcopy(edge)
        changed["relation_type"] = "controlled_chain_member"
        baseline = copy.deepcopy(changed)
        baseline["relation_type"] = "unknown"
        self.assertEqual(build_edge_feature_vector(changed), build_edge_feature_vector(baseline))

    def test_identity_ablation_removes_raw_and_derived_identity_paths(self):
        edge = toy_graph()["edges"][0]
        normal = build_edge_feature_vector(edge)
        ablated = build_edge_feature_vector(edge, disabled_feature_groups=["identity"])
        relation_index = EDGE_FEATURE_NAMES.index("relation:account_to_file")
        identity_index = EDGE_FEATURE_NAMES.index("shared_same_session")
        self.assertEqual(normal[relation_index], ablated[relation_index])
        self.assertEqual(normal[identity_index], 1.0)
        self.assertEqual(ablated[identity_index], 0.0)
        self.assertLess(
            attack_origin_score(edge, disabled_feature_groups=["identity"]),
            attack_origin_score(edge),
        )

    def test_cross_honeypot_ablation_masks_relation_one_hot(self):
        edge = toy_graph()["edges"][0]
        ablated = build_edge_feature_vector(edge, disabled_feature_groups=["cross_honeypot"])
        relation_index = EDGE_FEATURE_NAMES.index("relation:account_to_file")
        unknown_index = EDGE_FEATURE_NAMES.index("relation:unknown")
        self.assertEqual(ablated[relation_index], 0.0)
        self.assertEqual(ablated[unknown_index], 1.0)

    def test_weak_label_training_requires_explicit_smoke_flag(self):
        with self.assertRaises(RuntimeError):
            load_graphs_for_training("unused.json")


class EnvironmentAndScalingTests(unittest.TestCase):
    def test_environment_state_changes_after_pruning(self):
        data = causal_graph_to_pyg(toy_graph())
        data.y = torch.tensor([1, 0], dtype=torch.long)
        env = AttackGraphEnv(data, edge_order=[1, 0])
        state = env.reset()
        self.assertEqual(state["current_edge_idx"], 1)
        next_state, _, done, _ = env.step(1)
        self.assertFalse(done)
        self.assertFalse(bool(next_state["edge_mask"][1]))
        self.assertEqual(next_state["current_edge_idx"], 0)

    def test_origin_score_ablation_removes_origin_reward(self):
        data = causal_graph_to_pyg(toy_graph(), disabled_feature_groups=["origin_score"])
        data.y = torch.tensor([1, 0], dtype=torch.long)
        env = AttackGraphEnv(data, edge_order=[0, 1], use_terminal_reward=False)
        _, reward, _, info = env.step(0)
        self.assertEqual(reward, env.REWARD_KEEP_CORE)
        self.assertEqual(info["attack_origin_score"], 0.0)

    def test_partitioning_is_bounded_and_complete(self):
        graph = toy_graph()
        graph["edges"] = graph["edges"] * 3
        for index, edge in enumerate(graph["edges"]):
            edge["edge_id"] = f"edge_{index}"
        data = causal_graph_to_pyg(graph)
        parts = partition_edge_indices(data, max_edges=2)
        self.assertTrue(all(len(part) <= 2 for part in parts))
        self.assertEqual(sorted(index for part in parts for index in part), list(range(6)))


class DatasetTests(unittest.TestCase):
    def _write_scenario(self, root, suffix, split, graph=None):
        graph = graph or toy_graph(suffix)
        graph = copy.deepcopy(graph)
        for edge in graph["edges"]:
            edge.pop("scenario_id", None)
            edge.pop("scenario_role", None)
        graph_path = root / f"graph_{suffix}.json"
        labels_path = root / f"labels_{suffix}.json"
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        labels_path.write_text(json.dumps({f"core_{suffix}": 1, f"noise_{suffix}": 0}), encoding="utf-8")
        return {
            "scenario_id": f"scenario_{suffix}",
            "split": split,
            "graph": graph_path.name,
            "labels": labels_path.name,
            "source_type": "real_deployment",
            "trigger_mode": "controlled_external_trigger",
        }

    def test_valid_independent_scenario_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scenarios = [
                self._write_scenario(root, "train", "train"),
                self._write_scenario(root, "validation", "validation"),
                self._write_scenario(root, "test", "test"),
            ]
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
            report = ScenarioDataset(manifest).validate()
            self.assertTrue(report["valid"], report["errors"])

    def test_duplicate_structure_across_splits_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = toy_graph("same")
            scenarios = []
            for suffix, split in [("train", "train"), ("validation", "validation"), ("test", "test")]:
                graph = copy.deepcopy(base)
                graph["edges"][0]["edge_id"] = f"core_{suffix}"
                graph["edges"][1]["edge_id"] = f"noise_{suffix}"
                scenarios.append(self._write_scenario(root, suffix, split, graph=graph))
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
            report = ScenarioDataset(manifest).validate()
            self.assertFalse(report["valid"])
            self.assertTrue(any("structure leakage" in error for error in report["errors"]))

    def test_graph_with_scenario_answers_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scenarios = [
                self._write_scenario(root, "train", "train", graph=toy_graph("train")),
                self._write_scenario(root, "validation", "validation"),
                self._write_scenario(root, "test", "test"),
            ]
            graph_path = root / "graph_train.json"
            graph = toy_graph("train")
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
            report = ScenarioDataset(manifest).validate()
            self.assertFalse(report["valid"])
            self.assertTrue(any("experiment-answer metadata" in error for error in report["errors"]))

    def test_formal_dataset_requires_provenance_and_two_annotators(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scenarios = [
                self._write_scenario(root, "train", "train"),
                self._write_scenario(root, "validation", "validation"),
                self._write_scenario(root, "test", "test"),
            ]
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
            report = ScenarioDataset(
                manifest,
                require_double_annotation=True,
                require_raw_alerts=True,
            ).validate()
            self.assertFalse(report["valid"])
            self.assertTrue(any("annotator" in error for error in report["errors"]))
            self.assertTrue(any("raw_alerts" in error for error in report["errors"]))

    def test_double_annotated_dataset_passes_provenance_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scenarios = []
            for suffix, split in (("train", "train"), ("validation", "validation"), ("test", "test")):
                item = self._write_scenario(root, suffix, split)
                final_labels = root / item["labels"]
                rater_a = root / f"labels_{suffix}_rater_a.json"
                rater_b = root / f"labels_{suffix}_rater_b.json"
                rater_a.write_bytes(final_labels.read_bytes())
                rater_b.write_bytes(final_labels.read_bytes())
                raw = root / f"raw_{suffix}.json"
                raw.write_text(json.dumps({"scenario": suffix}), encoding="utf-8")
                item.update({
                    "annotator_labels": [rater_a.name, rater_b.name],
                    "raw_alerts": raw.name,
                    "group_id": f"group_{suffix}",
                    "attack_family": "test_family",
                })
                scenarios.append(item)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
            report = ScenarioDataset(
                manifest,
                require_double_annotation=True,
                require_raw_alerts=True,
            ).validate()
            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(report["annotation_agreement"]["cohen_kappa"], 1.0)

    def test_annotation_disagreement_requires_review_record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = self._write_scenario(root, "one", "train")
            rater_a = root / "rater_a.json"
            rater_b = root / "rater_b.json"
            rater_a.write_text(json.dumps({"core_one": 1, "noise_one": 0}), encoding="utf-8")
            rater_b.write_text(json.dumps({"core_one": 0, "noise_one": 0}), encoding="utf-8")
            raw = root / "raw.json"
            raw.write_text(json.dumps({"scenario": "one"}), encoding="utf-8")
            item.update({
                "annotator_labels": [rater_a.name, rater_b.name],
                "raw_alerts": raw.name,
                "group_id": "group_one",
                "attack_family": "test_family",
            })
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "scenarios": [item]}), encoding="utf-8")
            report = ScenarioDataset(
                manifest,
                require_double_annotation=True,
                require_raw_alerts=True,
                minimum_annotation_kappa=-1.0,
            ).validate(require_all_splits=False)
            self.assertFalse(report["valid"])
            self.assertTrue(any("annotation_review" in error for error in report["errors"]))


class EvaluationTests(unittest.TestCase):
    def test_triple_exact_metrics(self):
        triple = {
            "triple_id": "t1",
            "subject": {"type": "network", "id": "1.2.3.4"},
            "predicate": "file_access",
            "object": {"type": "file", "id": "/bait"},
        }
        result = evaluate_triples([triple], [copy.deepcopy(triple)])
        self.assertEqual(result["exact_triple"]["f1"], 1.0)

    def test_llm_unsupported_fact_is_counted(self):
        gold = {"cases": [{"case_id": "c1", "facts": ["fact a"], "ttps": ["T1110"]}]}
        prediction = {"cases": [{
            "case_id": "c1",
            "condition": "pruned_graph",
            "facts": ["fact a", "invented"],
            "ttps": ["T1110"],
        }]}
        result = evaluate_structured(prediction, gold)
        self.assertEqual(result["per_case"][0]["hallucination_count"], 1)
        self.assertEqual(result["per_case"][0]["fact_precision"], 0.5)

    def test_llm_missing_condition_is_rejected(self):
        gold = {"cases": [{"case_id": "c1", "facts": ["fact a"]}]}
        prediction = {"cases": [{"case_id": "c1", "condition": "pruned_graph", "facts": ["fact a"]}]}
        result = evaluate_structured(
            prediction,
            gold,
            expected_conditions=["full_graph", "pruned_graph"],
        )
        self.assertTrue(any("full_graph" in error for error in result["errors"]))

    def test_annotation_kappa_and_scenario_level_statistics(self):
        self.assertEqual(cohen_kappa([(0, 0), (1, 1)])["cohen_kappa"], 1.0)
        rows = []
        for seed in (1, 2):
            for scenario, reference, candidate in (("a", 0.8, 0.5), ("b", 0.6, 0.4)):
                for method, value in (("dqn_evidence_constraint", reference), ("evidence_rule", candidate)):
                    row = {"method": method, "seed": seed, "scenario_id": scenario}
                    row.update({metric: value for metric in (
                        "accuracy", "precision", "recall", "f1", "noise_precision",
                        "noise_recall", "noise_f1", "core_recall",
                        "noise_filter_rate", "compression_ratio", "causal_score",
                    )})
                    rows.append(row)
        aggregate = _aggregate(rows)
        self.assertEqual(aggregate["dqn_evidence_constraint"]["scenario_count"], 2)
        self.assertAlmostEqual(aggregate["dqn_evidence_constraint"]["f1_mean"], 0.7)
        comparisons = _comparisons(rows)
        self.assertTrue(any(row["candidate"] == "evidence_rule" for row in comparisons))


if __name__ == "__main__":
    unittest.main()
