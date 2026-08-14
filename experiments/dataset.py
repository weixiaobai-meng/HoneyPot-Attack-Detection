"""Scenario-level dataset manifest loading and scientific-validity checks."""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from step3_dqn_pruning.graph_loader import attach_manual_labels, load_graph_from_file, load_manual_labels


VALID_SPLITS = {"train", "validation", "test"}
VALID_LABELS = {0.0, 1.0}


@dataclass(frozen=True)
class ScenarioRecord:
    scenario_id: str
    split: str
    graph_path: Path
    label_path: Path
    source_type: str
    trigger_mode: str
    raw_alerts_path: Optional[Path] = None
    group_id: str = "unknown"
    attack_family: str = "unknown"
    annotator_label_paths: Tuple[Path, ...] = ()
    annotation_review_path: Optional[Path] = None


def _resolve(base: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _structural_fingerprint(graph_data: Dict) -> str:
    rows = []
    for edge in graph_data.get("edges", []):
        relation = str(edge.get("relation_type") or "unknown")
        if relation == "controlled_chain_member":
            relation = "label_only_relation"
        rows.append((
            str(edge.get("source") or ""),
            str(edge.get("target") or ""),
            str(edge.get("action") or ""),
            relation,
            str(edge.get("edge_kind") or ""),
        ))
    payload = json.dumps(sorted(rows), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def cohen_kappa(pairs):
    pairs = [(int(left), int(right)) for left, right in pairs]
    if not pairs:
        return {"items": 0, "observed_agreement": None, "cohen_kappa": None}
    total = len(pairs)
    observed = sum(left == right for left, right in pairs) / total
    left_positive = sum(left == 1 for left, _ in pairs) / total
    right_positive = sum(right == 1 for _, right in pairs) / total
    expected = (
        left_positive * right_positive
        + (1.0 - left_positive) * (1.0 - right_positive)
    )
    if abs(1.0 - expected) < 1e-12:
        kappa = 1.0 if observed == 1.0 else 0.0
    else:
        kappa = (observed - expected) / (1.0 - expected)
    return {
        "items": total,
        "observed_agreement": observed,
        "cohen_kappa": kappa,
    }


class ScenarioDataset:
    def __init__(
        self,
        manifest_path,
        require_complete_labels=True,
        require_double_annotation=False,
        require_raw_alerts=False,
        minimum_split_counts=None,
        minimum_annotation_kappa=0.6,
    ):
        self.manifest_path = Path(manifest_path).resolve()
        self.require_complete_labels = bool(require_complete_labels)
        self.require_double_annotation = bool(require_double_annotation)
        self.require_raw_alerts = bool(require_raw_alerts)
        self.minimum_split_counts = dict(minimum_split_counts or {})
        self.minimum_annotation_kappa = float(minimum_annotation_kappa)
        with open(self.manifest_path, "r", encoding="utf-8-sig") as handle:
            self.payload = json.load(handle)
        self.records = self._parse_records()

    def _parse_records(self) -> List[ScenarioRecord]:
        if int(self.payload.get("version", 0)) != 1:
            raise ValueError("dataset manifest version must be 1")
        scenarios = self.payload.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            raise ValueError("dataset manifest must contain a non-empty scenarios list")
        base = self.manifest_path.parent
        records = []
        for index, item in enumerate(scenarios):
            if not isinstance(item, dict):
                raise ValueError(f"scenarios[{index}] must be an object")
            scenario_id = str(item.get("scenario_id") or "").strip()
            split = str(item.get("split") or "").strip().lower()
            graph = str(item.get("graph") or "").strip()
            labels = str(item.get("labels") or "").strip()
            if not scenario_id or split not in VALID_SPLITS or not graph or not labels:
                raise ValueError(
                    f"scenarios[{index}] requires scenario_id, split, graph and labels; "
                    f"split must be one of {sorted(VALID_SPLITS)}"
                )
            raw_alerts = str(item.get("raw_alerts") or "").strip()
            annotation_review = str(item.get("annotation_review") or "").strip()
            annotator_labels = item.get("annotator_labels") or []
            if isinstance(annotator_labels, str):
                annotator_labels = [annotator_labels]
            records.append(ScenarioRecord(
                scenario_id=scenario_id,
                split=split,
                graph_path=_resolve(base, graph),
                label_path=_resolve(base, labels),
                source_type=str(item.get("source_type") or "unknown"),
                trigger_mode=str(item.get("trigger_mode") or "unknown"),
                raw_alerts_path=_resolve(base, raw_alerts) if raw_alerts else None,
                group_id=str(item.get("group_id") or "unknown").strip(),
                attack_family=str(item.get("attack_family") or "unknown").strip(),
                annotator_label_paths=tuple(
                    _resolve(base, str(path)) for path in annotator_labels if str(path).strip()
                ),
                annotation_review_path=(
                    _resolve(base, annotation_review) if annotation_review else None
                ),
            ))
        return records

    def validate(self, require_all_splits=True):
        errors = []
        warnings = []
        ids = [record.scenario_id for record in self.records]
        duplicates = sorted(key for key, count in Counter(ids).items() if count > 1)
        if duplicates:
            errors.append(f"duplicate scenario_id values: {duplicates}")

        split_counts = Counter(record.split for record in self.records)
        if require_all_splits:
            missing = sorted(VALID_SPLITS - set(split_counts))
            if missing:
                errors.append(f"missing dataset splits: {missing}")
        for split, minimum in sorted(self.minimum_split_counts.items()):
            if split_counts.get(split, 0) < int(minimum):
                errors.append(
                    f"{split} split has {split_counts.get(split, 0)} scenarios; "
                    f"formal benchmark requires at least {int(minimum)}"
                )

        groups = {}
        for record in self.records:
            if record.group_id == "unknown":
                if self.require_raw_alerts:
                    errors.append(f"{record.scenario_id} must declare group_id for leakage-safe splitting")
                continue
            previous = groups.get(record.group_id)
            if previous and previous.split != record.split:
                errors.append(
                    "group leakage across splits: "
                    f"{previous.scenario_id}({previous.split}) and "
                    f"{record.scenario_id}({record.split}) share group_id={record.group_id}"
                )
            else:
                groups[record.group_id] = record

        fingerprints = {}
        raw_alert_fingerprints = {}
        label_counts = Counter()
        split_label_counts = {split: Counter() for split in VALID_SPLITS}
        annotation_pairs = []
        scenario_rows = []
        for record in self.records:
            if not record.graph_path.exists():
                errors.append(f"missing graph for {record.scenario_id}: {record.graph_path}")
                continue
            if not record.label_path.exists():
                errors.append(f"missing labels for {record.scenario_id}: {record.label_path}")
                continue
            if record.raw_alerts_path and not record.raw_alerts_path.exists():
                errors.append(f"missing raw_alerts for {record.scenario_id}: {record.raw_alerts_path}")
            elif record.raw_alerts_path:
                raw_hash = hashlib.sha256(record.raw_alerts_path.read_bytes()).hexdigest()
                if raw_hash in raw_alert_fingerprints:
                    previous = raw_alert_fingerprints[raw_hash]
                    label = "raw-alert leakage across splits" if previous.split != record.split else "duplicate raw-alert file"
                    errors.append(f"{label}: {previous.scenario_id}({previous.split}) and {record.scenario_id}({record.split})")
                else:
                    raw_alert_fingerprints[raw_hash] = record
            elif self.require_raw_alerts:
                errors.append(f"{record.scenario_id} must record raw_alerts for formal benchmarking")

            with open(record.graph_path, "r", encoding="utf-8-sig") as handle:
                graph_data = json.load(handle)
            graph_edges = graph_data.get("edges", [])
            edge_ids = [str(edge.get("edge_id") or "") for edge in graph_edges]
            if any(not edge_id for edge_id in edge_ids):
                errors.append(f"{record.scenario_id} contains edges without edge_id")
            duplicate_edges = sorted(key for key, count in Counter(edge_ids).items() if key and count > 1)
            if duplicate_edges:
                errors.append(f"{record.scenario_id} has duplicate edge_ids: {duplicate_edges[:10]}")

            labels = load_manual_labels(str(record.label_path))
            invalid = sorted({value for value in labels.values() if value not in VALID_LABELS})
            if invalid:
                errors.append(f"{record.scenario_id} has invalid labels {invalid}; expected 0 or 1")
            missing_labels = sorted(set(edge_ids) - set(labels))
            extra_labels = sorted(set(labels) - set(edge_ids))
            if self.require_complete_labels and missing_labels:
                errors.append(
                    f"{record.scenario_id} label coverage is incomplete: "
                    f"{len(missing_labels)} of {len(edge_ids)} edges missing"
                )
            if extra_labels:
                warnings.append(f"{record.scenario_id} has {len(extra_labels)} labels not present in graph")

            if self.require_double_annotation:
                if len(record.annotator_label_paths) < 2:
                    errors.append(
                        f"{record.scenario_id} requires at least two independent annotator label files"
                    )
                elif len(set(record.annotator_label_paths)) != len(record.annotator_label_paths):
                    errors.append(f"{record.scenario_id} reuses the same annotator label file")
                else:
                    reviewer_labels = []
                    for label_path in record.annotator_label_paths[:2]:
                        if not label_path.exists():
                            errors.append(
                                f"missing annotator labels for {record.scenario_id}: {label_path}"
                            )
                            reviewer_labels = []
                            break
                        current = load_manual_labels(str(label_path))
                        invalid_reviewer = sorted({
                            value for value in current.values() if value not in VALID_LABELS
                        })
                        missing_reviewer = sorted(set(edge_ids) - set(current))
                        if invalid_reviewer:
                            errors.append(
                                f"{record.scenario_id} annotator file {label_path.name} "
                                f"has invalid labels {invalid_reviewer}"
                            )
                        if missing_reviewer:
                            errors.append(
                                f"{record.scenario_id} annotator file {label_path.name} "
                                f"is missing {len(missing_reviewer)} edges"
                            )
                        reviewer_labels.append(current)
                    if len(reviewer_labels) == 2:
                        disagreements = []
                        for edge_id in edge_ids:
                            if edge_id not in reviewer_labels[0] or edge_id not in reviewer_labels[1]:
                                continue
                            left = int(reviewer_labels[0][edge_id])
                            right = int(reviewer_labels[1][edge_id])
                            annotation_pairs.append((left, right))
                            if left == right and edge_id in labels and int(labels[edge_id]) != left:
                                errors.append(
                                    f"{record.scenario_id} final label for {edge_id} "
                                    "contradicts annotator consensus"
                                )
                            if left != right:
                                disagreements.append(edge_id)
                        if disagreements:
                            if not record.annotation_review_path:
                                errors.append(
                                    f"{record.scenario_id} has {len(disagreements)} annotation "
                                    "disagreements but no annotation_review file"
                                )
                            elif not record.annotation_review_path.exists():
                                errors.append(
                                    f"missing annotation review for {record.scenario_id}: "
                                    f"{record.annotation_review_path}"
                                )
                            else:
                                with open(record.annotation_review_path, "r", encoding="utf-8-sig") as handle:
                                    review_payload = json.load(handle)
                                review_rows = (
                                    review_payload.get("adjudication_template", [])
                                    if isinstance(review_payload, dict)
                                    else review_payload
                                )
                                reviews = {
                                    str(row.get("edge_id")): row
                                    for row in review_rows
                                    if isinstance(row, dict) and row.get("edge_id")
                                }
                                for edge_id in disagreements:
                                    row = reviews.get(edge_id, {})
                                    adjudicated = row.get("adjudicated_label")
                                    note = str(row.get("adjudication_note") or "").strip()
                                    if adjudicated not in (0, 1, 0.0, 1.0) or not note:
                                        errors.append(
                                            f"{record.scenario_id} disagreement {edge_id} requires "
                                            "adjudicated_label and a non-empty adjudication_note"
                                        )
                                    elif edge_id in labels and int(labels[edge_id]) != int(adjudicated):
                                        errors.append(
                                            f"{record.scenario_id} final label for {edge_id} "
                                            "does not match annotation review"
                                        )

            current_counts = Counter(int(value) for edge_id, value in labels.items() if edge_id in set(edge_ids))
            label_counts.update(current_counts)
            split_label_counts[record.split].update(current_counts)
            fingerprint = _structural_fingerprint(graph_data)
            if fingerprint in fingerprints:
                previous = fingerprints[fingerprint]
                label = "graph-structure leakage across splits" if previous.split != record.split else "duplicate graph structure"
                errors.append(f"{label}: {previous.scenario_id}({previous.split}) and {record.scenario_id}({record.split})")
            else:
                fingerprints[fingerprint] = record

            annotation_edges = [
                edge for edge in graph_edges
                if edge.get("scenario_id")
                or edge.get("scenario_role")
                or edge.get("relation_type") == "controlled_chain_member"
                or any(str(item).startswith("same_scenario:") for item in (edge.get("shared_evidence") or []))
            ]
            if annotation_edges:
                errors.append(
                    f"{record.scenario_id} graph contains experiment-answer metadata on "
                    f"{len(annotation_edges)} edges; rebuild it from unannotated alerts and keep labels external"
                )
            if record.source_type == "unknown" or record.trigger_mode == "unknown":
                warnings.append(
                    f"{record.scenario_id} should declare source_type and trigger_mode for provenance"
                )
            if self.require_raw_alerts and record.attack_family == "unknown":
                errors.append(f"{record.scenario_id} must declare attack_family")
            if record.raw_alerts_path is None:
                warnings.append(
                    f"{record.scenario_id} should record raw_alerts for auditability and cross-split leakage checks"
                )
            scenario_rows.append({
                "scenario_id": record.scenario_id,
                "split": record.split,
                "edges": len(edge_ids),
                "core_edges": current_counts.get(1, 0),
                "noise_edges": current_counts.get(0, 0),
                "label_coverage": len(set(edge_ids) & set(labels)) / max(len(edge_ids), 1),
            })

        for split in sorted(VALID_SPLITS & set(split_counts)):
            counts = split_label_counts[split]
            if counts.get(0, 0) == 0 or counts.get(1, 0) == 0:
                errors.append(f"{split} split must contain both core(1) and noise(0) labels")

        agreement = cohen_kappa(annotation_pairs)
        if (
            self.require_double_annotation
            and agreement["cohen_kappa"] is not None
            and agreement["cohen_kappa"] < self.minimum_annotation_kappa
        ):
            errors.append(
                f"annotation Cohen kappa {agreement['cohen_kappa']:.4f} is below "
                f"required {self.minimum_annotation_kappa:.4f}"
            )

        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "manifest": str(self.manifest_path),
            "scenario_count": len(self.records),
            "split_counts": dict(split_counts),
            "label_counts": {"core": label_counts.get(1, 0), "noise": label_counts.get(0, 0)},
            "annotation_agreement": agreement,
            "minimum_annotation_kappa": self.minimum_annotation_kappa if self.require_double_annotation else None,
            "scenarios": scenario_rows,
        }

    def assert_valid(self, require_all_splits=True):
        report = self.validate(require_all_splits=require_all_splits)
        if not report["valid"]:
            raise ValueError("invalid scenario dataset:\n- " + "\n- ".join(report["errors"]))
        return report

    def load_split(self, split: str, disabled_feature_groups: Optional[Iterable[str]] = None):
        split = str(split).lower()
        if split not in VALID_SPLITS:
            raise ValueError(f"unknown split {split!r}")
        graphs = []
        for record in self.records:
            if record.split != split:
                continue
            graph = load_graph_from_file(
                str(record.graph_path),
                disabled_feature_groups=disabled_feature_groups,
            )
            graph = attach_manual_labels(graph, str(record.label_path), strict=self.require_complete_labels)
            graph.scenario_id = record.scenario_id
            graph.dataset_split = record.split
            graph.source_type = record.source_type
            graph.trigger_mode = record.trigger_mode
            graphs.append(graph)
        return graphs
