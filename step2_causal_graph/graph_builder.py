"""
Step 2: build attack provenance graph and standard triples from canonical events.
"""

import json
import os
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from step1_data_collection.campaign import extract_campaign_id


@dataclass
class CausalEdge:
    """One graph edge derived from one canonical event or one event correlation."""

    edge_id: str
    event_id: str
    subject_type: str
    subject_id: str
    subject_label: str
    action: str
    object_type: str
    object_id: str
    object_label: str
    timestamp: datetime
    stage: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"
    raw_data: Dict = field(default_factory=dict)
    edge_kind: str = "event"
    path_id: Optional[str] = None
    relation_type: Optional[str] = None

    def to_triple(self) -> Dict[str, object]:
        return {
            "triple_id": self.edge_id,
            "event_id": self.event_id,
            "subject": {
                "id": self.subject_id,
                "type": self.subject_type,
                "label": self.subject_label,
            },
            "predicate": self.action,
            "object": {
                "id": self.object_id,
                "type": self.object_type,
                "label": self.object_label,
            },
            "timestamp": self.timestamp.isoformat(),
            "stage": self.stage,
            "tactic": self.tactic,
            "technique": self.technique,
            "confidence": self.confidence,
            "severity": self.severity,
            "edge_kind": self.edge_kind,
            "path_id": self.path_id,
            "relation_type": self.relation_type,
        }


class CausalGraphBuilder:
    """
    Convert unified alerts into a thesis-ready attack provenance graph.

    Output compatibility is preserved for:
    - nodes
    - edges
    - triples
    - event_sequence

    New thesis-oriented additions:
    - correlation edges between events
    - attack path grouping
    - graph statistics for event edges vs correlation edges
    """

    PATH_TIME_WINDOW = timedelta(minutes=10)
    CONTROLLED_CHAIN_WINDOW = timedelta(minutes=45)
    PROVENANCE_CHAIN_WINDOW = timedelta(minutes=60)
    STAGE_RANK = {
        "reconnaissance": 1,
        "initial_access": 2,
        "execution": 3,
        "persistence": 4,
        "privilege_escalation": 5,
        "defense_evasion": 6,
        "collection": 7,
        "command_and_control": 8,
        "exfiltration": 9,
    }
    CROSS_HONEYPOT_RELATIONS = {
        ("parasitic", "account"): "web_to_account",
        ("account", "file"): "account_to_file",
        ("parasitic", "file"): "web_to_file",
        ("account", "parasitic"): "account_to_web_followup",
        ("file", "account"): "file_to_account_followup",
        ("file", "parasitic"): "file_to_web_followup",
    }

    def __init__(self, include_experiment_annotations: bool = False):
        self.include_experiment_annotations = bool(include_experiment_annotations)
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[CausalEdge] = []
        self.event_index: Dict[str, Dict] = {}
        self.path_groups: Dict[str, Dict] = {}
        self.attacker_groups: Dict[str, Dict] = {}

    def build_from_alerts(self, alerts: list) -> Dict:
        self.nodes = {}
        self.edges = []
        self.event_index = {}
        self.path_groups = {}
        self.attacker_groups = {}

        normalized_events = []
        for alert in alerts:
            event = self._normalize_event(alert)
            self.event_index[event["event_id"]] = event
            normalized_events.append(event)

        normalized_events.sort(key=lambda item: self._parse_timestamp(item.get("timestamp")))
        self._assign_attackers(normalized_events)
        self._assign_attack_paths(normalized_events)

        event_edges: List[CausalEdge] = []
        for event in normalized_events:
            edge = self._event_to_edge(event)
            if edge is None:
                continue
            event_edges.append(edge)
            self._add_node(edge.subject_id, edge.subject_type, edge.subject_label, event, role="source")
            self._add_node(edge.object_id, edge.object_type, edge.object_label, event, role="object")

        correlation_edges = self._build_correlation_edges(normalized_events)
        self.edges = sorted(event_edges + correlation_edges, key=lambda item: (item.timestamp, item.edge_kind != "event"))
        return self.to_dict()

    def _normalize_event(self, alert: object) -> Dict:
        if hasattr(alert, "to_canonical_event"):
            data = alert.to_canonical_event()
        elif hasattr(alert, "to_dict"):
            data = alert.to_dict()
        else:
            data = dict(alert)

        if "canonical_event" in data and isinstance(data["canonical_event"], dict):
            data = data["canonical_event"]

        source = data.get("source") or {}
        obj = data.get("object") or {}
        details = data.get("details") or data.get("raw_details") or {}
        evidence = data.get("evidence") or details
        session_id = data.get("session_id") or details.get("session_token")
        experiment_meta = details.get("experiment") if isinstance(details.get("experiment"), dict) else {}
        campaign_id = (
            data.get("campaign_id")
            or details.get("campaign_id")
            or evidence.get("campaign_id")
            or experiment_meta.get("campaign_id")
            or extract_campaign_id(data, details, evidence, source, obj)
        )
        scenario_id = data.get("scenario_id") or details.get("scenario_id") or experiment_meta.get("scenario_id")
        scenario_role = (
            data.get("scenario_role")
            or details.get("scenario_role")
            or experiment_meta.get("scenario_role")
            or experiment_meta.get("role")
        )
        evidence_refs = data.get("evidence_refs") or details.get("evidence_refs") or experiment_meta.get("evidence_refs") or []
        fingerprint = source.get("label") if source.get("type") == "browser" else None
        if not fingerprint:
            fingerprint = data.get("attacker_info") or details.get("fingerprint")

        normalized = {
            "event_id": data.get("event_id") or data.get("alert_id") or str(uuid.uuid4()),
            "event_type": data.get("event_type") or data.get("alert_type"),
            "timestamp": self._to_iso(data.get("timestamp")),
            "action": data.get("action") or "unknown",
            "source": {
                "type": source.get("type") or data.get("source_type") or self._fallback_source_type(data),
                "id": source.get("id") or data.get("source_id") or self._fallback_source_id(data),
                "label": source.get("label") or data.get("source_label") or self._fallback_source_label(data),
                "ip": source.get("ip") or data.get("attacker_ip"),
                "info": source.get("info") or data.get("attacker_info"),
            },
            "object": {
                "type": obj.get("type") or data.get("object_type") or self._fallback_object_type(data),
                "id": obj.get("id") or data.get("object_id") or self._fallback_object_id(data),
                "label": obj.get("label") or data.get("object_label") or self._fallback_object_label(data),
                "host": obj.get("host") or data.get("target_host"),
                "path": obj.get("path") or data.get("target_path"),
            },
            "session_id": session_id,
            "fingerprint": fingerprint,
            "process": data.get("process") or data.get("process_info"),
            "stage": data.get("stage"),
            "tactic": data.get("tactic"),
            "technique": data.get("technique"),
            "severity": data.get("severity", "medium"),
            "confidence": float(data.get("confidence", 0.8)),
            "source_intel": data.get("source_intel") or {},
            "actor_intel": data.get("actor_intel") or {},
            "evidence": evidence,
            "raw_details": details,
            "campaign_id": campaign_id,
            "scenario_id": scenario_id,
            "scenario_role": scenario_role,
            "evidence_refs": evidence_refs,
        }
        return normalized

    def _build_attacker_anchor_keys(self, event: Dict) -> List[str]:
        anchors = []
        source = event.get("source", {})
        source_ip = source.get("ip")
        fingerprint = event.get("fingerprint")
        session_id = event.get("session_id")
        actor_group_id = (event.get("actor_intel") or {}).get("group_id")
        details = event.get("raw_details") or {}
        username = details.get("username")
        campaign_id = event.get("campaign_id")
        scenario_id = event.get("scenario_id")
        scenario_role = event.get("scenario_role")
        experiment_meta = details.get("experiment") if isinstance(details.get("experiment"), dict) else {}
        chain_actor_id = details.get("chain_actor_id") or experiment_meta.get("chain_actor_id")

        if actor_group_id:
            anchors.append(f"actor-group:{actor_group_id}")
        if campaign_id:
            anchors.append(f"campaign:{campaign_id}")
        if self.include_experiment_annotations and scenario_id and scenario_role == "controlled_chain":
            anchors.append(f"controlled-scenario:{scenario_id}")
        if self.include_experiment_annotations and chain_actor_id:
            anchors.append(f"chain-actor:{chain_actor_id}")
        if fingerprint:
            anchors.append(f"fp:{fingerprint}")
        if session_id:
            anchors.append(f"session:{session_id}")
        if source_ip:
            anchors.append(f"ip:{source_ip}")
        if username:
            anchors.append(f"user:{username}")
        return anchors

    def _assign_attackers(self, events: List[Dict]) -> None:
        anchor_to_attacker: Dict[str, str] = {}
        attacker_index = 1

        for event in events:
            anchor_keys = self._build_attacker_anchor_keys(event)
            attacker_id = None
            for key in anchor_keys:
                if key in anchor_to_attacker:
                    attacker_id = anchor_to_attacker[key]
                    break

            if attacker_id is None:
                attacker_id = f"attacker_{attacker_index:03d}"
                attacker_index += 1

            event["attacker_id"] = attacker_id
            self.attacker_groups.setdefault(
                attacker_id,
                {
                    "attacker_id": attacker_id,
                    "event_ids": [],
                    "path_ids": set(),
                    "event_types": set(),
                    "anchors": set(),
                    "start_time": event["timestamp"],
                    "end_time": event["timestamp"],
                },
            )

            group = self.attacker_groups[attacker_id]
            group["event_ids"].append(event["event_id"])
            group["event_types"].add(str(event.get("event_type") or "unknown"))
            group["start_time"] = min(group["start_time"], event["timestamp"])
            group["end_time"] = max(group["end_time"], event["timestamp"])
            for key in anchor_keys:
                group["anchors"].add(key)
                anchor_to_attacker[key] = attacker_id

        for attacker_id, group in self.attacker_groups.items():
            group["event_types"] = sorted(group["event_types"])
            group["anchors"] = sorted(group["anchors"])
            group["event_count"] = len(group["event_ids"])

    def _assign_attack_paths(self, events: List[Dict]) -> None:
        current_index = 1
        previous_by_attacker: Dict[str, Dict] = {}

        for event in events:
            attacker_key = event.get("attacker_id") or "unknown_attacker"
            previous_event = previous_by_attacker.get(attacker_key)
            if previous_event is None:
                path_id = f"path_{current_index:03d}"
            elif self._is_same_attack_path(previous_event, event):
                path_id = previous_event["path_id"]
            else:
                current_index += 1
                path_id = f"path_{current_index:03d}"

            event["path_id"] = path_id
            self.path_groups.setdefault(
                path_id,
                {
                    "path_id": path_id,
                    "attacker_id": event.get("attacker_id"),
                    "event_ids": [],
                    "event_types": set(),
                    "start_time": event["timestamp"],
                    "end_time": event["timestamp"],
                    "anchors": set(),
                },
            )
            group = self.path_groups[path_id]
            group["event_ids"].append(event["event_id"])
            group["event_types"].add(str(event.get("event_type") or "unknown"))
            group["start_time"] = min(group["start_time"], event["timestamp"])
            group["end_time"] = max(group["end_time"], event["timestamp"])
            group["attacker_id"] = group.get("attacker_id") or event.get("attacker_id")

            source_ip = event.get("source", {}).get("ip")
            fingerprint = event.get("fingerprint")
            session_id = event.get("session_id")
            if source_ip:
                group["anchors"].add(f"ip:{source_ip}")
            if fingerprint:
                group["anchors"].add(f"fp:{fingerprint}")
            if session_id:
                group["anchors"].add(f"session:{session_id}")
            if event.get("campaign_id"):
                group["anchors"].add(f"campaign:{event['campaign_id']}")
            if self.include_experiment_annotations and event.get("scenario_id") and event.get("scenario_role"):
                group["anchors"].add(f"{event['scenario_role']}:{event['scenario_id']}")

            previous_by_attacker[attacker_key] = event

        for path_id, group in self.path_groups.items():
            group["event_types"] = sorted(group["event_types"])
            group["anchors"] = sorted(group["anchors"])
            group["event_count"] = len(group["event_ids"])
            attacker_id = group.get("attacker_id")
            if attacker_id and attacker_id in self.attacker_groups:
                self.attacker_groups[attacker_id]["path_ids"].add(path_id)

    def _is_same_attack_path(self, prev_event: Dict, curr_event: Dict) -> bool:
        prev_ts = self._parse_timestamp(prev_event.get("timestamp"))
        curr_ts = self._parse_timestamp(curr_event.get("timestamp"))
        if self._same_controlled_scenario(prev_event, curr_event):
            return curr_ts - prev_ts <= self.CONTROLLED_CHAIN_WINDOW

        if curr_ts - prev_ts > self.PATH_TIME_WINDOW:
            return False

        prev_source = prev_event.get("source", {})
        curr_source = curr_event.get("source", {})
        prev_details = prev_event.get("raw_details") or {}
        curr_details = curr_event.get("raw_details") or {}

        if prev_source.get("ip") and prev_source.get("ip") == curr_source.get("ip"):
            return True
        if prev_event.get("session_id") and prev_event.get("session_id") == curr_event.get("session_id"):
            return True
        if prev_event.get("fingerprint") and prev_event.get("fingerprint") == curr_event.get("fingerprint"):
            return True
        if prev_details.get("username") and prev_details.get("username") == curr_details.get("username") and curr_ts - prev_ts <= timedelta(minutes=5):
            return True
        if prev_event.get("object", {}).get("path") and prev_event.get("object", {}).get("path") == curr_event.get("object", {}).get("path"):
            return True
        return False

    def _same_controlled_scenario(self, previous: Dict, current: Dict) -> bool:
        if not self.include_experiment_annotations:
            return False
        prev_scenario = previous.get("scenario_id")
        curr_scenario = current.get("scenario_id")
        if not prev_scenario or prev_scenario != curr_scenario:
            return False
        return previous.get("scenario_role") == "controlled_chain" and current.get("scenario_role") == "controlled_chain"

    def _event_to_edge(self, event: Dict) -> Optional[CausalEdge]:
        source = event.get("source") or {}
        obj = event.get("object") or {}
        action = event.get("action") or "unknown"
        timestamp = self._parse_timestamp(event.get("timestamp"))

        subject_id = source.get("id") or "unknown:source"
        object_id = obj.get("id") or "unknown:object"
        if subject_id == object_id and action == "unknown":
            return None

        return CausalEdge(
            edge_id=f"edge_{event.get('event_id', uuid.uuid4().hex)}",
            event_id=event.get("event_id", uuid.uuid4().hex),
            subject_type=source.get("type") or "unknown",
            subject_id=subject_id,
            subject_label=source.get("label") or subject_id,
            action=action,
            object_type=obj.get("type") or "unknown",
            object_id=object_id,
            object_label=obj.get("label") or object_id,
            timestamp=timestamp,
            stage=event.get("stage"),
            tactic=event.get("tactic"),
            technique=event.get("technique"),
            confidence=float(event.get("confidence", 0.8)),
            severity=event.get("severity", "medium"),
            raw_data=event,
            edge_kind="event",
            path_id=event.get("path_id"),
            relation_type="subject_action_object",
        )

    def _build_correlation_edges(self, events: List[Dict]) -> List[CausalEdge]:
        correlation_edges: List[CausalEdge] = []
        seen_edge_ids = set()
        events_by_path = defaultdict(list)
        for event in events:
            path_id = event.get("path_id") or f"event:{event.get('event_id')}"
            events_by_path[path_id].append(event)

        for path_events in events_by_path.values():
            path_events.sort(key=lambda item: self._parse_timestamp(item.get("timestamp")))
            for index in range(1, len(path_events)):
                previous = path_events[index - 1]
                current = path_events[index]
                relation_type = self._infer_correlation_relation(previous, current)
                if not relation_type:
                    continue

                edge = self._make_correlation_edge(previous, current, relation_type, edge_scope="path")
                if edge.edge_id not in seen_edge_ids:
                    seen_edge_ids.add(edge.edge_id)
                    correlation_edges.append(edge)
        correlation_edges.extend(self._build_attacker_timeline_edges(events, seen_edge_ids))
        return correlation_edges

    def _build_attacker_timeline_edges(self, events: List[Dict], seen_edge_ids: set) -> List[CausalEdge]:
        """Add long-horizon same-actor timeline edges for provenance reconstruction."""
        timeline_edges: List[CausalEdge] = []
        events_by_attacker = defaultdict(list)
        for event in events:
            events_by_attacker[event.get("attacker_id") or "unknown_attacker"].append(event)

        for attacker_events in events_by_attacker.values():
            attacker_events.sort(key=lambda item: self._parse_timestamp(item.get("timestamp")))
            for index in range(1, len(attacker_events)):
                previous = attacker_events[index - 1]
                current = attacker_events[index]
                previous_ts = self._parse_timestamp(previous.get("timestamp"))
                current_ts = self._parse_timestamp(current.get("timestamp"))
                if current_ts < previous_ts or current_ts - previous_ts > self.PROVENANCE_CHAIN_WINDOW:
                    continue

                relation_type = self._infer_provenance_relation(previous, current)
                if not relation_type:
                    continue

                edge = self._make_correlation_edge(previous, current, relation_type, edge_scope="attacker_timeline")
                if edge.edge_id in seen_edge_ids:
                    continue
                seen_edge_ids.add(edge.edge_id)
                timeline_edges.append(edge)
        return timeline_edges

    def _make_correlation_edge(self, previous: Dict, current: Dict, relation_type: str, edge_scope: str) -> CausalEdge:
        previous_node_id = f"event:{previous['event_id']}"
        current_node_id = f"event:{current['event_id']}"
        previous_label = f"{previous.get('action')}@{self._short_time(previous.get('timestamp'))}"
        current_label = f"{current.get('action')}@{self._short_time(current.get('timestamp'))}"

        self._add_event_node(previous, previous_node_id, previous_label)
        self._add_event_node(current, current_node_id, current_label)

        previous_ts = self._parse_timestamp(previous.get("timestamp"))
        current_ts = self._parse_timestamp(current.get("timestamp"))
        return CausalEdge(
            edge_id=f"corr_{previous['event_id']}_{current['event_id']}",
            event_id=current["event_id"],
            subject_type="event",
            subject_id=previous_node_id,
            subject_label=previous_label,
            action="correlates_to",
            object_type="event",
            object_id=current_node_id,
            object_label=current_label,
            timestamp=current_ts,
            stage=current.get("stage"),
            tactic=current.get("tactic"),
            technique=current.get("technique"),
            confidence=self._correlation_confidence(relation_type),
            severity=current.get("severity", "medium"),
            raw_data={
                "previous_event_id": previous["event_id"],
                "current_event_id": current["event_id"],
                "relation_type": relation_type,
                "edge_scope": edge_scope,
                "attacker_id": current.get("attacker_id"),
                "campaign_id": current.get("campaign_id"),
                "scenario_id": current.get("scenario_id"),
                "scenario_role": current.get("scenario_role"),
                "evidence_refs": current.get("evidence_refs") or [],
                "shared_evidence": self._shared_evidence_labels(previous, current),
                "time_delta_seconds": max(int((current_ts - previous_ts).total_seconds()), 0),
            },
            edge_kind="correlation",
            path_id=current.get("path_id"),
            relation_type=relation_type,
        )

    def _infer_correlation_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        if previous.get("path_id") and previous.get("path_id") == current.get("path_id"):
            cross_relation = self._cross_honeypot_relation(previous, current)
            if self._same_controlled_scenario(previous, current):
                return cross_relation or self._stage_transition_relation(previous, current) or "controlled_chain_member"

            shared_relation = self._shared_anchor_relation(previous, current)
            if cross_relation and shared_relation:
                return cross_relation
            if shared_relation:
                return shared_relation

            stage_relation = self._stage_transition_relation(previous, current)
            if stage_relation:
                return stage_relation
            return "same_attack_path"
        return None

    def _infer_provenance_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        if previous.get("attacker_id") != current.get("attacker_id"):
            return None

        cross_relation = self._cross_honeypot_relation(previous, current)
        shared_relation = self._shared_anchor_relation(previous, current)
        stage_relation = self._stage_transition_relation(previous, current)

        if self._same_controlled_scenario(previous, current):
            return cross_relation or stage_relation or "controlled_chain_member"
        if cross_relation and (shared_relation or stage_relation):
            return f"{cross_relation}_causal"
        if cross_relation:
            return cross_relation
        if shared_relation and stage_relation:
            return "same_actor_stage_transition"
        if shared_relation:
            return shared_relation
        if stage_relation:
            return "same_actor_temporal"
        return None

    def _cross_honeypot_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        pair = (previous.get("event_type"), current.get("event_type"))
        return self.CROSS_HONEYPOT_RELATIONS.get(pair)

    def _stage_transition_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        prev_rank = self.STAGE_RANK.get(str(previous.get("stage") or "").lower(), 0)
        curr_rank = self.STAGE_RANK.get(str(current.get("stage") or "").lower(), 0)
        if prev_rank and curr_rank and curr_rank > prev_rank:
            return "stage_transition"
        return None

    def _shared_anchor_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        prev_source = previous.get("source", {})
        curr_source = current.get("source", {})
        prev_details = previous.get("raw_details") or {}
        curr_details = current.get("raw_details") or {}

        if prev_source.get("ip") and prev_source.get("ip") == curr_source.get("ip"):
            return "same_source_ip"
        if previous.get("session_id") and previous.get("session_id") == current.get("session_id"):
            return "same_session"
        if previous.get("fingerprint") and previous.get("fingerprint") == current.get("fingerprint"):
            return "same_fingerprint"
        if previous.get("campaign_id") and previous.get("campaign_id") == current.get("campaign_id"):
            return "same_campaign"
        if prev_details.get("username") and prev_details.get("username") == curr_details.get("username"):
            return "same_account_probe"
        return None

    def _shared_evidence_labels(self, previous: Dict, current: Dict) -> List[str]:
        evidence = []
        prev_source = previous.get("source", {})
        curr_source = current.get("source", {})
        prev_details = previous.get("raw_details") or {}
        curr_details = current.get("raw_details") or {}

        if prev_source.get("ip") and prev_source.get("ip") == curr_source.get("ip"):
            evidence.append(f"same_ip:{prev_source.get('ip')}")
        if previous.get("fingerprint") and previous.get("fingerprint") == current.get("fingerprint"):
            evidence.append(f"same_fingerprint:{previous.get('fingerprint')}")
        if previous.get("session_id") and previous.get("session_id") == current.get("session_id"):
            evidence.append(f"same_session:{previous.get('session_id')}")
        if previous.get("campaign_id") and previous.get("campaign_id") == current.get("campaign_id"):
            evidence.append(f"same_campaign:{previous.get('campaign_id')}")
        if prev_details.get("username") and prev_details.get("username") == curr_details.get("username"):
            evidence.append(f"same_username:{prev_details.get('username')}")
        if (
            self.include_experiment_annotations
            and previous.get("scenario_id")
            and previous.get("scenario_id") == current.get("scenario_id")
        ):
            evidence.append(f"same_scenario:{previous.get('scenario_id')}")
        if previous.get("attacker_id") and previous.get("attacker_id") == current.get("attacker_id"):
            evidence.append(f"same_attacker:{previous.get('attacker_id')}")
        return evidence

    @staticmethod
    def _correlation_confidence(relation_type: str) -> float:
        mapping = {
            "same_session": 0.98,
            "same_fingerprint": 0.95,
            "same_source_ip": 0.9,
            "same_campaign": 0.99,
            "same_account_probe": 0.88,
            "same_attack_path": 0.82,
            "stage_transition": 0.86,
            "web_to_account": 0.94,
            "account_to_file": 0.94,
            "web_to_file": 0.9,
            "account_to_web_followup": 0.84,
            "file_to_account_followup": 0.8,
            "file_to_web_followup": 0.8,
            "controlled_chain_member": 0.99,
            "web_to_account_causal": 0.96,
            "account_to_file_causal": 0.96,
            "web_to_file_causal": 0.93,
            "account_to_web_followup_causal": 0.86,
            "file_to_account_followup_causal": 0.82,
            "file_to_web_followup_causal": 0.82,
            "same_actor_stage_transition": 0.88,
            "same_actor_temporal": 0.78,
        }
        return mapping.get(relation_type, 0.8)

    def _add_event_node(self, event: Dict, node_id: str, label: str) -> None:
        existing = self.nodes.get(node_id, {})
        payload = {
            "id": node_id,
            "type": "event",
            "label": label,
            "first_seen": event.get("timestamp"),
            "last_seen": event.get("timestamp"),
            "roles": sorted(set(existing.get("roles", []) + ["event"])),
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "path_id": event.get("path_id"),
            "attacker_id": event.get("attacker_id"),
            "campaign_id": event.get("campaign_id"),
        }
        if existing:
            payload["first_seen"] = min(existing.get("first_seen") or payload["first_seen"], payload["first_seen"])
            payload["last_seen"] = max(existing.get("last_seen") or payload["last_seen"], payload["last_seen"])
        self.nodes[node_id] = payload

    def _add_node(self, node_id: str, node_type: str, label: str, event: Dict, role: str) -> None:
        if not node_id:
            return
        existing = self.nodes.get(node_id, {})
        payload = {
            "id": node_id,
            "type": node_type or "unknown",
            "label": label or node_id,
            "first_seen": event.get("timestamp"),
            "last_seen": event.get("timestamp"),
            "roles": sorted(set(existing.get("roles", []) + [role])),
        }

        source = event.get("source", {})
        obj = event.get("object", {})
        if role == "source":
            if source.get("ip"):
                payload["ip"] = source.get("ip")
            if source.get("info"):
                payload["info"] = source.get("info")
            if event.get("source_intel"):
                payload["source_intel"] = event.get("source_intel")
            if event.get("actor_intel"):
                payload["actor_intel"] = event.get("actor_intel")
        else:
            if obj.get("host"):
                payload["host"] = obj.get("host")
            if obj.get("path"):
                payload["path"] = obj.get("path")

        if event.get("path_id"):
            payload["path_id"] = event.get("path_id")
        if event.get("attacker_id"):
            payload["attacker_id"] = event.get("attacker_id")
        if event.get("campaign_id"):
            payload["campaign_id"] = event.get("campaign_id")

        if existing:
            payload["first_seen"] = min(existing.get("first_seen") or payload["first_seen"], payload["first_seen"])
            payload["last_seen"] = max(existing.get("last_seen") or payload["last_seen"], payload["last_seen"])
            for key in ("ip", "info", "host", "path", "path_id", "attacker_id", "campaign_id"):
                if key not in payload and key in existing:
                    payload[key] = existing[key]

        self.nodes[node_id] = payload

    def _fallback_source_type(self, data: Dict) -> str:
        if data.get("event_type") == "audit" or data.get("alert_type") == "audit":
            return "process"
        if data.get("event_type") == "parasitic" or data.get("alert_type") == "parasitic":
            return "browser"
        return "network"

    def _fallback_source_id(self, data: Dict) -> str:
        source_type = self._fallback_source_type(data)
        if source_type == "process":
            process = data.get("process") or data.get("process_info") or {}
            pid = process.get("pid")
            return f"process:{pid}" if pid is not None else "process:unknown"
        if source_type == "browser":
            details = data.get("raw_details") or data.get("details") or {}
            fp = data.get("attacker_info") or details.get("fingerprint")
            return f"browser:{fp}" if fp else "browser:unknown"
        ip = data.get("attacker_ip")
        return f"network:{ip}" if ip else "network:unknown"

    def _fallback_source_label(self, data: Dict) -> str:
        if self._fallback_source_type(data) == "process":
            process = data.get("process") or data.get("process_info") or {}
            return process.get("exe") or f"pid:{process.get('pid', 'unknown')}"
        return data.get("attacker_ip") or data.get("attacker_info") or "unknown source"

    def _fallback_object_type(self, data: Dict) -> str:
        event_type = data.get("event_type") or data.get("alert_type")
        action = data.get("action")
        if event_type == "account":
            return "service"
        if event_type == "parasitic":
            return "url"
        if event_type == "audit":
            if action in {"execve", "fork"}:
                return "process"
            if action == "connect":
                return "network"
        return "file"

    def _fallback_object_id(self, data: Dict) -> str:
        object_type = self._fallback_object_type(data)
        details = data.get("raw_details") or data.get("details") or {}
        if object_type == "service":
            action = data.get("action") or "service"
            host = data.get("target_host") or "unknown"
            return f"service:{action}@{host}"
        if object_type == "url":
            value = data.get("target_path") or details.get("url") or details.get("path")
            return f"url:{value}" if value else "url:unknown"
        if object_type == "process":
            process = data.get("process") or data.get("process_info") or {}
            pid = process.get("pid")
            return f"process:{pid}" if pid is not None else "process:unknown"
        if object_type == "network":
            value = data.get("target_path") or details.get("dest_ip") or details.get("target")
            return f"network:{value}" if value else "network:unknown"
        path = data.get("target_path")
        return f"file:{path}" if path else "file:unknown"

    def _fallback_object_label(self, data: Dict) -> str:
        return data.get("target_path") or data.get("target_host") or "unknown object"

    def _to_iso(self, value: object) -> str:
        return self._parse_timestamp(value).isoformat()

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now()

    def _short_time(self, value: object) -> str:
        ts = self._parse_timestamp(value)
        return ts.strftime("%H:%M:%S")

    def to_dict(self) -> Dict:
        edge_dicts = []
        triples = []
        event_sequence = []
        attacker_summaries = []
        path_summaries = []

        for edge in self.edges:
            event = self.event_index.get(edge.event_id, edge.raw_data)
            edge_dict = {
                "edge_id": edge.edge_id,
                "event_id": edge.event_id,
                "source": edge.subject_id,
                "target": edge.object_id,
                "action": edge.action,
                "timestamp": edge.timestamp.isoformat(),
                "subject_type": edge.subject_type,
                "subject_label": edge.subject_label,
                "object_type": edge.object_type,
                "object_label": edge.object_label,
                "stage": edge.stage,
                "tactic": edge.tactic,
                "technique": edge.technique,
                "confidence": edge.confidence,
                "severity": edge.severity,
                "edge_kind": edge.edge_kind,
                "path_id": edge.path_id,
                "relation_type": edge.relation_type,
                "attacker_id": edge.raw_data.get("attacker_id"),
                "campaign_id": event.get("campaign_id") or edge.raw_data.get("campaign_id"),
                "scenario_id": event.get("scenario_id") or edge.raw_data.get("scenario_id"),
                "scenario_role": event.get("scenario_role") or edge.raw_data.get("scenario_role"),
                "evidence_refs": event.get("evidence_refs") or edge.raw_data.get("evidence_refs") or [],
                "edge_scope": edge.raw_data.get("edge_scope") if edge.edge_kind == "correlation" else "event",
                "shared_evidence": edge.raw_data.get("shared_evidence", []) if edge.edge_kind == "correlation" else [],
                "time_delta_seconds": edge.raw_data.get("time_delta_seconds") if edge.edge_kind == "correlation" else None,
            }
            edge_dicts.append(edge_dict)
            triples.append(edge.to_triple())
            if edge.edge_kind == "event":
                event_sequence.append(
                    {
                        "event_id": edge.event_id,
                        "timestamp": edge.timestamp.isoformat(),
                        "action": edge.action,
                        "stage": edge.stage,
                        "source_id": edge.subject_id,
                        "object_id": edge.object_id,
                        "tactic": edge.tactic,
                        "technique": edge.technique,
                        "severity": edge.severity,
                        "confidence": edge.confidence,
                        "path_id": edge.path_id,
                        "attacker_id": event.get("attacker_id"),
                        "campaign_id": event.get("campaign_id"),
                        "scenario_id": event.get("scenario_id"),
                        "scenario_role": event.get("scenario_role"),
                        "evidence_refs": event.get("evidence_refs") or [],
                        "canonical_event": event,
                    }
                )

        for attacker_id, group in sorted(self.attacker_groups.items()):
            attacker_summaries.append(
                {
                    "attacker_id": attacker_id,
                    "event_ids": list(group.get("event_ids", [])),
                    "path_ids": sorted(group.get("path_ids", [])),
                    "event_types": list(group.get("event_types", [])),
                    "event_count": int(group.get("event_count", 0)),
                    "anchors": list(group.get("anchors", [])),
                    "start_time": group.get("start_time"),
                    "end_time": group.get("end_time"),
                    "campaign_ids": sorted(
                        {
                            str(self.event_index.get(event_id, {}).get("campaign_id"))
                            for event_id in group.get("event_ids", [])
                            if self.event_index.get(event_id, {}).get("campaign_id")
                        }
                    ),
                    "scenario_ids": sorted(
                        {
                            str(self.event_index.get(event_id, {}).get("scenario_id"))
                            for event_id in group.get("event_ids", [])
                            if self.event_index.get(event_id, {}).get("scenario_id")
                        }
                    ),
                }
            )

        for path_id, group in sorted(self.path_groups.items()):
            path_summaries.append(
                {
                    "path_id": path_id,
                    "attacker_id": group.get("attacker_id"),
                    "event_ids": list(group.get("event_ids", [])),
                    "event_types": list(group.get("event_types", [])),
                    "event_count": int(group.get("event_count", 0)),
                    "anchors": list(group.get("anchors", [])),
                    "start_time": group.get("start_time"),
                    "end_time": group.get("end_time"),
                    "campaign_ids": sorted(
                        {
                            str(self.event_index.get(event_id, {}).get("campaign_id"))
                            for event_id in group.get("event_ids", [])
                            if self.event_index.get(event_id, {}).get("campaign_id")
                        }
                    ),
                    "scenario_ids": sorted(
                        {
                            str(self.event_index.get(event_id, {}).get("scenario_id"))
                            for event_id in group.get("event_ids", [])
                            if self.event_index.get(event_id, {}).get("scenario_id")
                        }
                    ),
                }
            )

        event_edge_count = sum(1 for edge in self.edges if edge.edge_kind == "event")
        correlation_edge_count = sum(1 for edge in self.edges if edge.edge_kind == "correlation")
        relation_counts = Counter(edge.relation_type or "unknown" for edge in self.edges)
        scenario_summaries = self._build_scenario_summaries()
        provenance_chains = self._build_provenance_chains()

        return {
            "graph_meta": {
                "graph_type": "attack_provenance_graph",
                "node_count": len(self.nodes),
                "edge_count": len(edge_dicts),
                "event_edge_count": event_edge_count,
                "correlation_edge_count": correlation_edge_count,
                "triple_count": len(triples),
                "attacker_count": len(attacker_summaries),
                "path_count": len(path_summaries),
                "relation_counts": dict(relation_counts),
                "controlled_scenario_count": len(scenario_summaries),
                "provenance_chain_count": len(provenance_chains),
                "strong_provenance_chain_count": sum(
                    1 for chain in provenance_chains if chain.get("chain_strength") == "strong"
                ),
                "generated_at": datetime.now().isoformat(),
            },
            "nodes": list(self.nodes.values()),
            "edges": edge_dicts,
            "triples": triples,
            "event_sequence": event_sequence,
            "attacker_groups": attacker_summaries,
            "attack_paths": path_summaries,
            "provenance_chains": provenance_chains,
            "controlled_scenarios": scenario_summaries,
        }

    def _build_provenance_chains(self) -> List[Dict]:
        events_by_attacker = defaultdict(list)
        for event in self.event_index.values():
            attacker_id = event.get("attacker_id") or "unknown_attacker"
            events_by_attacker[attacker_id].append(event)

        correlation_edges_by_attacker = defaultdict(list)
        for edge in self.edges:
            if edge.edge_kind != "correlation":
                continue
            attacker_id = edge.raw_data.get("attacker_id") or "unknown_attacker"
            correlation_edges_by_attacker[attacker_id].append(edge)

        chains = []
        cross_relation_names = set(self.CROSS_HONEYPOT_RELATIONS.values())
        cross_relation_names.update(f"{name}_causal" for name in self.CROSS_HONEYPOT_RELATIONS.values())

        for attacker_id, events in sorted(events_by_attacker.items()):
            events.sort(key=lambda item: self._parse_timestamp(item.get("timestamp")))
            event_types = [str(event.get("event_type") or "unknown") for event in events]
            unique_event_types = sorted(set(event_types))
            if len(events) < 2 and len(unique_event_types) < 2:
                continue

            hop_edges = []
            for edge in sorted(correlation_edges_by_attacker.get(attacker_id, []), key=lambda item: item.timestamp):
                relation_type = edge.relation_type or "unknown"
                hop_edges.append(
                    {
                        "edge_id": edge.edge_id,
                        "from_event_id": edge.raw_data.get("previous_event_id"),
                        "to_event_id": edge.raw_data.get("current_event_id"),
                        "relation_type": relation_type,
                        "edge_scope": edge.raw_data.get("edge_scope", "path"),
                        "confidence": edge.confidence,
                        "shared_evidence": edge.raw_data.get("shared_evidence", []),
                        "time_delta_seconds": edge.raw_data.get("time_delta_seconds"),
                    }
                )

            phase_sequence = []
            for event in events:
                phase_sequence.append(
                    {
                        "event_id": event.get("event_id"),
                        "timestamp": event.get("timestamp"),
                        "event_type": event.get("event_type"),
                        "action": event.get("action"),
                        "stage": event.get("stage"),
                        "source_id": (event.get("source") or {}).get("id"),
                        "object_id": (event.get("object") or {}).get("id"),
                        "campaign_id": event.get("campaign_id"),
                        "scenario_id": event.get("scenario_id"),
                        "scenario_role": event.get("scenario_role"),
                    }
                )

            cross_honeypot_hops = [
                hop for hop in hop_edges
                if str(hop.get("relation_type") or "") in cross_relation_names
            ]
            has_all_honeypots = {"account", "file", "parasitic"}.issubset(set(unique_event_types))
            has_multi_honeypot = len({"account", "file", "parasitic"}.intersection(set(unique_event_types))) >= 2
            avg_confidence = (
                sum(float(hop.get("confidence") or 0.0) for hop in hop_edges) / max(len(hop_edges), 1)
                if hop_edges else 0.0
            )
            stage_ranks = [self.STAGE_RANK.get(str(event.get("stage") or "").lower(), 0) for event in events]
            stage_progression_pairs = 0
            stage_regression_pairs = 0
            for index in range(1, len(stage_ranks)):
                if stage_ranks[index - 1] and stage_ranks[index]:
                    if stage_ranks[index] >= stage_ranks[index - 1]:
                        stage_progression_pairs += 1
                    else:
                        stage_regression_pairs += 1

            if has_all_honeypots and len(cross_honeypot_hops) >= 2:
                chain_strength = "strong"
            elif has_multi_honeypot and (cross_honeypot_hops or len(hop_edges) >= 1):
                chain_strength = "medium"
            else:
                chain_strength = "weak"

            chains.append(
                {
                    "chain_id": f"chain_{len(chains) + 1:03d}",
                    "attacker_id": attacker_id,
                    "chain_strength": chain_strength,
                    "event_count": len(events),
                    "event_types": unique_event_types,
                    "has_all_honeypots": has_all_honeypots,
                    "has_multi_honeypot": has_multi_honeypot,
                    "start_time": events[0].get("timestamp") if events else "",
                    "end_time": events[-1].get("timestamp") if events else "",
                    "phase_label": " -> ".join(event_types),
                    "campaign_ids": sorted({str(event.get("campaign_id")) for event in events if event.get("campaign_id")}),
                    "phase_sequence": phase_sequence,
                    "hop_edges": hop_edges,
                    "cross_honeypot_hop_count": len(cross_honeypot_hops),
                    "average_correlation_confidence": round(avg_confidence, 4),
                    "stage_progression_pairs": stage_progression_pairs,
                    "stage_regression_pairs": stage_regression_pairs,
                    "thesis_use": (
                        "core_cross_honeypot_chain"
                        if chain_strength == "strong"
                        else ("candidate_chain" if chain_strength == "medium" else "background_or_single_surface")
                    ),
                }
            )
        return chains

    def _build_scenario_summaries(self) -> List[Dict]:
        scenario_groups = defaultdict(list)
        for event in self.event_index.values():
            scenario_id = event.get("scenario_id")
            if scenario_id:
                scenario_groups[str(scenario_id)].append(event)

        summaries = []
        for scenario_id, events in sorted(scenario_groups.items()):
            events.sort(key=lambda item: self._parse_timestamp(item.get("timestamp")))
            event_types = sorted({str(event.get("event_type") or "unknown") for event in events})
            roles = sorted({str(event.get("scenario_role") or "unknown") for event in events})
            summaries.append(
                {
                    "scenario_id": scenario_id,
                    "roles": roles,
                    "event_types": event_types,
                    "event_count": len(events),
                    "has_all_honeypots": {"account", "file", "parasitic"}.issubset(set(event_types)),
                    "start_time": events[0].get("timestamp") if events else "",
                    "end_time": events[-1].get("timestamp") if events else "",
                    "event_ids": [event.get("event_id") for event in events],
                    "campaign_ids": sorted({str(event.get("campaign_id")) for event in events if event.get("campaign_id")}),
                    "attacker_ids": sorted({str(event.get("attacker_id")) for event in events if event.get("attacker_id")}),
                }
            )
        return summaries

    def save(self, output_path: str) -> None:
        data = self.to_dict()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] Saved provenance graph to {output_path}")
        print(f"    nodes: {len(data['nodes'])}")
        print(f"    edges: {len(data['edges'])}")
