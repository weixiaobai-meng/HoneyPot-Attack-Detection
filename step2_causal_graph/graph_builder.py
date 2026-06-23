"""
Step 2: build attack provenance graph and standard triples from canonical events.
"""

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


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

    def __init__(self):
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
            "evidence": evidence,
            "raw_details": details,
        }
        return normalized

    def _build_attacker_anchor_keys(self, event: Dict) -> List[str]:
        anchors = []
        source = event.get("source", {})
        source_ip = source.get("ip")
        fingerprint = event.get("fingerprint")
        session_id = event.get("session_id")
        details = event.get("raw_details") or {}
        username = details.get("username")

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
        previous_event = None

        for event in events:
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

            previous_event = event

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
        for index in range(1, len(events)):
            previous = events[index - 1]
            current = events[index]
            relation_type = self._infer_correlation_relation(previous, current)
            if not relation_type:
                continue

            previous_node_id = f"event:{previous['event_id']}"
            current_node_id = f"event:{current['event_id']}"
            previous_label = f"{previous.get('action')}@{self._short_time(previous.get('timestamp'))}"
            current_label = f"{current.get('action')}@{self._short_time(current.get('timestamp'))}"

            self._add_event_node(previous, previous_node_id, previous_label)
            self._add_event_node(current, current_node_id, current_label)

            correlation_edges.append(
                CausalEdge(
                    edge_id=f"corr_{previous['event_id']}_{current['event_id']}",
                    event_id=current["event_id"],
                    subject_type="event",
                    subject_id=previous_node_id,
                    subject_label=previous_label,
                    action="correlates_to",
                    object_type="event",
                    object_id=current_node_id,
                    object_label=current_label,
                    timestamp=self._parse_timestamp(current.get("timestamp")),
                    stage=current.get("stage"),
                    tactic=current.get("tactic"),
                    technique=current.get("technique"),
                    confidence=self._correlation_confidence(relation_type),
                    severity=current.get("severity", "medium"),
                    raw_data={
                        "previous_event_id": previous["event_id"],
                        "current_event_id": current["event_id"],
                        "relation_type": relation_type,
                        "attacker_id": current.get("attacker_id"),
                    },
                    edge_kind="correlation",
                    path_id=current.get("path_id"),
                    relation_type=relation_type,
                )
            )
        return correlation_edges

    def _infer_correlation_relation(self, previous: Dict, current: Dict) -> Optional[str]:
        prev_source = previous.get("source", {})
        curr_source = current.get("source", {})
        prev_details = previous.get("raw_details") or {}
        curr_details = current.get("raw_details") or {}

        if previous.get("path_id") and previous.get("path_id") == current.get("path_id"):
            if prev_source.get("ip") and prev_source.get("ip") == curr_source.get("ip"):
                return "same_source_ip"
            if previous.get("session_id") and previous.get("session_id") == current.get("session_id"):
                return "same_session"
            if previous.get("fingerprint") and previous.get("fingerprint") == current.get("fingerprint"):
                return "same_fingerprint"
            if prev_details.get("username") and prev_details.get("username") == curr_details.get("username"):
                return "same_account_probe"
            return "same_attack_path"
        return None

    @staticmethod
    def _correlation_confidence(relation_type: str) -> float:
        mapping = {
            "same_session": 0.98,
            "same_fingerprint": 0.95,
            "same_source_ip": 0.9,
            "same_account_probe": 0.88,
            "same_attack_path": 0.82,
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
        else:
            if obj.get("host"):
                payload["host"] = obj.get("host")
            if obj.get("path"):
                payload["path"] = obj.get("path")

        if event.get("path_id"):
            payload["path_id"] = event.get("path_id")
        if event.get("attacker_id"):
            payload["attacker_id"] = event.get("attacker_id")

        if existing:
            payload["first_seen"] = min(existing.get("first_seen") or payload["first_seen"], payload["first_seen"])
            payload["last_seen"] = max(existing.get("last_seen") or payload["last_seen"], payload["last_seen"])
            for key in ("ip", "info", "host", "path", "path_id", "attacker_id"):
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
                }
            )

        event_edge_count = sum(1 for edge in self.edges if edge.edge_kind == "event")
        correlation_edge_count = sum(1 for edge in self.edges if edge.edge_kind == "correlation")

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
                "generated_at": datetime.now().isoformat(),
            },
            "nodes": list(self.nodes.values()),
            "edges": edge_dicts,
            "triples": triples,
            "event_sequence": event_sequence,
            "attacker_groups": attacker_summaries,
            "attack_paths": path_summaries,
        }

    def save(self, output_path: str) -> None:
        data = self.to_dict()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] Saved provenance graph to {output_path}")
        print(f"    nodes: {len(data['nodes'])}")
        print(f"    edges: {len(data['edges'])}")
