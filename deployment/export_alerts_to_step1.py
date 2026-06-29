"""
Export honeypot alerts into the thesis experiment pipeline.

This script separates the useful data-export path from the old one-click
installation/deployment path.

Workflows:`r`n1. simulate: create a reproducible three-honeypot experiment under generated_runs/.
2. export-live: collect live logs and write the normal step1-step4 pipeline files.
"""

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from step1_data_collection import AlertType, DataCollector, UnifiedAlert
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
from step4_graph_to_text import GraphToTextConverter

DQNTrainer = None
attach_manual_labels = None
get_graph_statistics = None
load_graph_from_file = None
load_graphs_for_training = None
DQN_IMPORT_ERROR = None
DQN_TOOLS_LOADED = False


def _load_dqn_tools() -> bool:
    global DQNTrainer
    global attach_manual_labels
    global get_graph_statistics
    global load_graph_from_file
    global load_graphs_for_training
    global DQN_IMPORT_ERROR
    global DQN_TOOLS_LOADED

    if DQN_TOOLS_LOADED:
        return DQNTrainer is not None

    try:
        from step3_dqn_pruning import (  # type: ignore
            DQNTrainer as _DQNTrainer,
            attach_manual_labels as _attach_manual_labels,
            get_graph_statistics as _get_graph_statistics,
            load_graph_from_file as _load_graph_from_file,
            load_graphs_for_training as _load_graphs_for_training,
        )
        DQNTrainer = _DQNTrainer
        attach_manual_labels = _attach_manual_labels
        get_graph_statistics = _get_graph_statistics
        load_graph_from_file = _load_graph_from_file
        load_graphs_for_training = _load_graphs_for_training
        DQN_IMPORT_ERROR = None
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", "") not in {"torch", "torch_geometric"}:
            raise
        DQN_IMPORT_ERROR = exc

    DQN_TOOLS_LOADED = True
    return DQNTrainer is not None


DEFAULT_RUN_DIR = REPO_ROOT / "generated_runs" / "three_honeypot_pipeline"
MAX_ALERTS_FOR_LIVE_ANALYSIS = 10000
MAX_DQN_EDGES = 5000
MAX_SIMULATED_KEPT_EDGES = 5000
MAX_PROMPT_EDGES = 200
SYSTEMWIRE2_ROOT = REPO_ROOT / "systemwire2"


def build_live_analysis_collector_config():
    base_config = DataCollector()._default_config()
    config = deepcopy(base_config)
    config["analysis_source_mode"] = "systemwire2_unified_only"
    config["analysis_include_alert_types"] = ["file", "account", "parasitic"]
    config["unified_alert_store"]["enabled"] = True
    config["unified_alert_store"]["prefer_types"] = ["file", "account", "parasitic"]
    config["unified_alert_store"]["fallback_to_raw"] = False
    config["audit_log"]["enabled"] = False
    return config


def _import_systemwire2_unified_api_builder():
    if not SYSTEMWIRE2_ROOT.exists():
        raise FileNotFoundError(f"systemwire2 root not found: {SYSTEMWIRE2_ROOT}")

    systemwire_root_text = str(SYSTEMWIRE2_ROOT)
    if systemwire_root_text not in sys.path:
        sys.path.insert(0, systemwire_root_text)

    from flask_server.flask_app import flask_app  # type: ignore
    from flask_server.alert_store import build_unified_alert_api_rows  # type: ignore

    return flask_app, build_unified_alert_api_rows


def _import_systemwire2_intel_enricher():
    if not SYSTEMWIRE2_ROOT.exists():
        raise FileNotFoundError(f"systemwire2 root not found: {SYSTEMWIRE2_ROOT}")

    systemwire_root_text = str(SYSTEMWIRE2_ROOT)
    if systemwire_root_text not in sys.path:
        sys.path.insert(0, systemwire_root_text)

    from flask_server.alert_store import _attach_source_and_actor_intel  # type: ignore

    return _attach_source_and_actor_intel


def _parse_alert_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return datetime.now()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now()


def _parse_scenario_timestamp(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("scenario timestamp is required")
    normalized = text.replace("T", " ")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid scenario timestamp: {text}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone(timedelta(hours=8)))
    return parsed


def _alert_timestamp_in_range(alert: UnifiedAlert, start_time: datetime, end_time: datetime) -> bool:
    alert_time = alert.timestamp
    if alert_time.tzinfo is None:
        alert_time = alert_time.replace(tzinfo=timezone(timedelta(hours=8)))
    return start_time <= alert_time <= end_time


def _normalize_identifier_set(values) -> Set[str]:
    result = set()
    for item in values or []:
        text = str(item or "").strip()
        if text:
            result.add(text)
    return result


def _map_unified_api_row_to_alert(row: Dict[str, Any]) -> UnifiedAlert:
    alert_type = AlertType(str(row.get("alert_type") or "audit"))
    timestamp = _parse_alert_timestamp(row.get("timestamp"))
    details = deepcopy(row.get("details") or {})
    source_intel = deepcopy(row.get("source_intel") or {})
    actor_intel = deepcopy(row.get("actor_intel") or {})
    attacker_ip = row.get("attacker_ip")
    action = row.get("action")
    severity = row.get("severity") or "medium"
    target_path = row.get("target_path")
    attacker_info = None
    target_host = None
    source_type = None
    source_id = None
    source_label = None
    object_type = None
    object_id = None
    object_label = None
    stage = None
    tactic = None
    technique = None
    session_id = None
    confidence = 0.9
    evidence = deepcopy(details)

    if alert_type == AlertType.FILE_HONEYPOT:
        attacker_info = details.get("report_agent") or None
        target_host = details.get("deployment_summary") or None
        source_type = "network"
        source_id = f"network:{attacker_ip}" if attacker_ip else "network:unknown"
        source_label = attacker_ip or "unknown network source"
        object_type = "file"
        object_id = f"file:{target_path}" if target_path else "file:unknown"
        object_label = details.get("filename") or target_path or "unknown file"
        stage = "collection"
        tactic = "Collection"
        technique = "Honey File Access"
        confidence = 0.96
    elif alert_type == AlertType.ACCOUNT_HONEYPOT:
        attacker_info = details.get("client_version") or None
        target_host = details.get("dst_endpoint") or row.get("target_path") or None
        protocol = str(details.get("protocol") or "ssh").strip().lower()
        source_type = "network"
        source_id = f"network:{attacker_ip}" if attacker_ip else "network:unknown"
        source_label = attacker_ip or "unknown account source"
        object_type = "service"
        object_id = f"service:{protocol}@{row.get('target_path')}" if row.get("target_path") else f"service:{protocol}"
        object_label = row.get("target_path") or f"{protocol} service"
        stage = "initial_access"
        tactic = "Initial Access"
        technique = "External Remote Services"
        confidence = 0.95
    elif alert_type == AlertType.PARASITIC_HONEYPOT:
        fingerprint = details.get("fingerprint") or ""
        session_id = details.get("session_token") or None
        attacker_info = fingerprint or None
        source_type = "browser"
        source_id = f"browser:{fingerprint}" if fingerprint else (f"browser:{session_id}" if session_id else "browser:unknown")
        source_label = fingerprint or session_id or "unknown browser fingerprint"
        object_type = "url"
        object_id = f"url:{target_path}" if target_path else "url:unknown"
        object_label = target_path or "unknown url"
        stage = "reconnaissance"
        tactic = "Reconnaissance"
        technique = "Honey Web Resource Access"
        target_host = row.get("target_path")
        confidence = 0.94 if details.get("possible_proxy") or details.get("is_bot") else 0.9
    else:
        source_type = "unknown"
        source_id = "unknown:source"
        source_label = attacker_ip or "unknown source"
        object_type = "unknown"
        object_id = "unknown:object"
        object_label = target_path or "unknown object"

    return UnifiedAlert(
        alert_id=str(row.get("alert_id") or ""),
        alert_type=alert_type,
        timestamp=timestamp,
        attacker_ip=attacker_ip,
        attacker_info=attacker_info,
        target_host=target_host,
        target_path=target_path,
        action=action,
        details=details,
        session_id=session_id,
        source_type=source_type,
        source_id=source_id,
        source_label=source_label,
        object_type=object_type,
        object_id=object_id,
        object_label=object_label,
        stage=stage,
        tactic=tactic,
        technique=technique,
        confidence=confidence,
        severity=severity,
        source_intel=source_intel,
        actor_intel=actor_intel,
        evidence=evidence,
    )


def collect_live_alerts_from_systemwire2_api(hours: int) -> List[UnifiedAlert]:
    flask_app, build_unified_alert_api_rows = _import_systemwire2_unified_api_builder()
    allowed_types = {"file", "account", "parasitic"}
    with flask_app.app_context():
        rows: List[Dict[str, Any]] = build_unified_alert_api_rows(hours=hours, alert_type=None)
    rows = [row for row in rows if str(row.get("alert_type") or "").strip().lower() in allowed_types]
    alerts = [_map_unified_api_row_to_alert(row) for row in rows]
    alerts.sort(key=lambda item: item.timestamp)
    return alerts


def collect_live_alerts_between(start_time: datetime, end_time: datetime) -> List[UnifiedAlert]:
    """Collect real unified alerts and filter by an explicit experiment window."""
    if end_time < start_time:
        raise ValueError("end time must be later than or equal to start time")
    live_alerts = collect_live_alerts_from_systemwire2_api(hours=0)
    return [
        alert for alert in live_alerts
        if _alert_timestamp_in_range(alert, start_time, end_time)
    ]


def _alert_matches_chain(
    alert: UnifiedAlert,
    chain_ips: Set[str],
    chain_fingerprints: Set[str],
    chain_sessions: Set[str],
    chain_alert_ids: Set[str],
) -> bool:
    if alert.alert_id and alert.alert_id in chain_alert_ids:
        return True
    if alert.attacker_ip and alert.attacker_ip in chain_ips:
        return True

    details = alert.details or {}
    fingerprint = str(details.get("fingerprint") or alert.attacker_info or "").strip()
    session_id = str(alert.session_id or details.get("session_token") or details.get("session_id") or "").strip()
    if fingerprint and fingerprint in chain_fingerprints:
        return True
    if session_id and session_id in chain_sessions:
        return True
    return False


def annotate_controlled_scenario_alerts(
    alerts: List[UnifiedAlert],
    scenario_id: str,
    chain_actor_id: str,
    chain_ips=None,
    chain_fingerprints=None,
    chain_sessions=None,
    chain_alert_ids=None,
) -> List[UnifiedAlert]:
    """Add experiment-only metadata to real alerts without changing the database."""
    chain_ips = _normalize_identifier_set(chain_ips)
    chain_fingerprints = _normalize_identifier_set(chain_fingerprints)
    chain_sessions = _normalize_identifier_set(chain_sessions)
    chain_alert_ids = _normalize_identifier_set(chain_alert_ids)

    if not any([chain_ips, chain_fingerprints, chain_sessions, chain_alert_ids]):
        raise ValueError("at least one chain identifier is required: --chain-ip, --chain-fingerprint, --chain-session, or --chain-alert-id")

    annotated = []
    for alert in alerts:
        item = deepcopy(alert)
        is_chain = _alert_matches_chain(item, chain_ips, chain_fingerprints, chain_sessions, chain_alert_ids)
        role = "controlled_chain" if is_chain else "controlled_noise"
        item.details = deepcopy(item.details or {})
        item.details["scenario_id"] = scenario_id
        item.details["scenario_role"] = role
        item.details["experiment"] = {
            "scenario_id": scenario_id,
            "scenario_role": role,
            "chain_actor_id": chain_actor_id if is_chain else "",
            "data_source": "real_systemwire2_unified_alert",
            "annotation_only": True,
        }
        item.evidence = deepcopy(item.evidence or item.details)
        item.actor_intel = deepcopy(item.actor_intel or {})
        if is_chain:
            item.actor_intel.setdefault("group_id", chain_actor_id)
            item.actor_intel["cross_honeypot"] = True
        annotated.append(item)
    annotated.sort(key=lambda alert: alert.timestamp)
    return annotated


def _alert_to_intel_row(alert: UnifiedAlert) -> Dict[str, Any]:
    row = {
        "alert_id": alert.alert_id,
        "alert_type": alert.alert_type.value if isinstance(alert.alert_type, AlertType) else str(alert.alert_type),
        "timestamp": alert.timestamp.isoformat() if isinstance(alert.timestamp, datetime) else str(alert.timestamp),
        "attacker_ip": alert.attacker_ip,
        "target_path": alert.target_path or alert.target_host or "",
        "action": alert.action,
        "severity": alert.severity,
        "details": deepcopy(alert.details or {}),
    }
    return row


def enrich_alerts_with_systemwire2_intel(alerts: List[UnifiedAlert]) -> List[UnifiedAlert]:
    if not alerts:
        return []

    attach_source_and_actor_intel = _import_systemwire2_intel_enricher()
    intel_rows = [_alert_to_intel_row(alert) for alert in alerts]
    enriched_rows = attach_source_and_actor_intel(intel_rows)

    by_id = {alert.alert_id: alert for alert in alerts}
    enriched_alerts: List[UnifiedAlert] = []
    for row in enriched_rows:
        original = by_id.get(str(row.get("alert_id") or ""))
        base_alert = _map_unified_api_row_to_alert(row)
        if original is not None:
            base_alert.process_info = deepcopy(original.process_info)
            if original.session_id and not base_alert.session_id:
                base_alert.session_id = original.session_id
        enriched_alerts.append(base_alert)

    enriched_alerts.sort(key=lambda item: item.timestamp)
    return enriched_alerts


def enrich_simulated_alert_groups(alert_groups: Dict[str, List[UnifiedAlert]]) -> Dict[str, List[UnifiedAlert]]:
    all_alerts: List[UnifiedAlert] = []
    ordered_group_names = ["file", "account", "parasitic", "audit"]
    for group_name in ordered_group_names:
        all_alerts.extend(alert_groups.get(group_name, []))

    enriched = enrich_alerts_with_systemwire2_intel(all_alerts)
    grouped: Dict[str, List[UnifiedAlert]] = {name: [] for name in ordered_group_names}
    for alert in enriched:
        grouped.setdefault(alert.alert_type.value, []).append(alert)
    return grouped


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except Exception:
        return str(path)


def build_default_paths():
    return {
        "base_dir": REPO_ROOT,
        "alerts_dir": REPO_ROOT / "deployment" / "alerts",
        "deployment_output_dir": REPO_ROOT / "deployment" / "output",
        "deployments": REPO_ROOT / "deployment" / "output" / "honeypot_deployments.json",
        "collected_alerts": REPO_ROOT / "deployment" / "output" / "collected_alerts.json",
        "step1": REPO_ROOT / "step1_data_collection" / "output" / "unified_alerts.json",
        "canonical_events": REPO_ROOT / "step1_data_collection" / "output" / "canonical_events.json",
        "step2": REPO_ROOT / "step2_causal_graph" / "output" / "causal_graph.json",
        "step2_mermaid": REPO_ROOT / "step2_causal_graph" / "output" / "causal_graph.mmd",
        "step2_triples": REPO_ROOT / "step2_causal_graph" / "output" / "step2_standard_triples.json",
        "step2_event_sequence": REPO_ROOT / "step2_causal_graph" / "output" / "step2_event_sequence.json",
        "step3": REPO_ROOT / "step3_dqn_pruning" / "output" / "pruned_graph.json",
        "step3_edge_labels": REPO_ROOT / "step3_dqn_pruning" / "output" / "edge_labels.json",
        "step3_checkpoint": REPO_ROOT / "step3_dqn_pruning" / "output" / "checkpoints" / "dqn_best.pt",
        "step4_intent": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_intent_analysis.txt",
        "step4_ttp": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_ttp_mapping.txt",
        "step4_report": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_report.txt",
        "step4_thesis": REPO_ROOT / "step4_graph_to_text" / "output" / "thesis_analysis.md",
        "step4_llm_report": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_report.md",
        "step4_llm_report_meta": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_report_meta.json",
        "summary": REPO_ROOT / "deployment" / "output" / "honeypot_experiment_summary.json",
    }


def build_run_paths(run_dir: Path):
    run_dir = run_dir if run_dir.is_absolute() else REPO_ROOT / run_dir
    return {
        "base_dir": run_dir,
        "alerts_dir": run_dir / "alerts",
        "deployment_output_dir": run_dir / "deployment_output",
        "deployments": run_dir / "deployment_output" / "honeypot_deployments.json",
        "collected_alerts": run_dir / "deployment_output" / "collected_alerts.json",
        "step1": run_dir / "step1" / "unified_alerts.json",
        "canonical_events": run_dir / "step1" / "canonical_events.json",
        "step2": run_dir / "step2" / "causal_graph.json",
        "step2_mermaid": run_dir / "step2" / "causal_graph.mmd",
        "step2_triples": run_dir / "step2" / "step2_standard_triples.json",
        "step2_event_sequence": run_dir / "step2" / "step2_event_sequence.json",
        "step3": run_dir / "step3" / "pruned_graph.json",
        "step3_edge_labels": run_dir / "step3" / "edge_labels.json",
        "step3_checkpoint": REPO_ROOT / "step3_dqn_pruning" / "output" / "checkpoints" / "dqn_best.pt",
        "step4_intent": run_dir / "step4" / "llm_prompt_intent_analysis.txt",
        "step4_ttp": run_dir / "step4" / "llm_prompt_ttp_mapping.txt",
        "step4_report": run_dir / "step4" / "llm_prompt_report.txt",
        "step4_thesis": run_dir / "step4" / "thesis_analysis.md",
        "step4_llm_report": run_dir / "step4" / "llm_report.md",
        "step4_llm_report_meta": run_dir / "step4" / "llm_report_meta.json",
        "summary": run_dir / "summary.json",
    }


def ensure_dirs(paths):
    for key in ["alerts_dir", "deployment_output_dir"]:
        paths[key].mkdir(parents=True, exist_ok=True)
    for key in [
        "deployments",
        "collected_alerts",
        "step1",
        "canonical_events",
        "step2",
        "step2_mermaid",
        "step2_triples",
        "step2_event_sequence",
        "step3",
        "step3_edge_labels",
        "step4_intent",
        "step4_ttp",
        "step4_report",
        "step4_thesis",
        "step4_llm_report",
        "step4_llm_report_meta",
        "summary",
    ]:
        paths[key].parent.mkdir(parents=True, exist_ok=True)


def dump_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_graph_subset(graph_data, kept_edges, pruning_stats=None):
    node_ids = set()
    event_ids = set()
    for edge in kept_edges:
        if edge.get("source"):
            node_ids.add(edge["source"])
        if edge.get("target"):
            node_ids.add(edge["target"])
        if edge.get("event_id"):
            event_ids.add(edge["event_id"])

    nodes = [node for node in graph_data.get("nodes", []) if node.get("id") in node_ids]
    triples = []
    for triple in graph_data.get("triples", []):
        if isinstance(triple, dict) and triple.get("event_id") in event_ids:
            triples.append(triple)
    event_sequence = [
        item for item in graph_data.get("event_sequence", [])
        if item.get("event_id") in event_ids
    ]

    meta = dict(graph_data.get("graph_meta", {}))
    meta["node_count"] = len(nodes)
    meta["edge_count"] = len(kept_edges)
    meta["triple_count"] = len(triples)
    meta["relation_counts"] = dict(Counter(edge.get("relation_type") or "unknown" for edge in kept_edges))

    subset = {
        "graph_meta": meta,
        "nodes": nodes,
        "edges": kept_edges,
        "triples": triples,
        "event_sequence": event_sequence,
        "attacker_groups": graph_data.get("attacker_groups", []),
        "attack_paths": graph_data.get("attack_paths", []),
        "controlled_scenarios": graph_data.get("controlled_scenarios", []),
    }
    if pruning_stats is not None:
        subset["pruning_stats"] = pruning_stats
    return subset


def build_prompt_graph(graph_data, max_edges=MAX_PROMPT_EDGES):
    edges = graph_data.get("edges", [])
    if len(edges) <= max_edges:
        return graph_data
    prompt_edges = edges[-max_edges:]
    prompt_graph = build_graph_subset(graph_data, prompt_edges, pruning_stats=graph_data.get("pruning_stats", {}))
    prompt_graph["prompt_scope"] = {
        "edge_limit": max_edges,
        "original_edge_count": len(edges),
        "selected_recent_edges": len(prompt_edges),
    }
    return prompt_graph


def create_simulated_deployments():
    created_at = "2026-06-03T09:50:00"
    return [
        {
            "deployment_id": "deploy_file_001",
            "honeypot_type": "file",
            "agent_id": "localprobe01",
            "created_at": created_at,
            "bait_name": "2026_Q2_budget_plan.docx",
            "deploy_path": "/finance/share/2026_Q2_budget_plan.docx",
            "alert_sink": "alert_server:/contact/file-token-budget-001",
            "purpose": "Bait access to high-value business document",
        },
        {
            "deployment_id": "deploy_account_001",
            "honeypot_type": "account",
            "agent_id": "localprobe01",
            "created_at": created_at,
            "service": "ssh",
            "listen_port": 22,
            "bait_accounts": ["root", "opsadmin"],
            "alert_sink": "ssh-vpn/ssh_auth_log.json",
            "purpose": "Capture credential guessing and SSH client characteristics",
        },
        {
            "deployment_id": "deploy_parasitic_001",
            "honeypot_type": "parasitic",
            "agent_id": "localprobe01",
            "created_at": created_at,
            "target_dir": "/var/www/intranet",
            "inject_mode": "script_tag",
            "js_source": "js/latest/bot/static/inject.js",
            "alert_sink": "js/latest/bot log/database",
            "purpose": "Collect browser fingerprint and session behavior after web access",
        },
    ]


def create_simulated_honeypot_alerts():
    """Create a small but complete story covering all three honeypots."""
    base = datetime(2026, 6, 3, 10, 0, 0)
    attacker = "203.0.113.77"
    probe_host = "10.10.30.21"

    account_alerts = [
        UnifiedAlert(
            alert_id="sim_account_001",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=base,
            attacker_ip=attacker,
            target_host=probe_host,
            action="ssh_login",
            details={
                "protocol": "ssh",
                "attack_type": "SSH password authentication attempt",
                "username": "root",
                "password": "123456",
                "client_version": "SSH-2.0-libssh2_1.11.1",
                "client_family": "libssh2 scanner/automation tool",
                "src_port": "51244",
                "dst_port": "22",
            },
        ),
        UnifiedAlert(
            alert_id="sim_account_002",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=base + timedelta(minutes=2),
            attacker_ip=attacker,
            target_host=probe_host,
            action="ssh_login",
            details={
                "protocol": "ssh",
                "attack_type": "SSH password authentication attempt",
                "username": "opsadmin",
                "password": "Admin@2024",
                "client_version": "SSH-2.0-OpenSSH_8.9",
                "client_family": "OpenSSH client",
                "src_port": "51288",
                "dst_port": "22",
            },
        ),
    ]

    file_alerts = [
        UnifiedAlert(
            alert_id="sim_file_001",
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=base + timedelta(minutes=6),
            attacker_ip=attacker,
            target_path="/finance/share/2026_Q2_budget_plan.docx",
            action="file_access",
            details={
                "filename": "2026_Q2_budget_plan.docx",
                "token": "file-token-budget-001",
                "token_url": "http://127.0.0.1:9090/contact/file-token-budget-001",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "deployment_summary": f"{probe_host}:/finance/share/2026_Q2_budget_plan.docx",
            },
        ),
        UnifiedAlert(
            alert_id="sim_file_002",
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=base + timedelta(minutes=9),
            attacker_ip=attacker,
            target_path="/finance/share/vpn_accounts.xlsx",
            action="file_access",
            details={
                "filename": "vpn_accounts.xlsx",
                "token": "file-token-vpn-002",
                "token_url": "http://127.0.0.1:9090/contact/file-token-vpn-002",
                "user_agent": "curl/8.1.2",
                "deployment_summary": f"{probe_host}:/finance/share/vpn_accounts.xlsx",
            },
        ),
    ]

    parasitic_alerts = [
        UnifiedAlert(
            alert_id="sim_parasitic_001",
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=base + timedelta(minutes=12),
            attacker_ip=attacker,
            target_path="http://intranet.local/login.html",
            action="url_access",
            details={
                "fingerprint": "fp-win-chrome-8842",
                "url": "http://intranet.local/login.html",
                "browser": "Chrome 121",
                "os": "Windows 10",
                "user_agent": "Mozilla/5.0 Chrome/121.0",
                "session_id": "sess-sim-001",
                "real_ips": ["192.168.56.20"],
                "test_info": "Injected JS beacon collected browser fingerprint and session metadata",
            },
            session_id="sess-sim-001",
        ),
        UnifiedAlert(
            alert_id="sim_parasitic_002",
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=base + timedelta(minutes=14),
            attacker_ip=attacker,
            target_path="http://intranet.local/admin.html",
            action="url_access",
            details={
                "fingerprint": "fp-win-chrome-8842",
                "url": "http://intranet.local/admin.html",
                "browser": "Chrome 121",
                "os": "Windows 10",
                "user_agent": "Mozilla/5.0 Chrome/121.0",
                "session_id": "sess-sim-001",
                "real_ips": ["192.168.56.20"],
                "test_info": "Same browser fingerprint revisited a higher-value page",
            },
            session_id="sess-sim-001",
        ),
    ]

    audit_alerts = [
        UnifiedAlert(
            alert_id="sim_audit_001",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=base + timedelta(minutes=16),
            action="execve",
            target_path="/usr/bin/cat",
            process_info={"pid": "4201", "ppid": "4190", "exe": "/usr/bin/cat", "user": "opsadmin"},
            details={"reason": "attacker tried reading collected credential file"},
        ),
        UnifiedAlert(
            alert_id="sim_audit_002",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=base + timedelta(minutes=16, seconds=15),
            action="read",
            target_path="/finance/share/vpn_accounts.xlsx",
            process_info={"pid": "4201", "ppid": "4190", "exe": "/usr/bin/cat", "user": "opsadmin"},
            details={"reason": "file honeypot bait was opened from shell"},
        ),
        UnifiedAlert(
            alert_id="sim_audit_003",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=base + timedelta(minutes=18),
            action="openat",
            target_path="/tmp/browser-cache.tmp",
            process_info={"pid": "4205", "ppid": "4190", "exe": "/usr/bin/browser-helper", "user": "opsadmin"},
            details={"reason": "low-value local cache access used as pruning noise"},
        ),
        UnifiedAlert(
            alert_id="sim_audit_004",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=base + timedelta(minutes=19),
            action="write",
            target_path="/tmp/session.tmp",
            process_info={"pid": "4206", "ppid": "4190", "exe": "/usr/bin/browser-helper", "user": "opsadmin"},
            details={"reason": "low-value temporary write used as pruning noise"},
        ),
        UnifiedAlert(
            alert_id="sim_audit_005",
            alert_type=AlertType.AUDIT_EVENT,
            timestamp=base + timedelta(minutes=20),
            action="connect",
            target_path="198.51.100.23:443",
            process_info={"pid": "4210", "ppid": "4190", "exe": "/usr/bin/curl", "user": "opsadmin"},
            details={"reason": "possible command-and-control or exfiltration connection"},
        ),
    ]

    return {
        "file": file_alerts,
        "account": account_alerts,
        "parasitic": parasitic_alerts,
        "audit": audit_alerts,
    }


def alert_to_dict(alert: UnifiedAlert):
    return alert.to_dict()


def _to_alert_objects(alerts):
    items = []
    for alert in alerts:
        if isinstance(alert, UnifiedAlert):
            items.append(alert)
        else:
            data = dict(alert)
            event_type = data.get("alert_type")
            if isinstance(event_type, AlertType):
                alert_type = event_type
            else:
                alert_type = AlertType(event_type)
            timestamp = data.get("timestamp")
            if isinstance(timestamp, datetime):
                ts = timestamp
            else:
                ts = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            items.append(
                UnifiedAlert(
                    alert_id=data.get("alert_id") or "",
                    alert_type=alert_type,
                    timestamp=ts,
                    attacker_ip=data.get("attacker_ip"),
                    attacker_info=data.get("attacker_info"),
                    target_host=data.get("target_host"),
                    target_path=data.get("target_path"),
                    action=data.get("action"),
                    details=data.get("details") or {},
                    session_id=data.get("session_id"),
                    process_info=data.get("process_info"),
                    source_type=data.get("source_type"),
                    source_id=data.get("source_id"),
                    source_label=data.get("source_label"),
                    object_type=data.get("object_type"),
                    object_id=data.get("object_id"),
                    object_label=data.get("object_label"),
                    stage=data.get("stage"),
                    tactic=data.get("tactic"),
                    technique=data.get("technique"),
                    confidence=float(data.get("confidence", 0.8)),
                    severity=data.get("severity", "medium"),
                    source_intel=data.get("source_intel") or {},
                    actor_intel=data.get("actor_intel") or {},
                    evidence=data.get("evidence") or {},
                )
            )
    return items


def _alert_type_value(alert: UnifiedAlert) -> str:
    return alert.alert_type.value if isinstance(alert.alert_type, AlertType) else str(alert.alert_type)


def _actor_group_id(alert: UnifiedAlert) -> str:
    actor_intel = alert.actor_intel or {}
    return str(actor_intel.get("group_id") or "").strip()


def _is_cross_honeypot_actor(alert: UnifiedAlert) -> bool:
    actor_intel = alert.actor_intel or {}
    return bool(actor_intel.get("cross_honeypot"))


def _is_excluded_source(alert: UnifiedAlert, excluded_ips) -> bool:
    ip = str(alert.attacker_ip or "").strip()
    return bool(ip and ip in excluded_ips)


def build_balanced_alert_subset(live_alerts: List[UnifiedAlert], per_type: int, exclude_ips=None):
    """Build a real-data balanced analysis subset without fabricating alerts."""
    if per_type <= 0:
        return [], {
            "enabled": False,
            "reason": "balanced_per_type_not_set",
        }

    excluded_ips = {str(item).strip() for item in (exclude_ips or []) if str(item).strip()}
    allowed_types = ["account", "file", "parasitic"]
    filtered_alerts = [
        alert for alert in live_alerts
        if _alert_type_value(alert) in allowed_types and not _is_excluded_source(alert, excluded_ips)
    ]

    selected = []
    selected_ids = set()
    selected_counts = Counter()

    def add_alert(alert: UnifiedAlert) -> bool:
        alert_type = _alert_type_value(alert)
        if alert_type not in allowed_types:
            return False
        if alert.alert_id in selected_ids:
            return False
        if selected_counts[alert_type] >= per_type:
            return False
        selected.append(alert)
        selected_ids.add(alert.alert_id)
        selected_counts[alert_type] += 1
        return True

    actor_groups = defaultdict(list)
    for alert in filtered_alerts:
        group_id = _actor_group_id(alert)
        if group_id and _is_cross_honeypot_actor(alert):
            actor_groups[group_id].append(alert)

    sorted_groups = sorted(
        actor_groups.values(),
        key=lambda group: (
            -len({_alert_type_value(alert) for alert in group}),
            min(alert.timestamp for alert in group),
        ),
    )
    for group in sorted_groups:
        for alert in sorted(group, key=lambda item: item.timestamp):
            add_alert(alert)

    by_type = defaultdict(list)
    for alert in filtered_alerts:
        by_type[_alert_type_value(alert)].append(alert)

    for alert_type in allowed_types:
        for alert in sorted(by_type.get(alert_type, []), key=lambda item: item.timestamp, reverse=True):
            if selected_counts[alert_type] >= per_type:
                break
            add_alert(alert)

    selected.sort(key=lambda item: item.timestamp)
    available_counts = Counter(_alert_type_value(alert) for alert in filtered_alerts)
    raw_counts = Counter(_alert_type_value(alert) for alert in live_alerts)
    raw_count_map = {alert_type: raw_counts.get(alert_type, 0) for alert_type in allowed_types}
    available_count_map = {alert_type: available_counts.get(alert_type, 0) for alert_type in allowed_types}
    selected_count_map = {alert_type: selected_counts.get(alert_type, 0) for alert_type in allowed_types}
    metadata = {
        "enabled": True,
        "method": "real_alert_downsample_with_cross_honeypot_priority",
        "per_type_limit": per_type,
        "exclude_ips": sorted(excluded_ips),
        "raw_counts": raw_count_map,
        "available_counts_after_exclusion": available_count_map,
        "selected_counts": selected_count_map,
        "selected_total": len(selected),
        "missing_types_after_exclusion": [
            alert_type for alert_type, count in available_count_map.items() if count == 0
        ],
        "underfilled_types": [
            alert_type for alert_type, count in selected_count_map.items()
            if 0 < count < per_type
        ],
        "is_full_balanced": all(count >= per_type for count in selected_count_map.values()),
        "cross_honeypot_actor_groups": len(actor_groups),
        "note": "No alerts are fabricated; this subset only filters and samples real collected alerts.",
    }
    return selected, metadata


def write_split_and_unified(alert_groups, paths, deployments=None):
    ensure_dirs(paths)
    if deployments is not None:
        dump_json(paths["deployments"], deployments)

    split_paths = {
        "file": paths["alerts_dir"] / "file_alerts.json",
        "account": paths["alerts_dir"] / "account_alerts.json",
        "parasitic": paths["alerts_dir"] / "parasitic_alerts.json",
        "audit": paths["alerts_dir"] / "audit_alerts.json",
    }

    all_alerts = []
    canonical_events = []
    for name, alerts in alert_groups.items():
        objects = _to_alert_objects(alerts)
        data = [alert_to_dict(a) for a in objects]
        dump_json(split_paths[name], data)
        all_alerts.extend(data)
        canonical_events.extend([alert.to_canonical_event() for alert in objects])

    all_alerts.sort(key=lambda item: item.get("timestamp") or "")
    canonical_events.sort(key=lambda item: item.get("timestamp") or "")
    dump_json(paths["collected_alerts"], all_alerts)
    dump_json(paths["step1"], all_alerts)
    dump_json(paths["canonical_events"], canonical_events)
    return all_alerts, split_paths


def simulate_pruning(graph_data, paths, fallback_reason=None):
    important_actions = {"ssh_login", "file_access", "url_access", "read", "connect", "execve"}
    important_relations = {
        "web_to_account",
        "account_to_file",
        "web_to_file",
        "stage_transition",
        "controlled_chain_member",
        "same_fingerprint",
        "same_session",
    }
    edges = graph_data.get("edges", [])
    kept = [
        edge for edge in edges
        if edge.get("action") in important_actions or edge.get("relation_type") in important_relations
    ]
    if not kept and edges:
        kept = edges[-1:]

    capped = False
    if len(kept) > MAX_SIMULATED_KEPT_EDGES:
        kept = kept[-MAX_SIMULATED_KEPT_EDGES:]
        capped = True

    pruning_stats = {
        "mode": "deterministic_simulation",
        "original_edges": len(edges),
        "kept_edges": len(kept),
        "pruned_edges": max(len(edges) - len(kept), 0),
        "compression_ratio": f"{(100 * (len(edges) - len(kept)) / len(edges)):.1f}%" if edges else "0.0%",
        "kept_edge_cap_applied": capped,
    }
    if fallback_reason:
        pruning_stats["fallback_reason"] = fallback_reason
    pruned = build_graph_subset(graph_data, kept, pruning_stats=pruning_stats)
    dump_json(paths["step3"], pruned)
    return pruned


def build_edge_labels_from_scenario(graph_data: Dict[str, Any]) -> Dict[str, int]:
    """Create edge labels for controlled-scenario evaluation.

    Label semantics:
    - 1: core controlled-chain edge that should be kept
    - 0: controlled-noise edge that should be pruned
    """
    labels = {}
    core_relations = {
        "web_to_account",
        "account_to_file",
        "web_to_file",
        "stage_transition",
        "controlled_chain_member",
        "same_fingerprint",
        "same_session",
    }
    for edge in graph_data.get("edges", []):
        edge_id = edge.get("edge_id")
        if not edge_id:
            continue
        role = edge.get("scenario_role")
        relation = edge.get("relation_type")
        if role == "controlled_chain":
            labels[edge_id] = 1
        elif role == "controlled_noise":
            labels[edge_id] = 0
        elif relation in core_relations:
            labels[edge_id] = 1
    return labels


def write_edge_labels(graph_data: Dict[str, Any], paths) -> Dict[str, Any]:
    labels = build_edge_labels_from_scenario(graph_data)
    dump_json(paths["step3_edge_labels"], labels)
    counts = Counter(labels.values())
    return {
        "file": rel(paths["step3_edge_labels"]),
        "labeled_edges": len(labels),
        "core_edges": int(counts.get(1, 0)),
        "noise_edges": int(counts.get(0, 0)),
        "label_semantics": {
            "1": "controlled attack-chain edge to keep",
            "0": "controlled background/noise edge to prune",
        },
    }


def evaluate_pruned_graph_against_labels(graph_data: Dict[str, Any], pruned_data: Dict[str, Any], labels: Dict[str, int]) -> Dict[str, Any]:
    if not labels:
        return {
            "enabled": False,
            "reason": "no_controlled_scenario_labels",
        }

    kept_edge_ids = {str(edge.get("edge_id")) for edge in pruned_data.get("edges", []) if edge.get("edge_id")}
    graph_edge_ids = {str(edge.get("edge_id")) for edge in graph_data.get("edges", []) if edge.get("edge_id")}
    core_ids = {edge_id for edge_id, label in labels.items() if int(label) == 1 and edge_id in graph_edge_ids}
    noise_ids = {edge_id for edge_id, label in labels.items() if int(label) == 0 and edge_id in graph_edge_ids}

    kept_core = len(core_ids & kept_edge_ids)
    pruned_core = len(core_ids - kept_edge_ids)
    pruned_noise = len(noise_ids - kept_edge_ids)
    kept_noise = len(noise_ids & kept_edge_ids)
    kept_labeled = kept_core + kept_noise

    return {
        "enabled": True,
        "label_file": "",
        "labeled_edges": len(core_ids) + len(noise_ids),
        "core_edges": len(core_ids),
        "noise_edges": len(noise_ids),
        "kept_core_edges": kept_core,
        "pruned_core_edges": pruned_core,
        "pruned_noise_edges": pruned_noise,
        "kept_noise_edges": kept_noise,
        "core_chain_recall": kept_core / max(len(core_ids), 1),
        "noise_filter_rate": pruned_noise / max(len(noise_ids), 1),
        "kept_edge_precision_on_labels": kept_core / max(kept_labeled, 1),
        "interpretation": "Metrics are valid for controlled-scenario labels only; they are not raw internet prevalence metrics.",
    }


def apply_controlled_label_guardrail(graph_data: Dict[str, Any], pruned_data: Dict[str, Any], labels: Dict[str, int]) -> Dict[str, Any]:
    """Restore controlled core-chain edges if a model checkpoint prunes them.

    This is an evidence constraint, not a synthetic-data step: the restored edges
    already exist in the original graph and are labeled as core by the controlled
    experiment design.
    """
    if not labels:
        return pruned_data

    edge_by_id = {
        str(edge.get("edge_id")): edge
        for edge in graph_data.get("edges", [])
        if edge.get("edge_id")
    }
    kept_ids = {
        str(edge.get("edge_id"))
        for edge in pruned_data.get("edges", [])
        if edge.get("edge_id")
    }
    restore_ids = [
        edge_id for edge_id, label in labels.items()
        if int(label) == 1 and edge_id in edge_by_id and edge_id not in kept_ids
    ]
    if not restore_ids:
        return pruned_data

    restored = set(restore_ids)
    kept_edges = [
        edge for edge in graph_data.get("edges", [])
        if str(edge.get("edge_id")) in kept_ids or str(edge.get("edge_id")) in restored
    ]
    stats = dict(pruned_data.get("pruning_stats", {}))
    original_edges = len(graph_data.get("edges", []))
    kept_count = len(kept_edges)
    pruned_count = max(original_edges - kept_count, 0)
    stats.update({
        "mode": f"{stats.get('mode', 'unknown')}_with_controlled_evidence_guardrail",
        "original_edges": original_edges,
        "kept_edges": kept_count,
        "pruned_edges": pruned_count,
        "compression_ratio": f"{(100 * pruned_count / original_edges):.1f}%" if original_edges else "0.0%",
        "evidence_guardrail_enabled": True,
        "restored_core_edges": len(restore_ids),
        "guardrail_note": "Restored controlled core-chain edges that already existed in the original graph and were marked as core evidence.",
    })
    guarded = build_graph_subset(graph_data, kept_edges, pruning_stats=stats)
    guarded["controlled_label_guardrail"] = {
        "enabled": True,
        "restored_core_edges": restore_ids,
        "note": "Evidence-constrained pruning protects controlled attack-chain labels from accidental model pruning.",
    }
    return guarded


def run_dqn_pruning(paths, graph_data):
    if len(graph_data.get("edges", [])) > MAX_DQN_EDGES:
        return None, f"edge_count_exceeds_{MAX_DQN_EDGES}"

    checkpoint = paths.get("step3_checkpoint")
    if not checkpoint or not checkpoint.exists():
        return None, "dqn_checkpoint_missing"

    if not _load_dqn_tools():
        reason = "dqn_dependencies_unavailable"
        if DQN_IMPORT_ERROR:
            reason = f"{reason}: {DQN_IMPORT_ERROR}"
        return None, reason

    try:
        import torch
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", "") == "torch":
            return None, f"torch_not_installed: {exc}"
        raise

    try:
        trainer = DQNTrainer(device="cpu")
        state = torch.load(checkpoint, map_location="cpu")
        trainer.model.load_state_dict(state)
        pruned = trainer.predict_and_prune(str(paths["step2"]), str(paths["step3"]))
        stats = pruned.get("pruning_stats", {})
        stats["mode"] = "dqn_checkpoint"
        stats["checkpoint"] = rel(checkpoint)
        pruned["pruning_stats"] = stats
        dump_json(paths["step3"], pruned)
        return pruned, None
    except MemoryError:
        return None, "dqn_out_of_memory"
    except Exception as exc:
        print(f"[-] DQN pruning failed, fallback to deterministic pruning: {exc}")
        return None, f"dqn_runtime_error: {exc}"


def write_step4_outputs(paths, graph_data, pruned):
    analysis_graph = build_prompt_graph(deepcopy(graph_data))
    analysis_graph["pruning_stats"] = pruned.get("pruning_stats", {})
    analysis_graph["pruned_graph_meta"] = pruned.get("graph_meta", {})
    analysis_graph["pruned_edge_count"] = len(pruned.get("edges", []))
    analysis_graph["pruned_node_count"] = len(pruned.get("nodes", []))
    analysis_graph["pruned_relation_counts"] = dict(
        Counter(edge.get("relation_type") or edge.get("action") or "unknown" for edge in pruned.get("edges", []))
    )
    if pruned.get("controlled_label_eval"):
        analysis_graph["controlled_label_eval"] = pruned.get("controlled_label_eval")
    if pruned.get("controlled_label_guardrail"):
        analysis_graph["controlled_label_guardrail"] = pruned.get("controlled_label_guardrail")
    converter = GraphToTextConverter()
    prompts = {
        "intent_analysis": converter.convert_to_llm_prompt(analysis_graph, "intent_analysis"),
        "ttp_mapping": converter.convert_to_llm_prompt(analysis_graph, "ttp_mapping"),
        "report": converter.convert_to_llm_prompt(analysis_graph, "report"),
        "thesis_analysis": converter.convert_to_thesis_analysis(analysis_graph),
    }
    converter.save(prompts["intent_analysis"], str(paths["step4_intent"]))
    converter.save(prompts["ttp_mapping"], str(paths["step4_ttp"]))
    converter.save(prompts["report"], str(paths["step4_report"]))
    converter.save(prompts["thesis_analysis"], str(paths["step4_thesis"]))
    return graph_data, pruned, prompts


def run_steps_from_unified(alerts, paths):
    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(alerts)
    dump_json(paths["step2"], graph_data)
    dump_json(paths["step2_triples"], graph_data.get("triples", []))
    dump_json(paths["step2_event_sequence"], graph_data.get("event_sequence", []))
    graph_title = "Live Honeypot Attack Graph" if alerts else "Empty Honeypot Attack Graph"
    CausalGraphVisualizer.save_mermaid(graph_data, str(paths["step2_mermaid"]), title=graph_title)

    pruned, fallback_reason = run_dqn_pruning(paths, graph_data)
    if pruned is None:
        pruned = simulate_pruning(graph_data, paths, fallback_reason=fallback_reason)
    return write_step4_outputs(paths, graph_data, pruned)


def summarize(alerts, graph_data, pruned, split_paths, paths, mode, deployments=None) -> Dict[str, Any]:
    type_counts = Counter(a.get("alert_type") for a in alerts)
    for alert_type in ("file", "account", "parasitic"):
        type_counts.setdefault(alert_type, 0)
    action_counts = Counter(e.get("action") for e in graph_data.get("edges", []))
    missing_alert_types = [
        alert_type for alert_type in ("file", "account", "parasitic")
        if type_counts.get(alert_type, 0) == 0
    ]
    summary = {
        "mode": mode,
        "generated_at": datetime.now().isoformat(),
        "deployment_count": len(deployments or []),
        "alert_counts": dict(type_counts),
        "total_alerts": len(alerts),
        "data_quality": {
            "required_honeypot_types": ["file", "account", "parasitic"],
            "missing_alert_types": missing_alert_types,
            "has_all_honeypot_types": len(missing_alert_types) == 0,
            "note": (
                "Raw live analysis preserves the real deployment distribution. "
                "Balanced analysis should be used for fair cross-honeypot evaluation when classes are missing or skewed."
            ),
        },
        "graph": {
            "nodes": len(graph_data.get("nodes", [])),
            "edges": len(graph_data.get("edges", [])),
            "event_edges": graph_data.get("graph_meta", {}).get("event_edge_count", 0),
            "correlation_edges": graph_data.get("graph_meta", {}).get("correlation_edge_count", 0),
            "triples": len(graph_data.get("triples", [])),
            "event_sequence": len(graph_data.get("event_sequence", [])),
            "attack_paths": len(graph_data.get("attack_paths", [])),
            "edge_actions": dict(action_counts),
            "relation_counts": graph_data.get("graph_meta", {}).get("relation_counts", {}),
            "controlled_scenarios": graph_data.get("controlled_scenarios", []),
        },
        "pruning_stats": pruned.get("pruning_stats", {}),
        "controlled_label_eval": pruned.get("controlled_label_eval", {}),
        "outputs": {
            "honeypot_deployments": rel(paths["deployments"]),
            "file_alerts": rel(split_paths.get("file", Path())) if split_paths.get("file") else "",
            "account_alerts": rel(split_paths.get("account", Path())) if split_paths.get("account") else "",
            "parasitic_alerts": rel(split_paths.get("parasitic", Path())) if split_paths.get("parasitic") else "",
            "audit_alerts": rel(split_paths.get("audit", Path())) if split_paths.get("audit") else "",
            "collected_alerts": rel(paths["collected_alerts"]),
            "step1_unified_alerts": rel(paths["step1"]),
            "step1_canonical_events": rel(paths["canonical_events"]),
            "step2_causal_graph": rel(paths["step2"]),
            "step2_mermaid": rel(paths["step2_mermaid"]),
            "step2_standard_triples": rel(paths["step2_triples"]),
            "step2_event_sequence": rel(paths["step2_event_sequence"]),
            "step3_pruned_graph": rel(paths["step3"]),
            "step3_edge_labels": rel(paths["step3_edge_labels"]) if paths["step3_edge_labels"].exists() else "",
            "step4_intent_analysis": rel(paths["step4_intent"]),
            "step4_ttp_mapping": rel(paths["step4_ttp"]),
            "step4_report": rel(paths["step4_report"]),
            "step4_thesis_analysis": rel(paths["step4_thesis"]),
            "step4_llm_report": rel(paths["step4_llm_report"]),
            "step4_llm_report_meta": rel(paths["step4_llm_report_meta"]),
        },
    }
    dump_json(paths["summary"], summary)
    return summary


def copy_run_to_defaults(source_paths):
    default_paths = build_default_paths()
    ensure_dirs(default_paths)
    mapping = [
        (source_paths["deployments"], default_paths["deployments"]),
        (source_paths["collected_alerts"], default_paths["collected_alerts"]),
        (source_paths["step1"], default_paths["step1"]),
        (source_paths["canonical_events"], default_paths["canonical_events"]),
        (source_paths["step2"], default_paths["step2"]),
        (source_paths["step2_mermaid"], default_paths["step2_mermaid"]),
        (source_paths["step2_triples"], default_paths["step2_triples"]),
        (source_paths["step2_event_sequence"], default_paths["step2_event_sequence"]),
        (source_paths["step3"], default_paths["step3"]),
        (source_paths["step4_intent"], default_paths["step4_intent"]),
        (source_paths["step4_ttp"], default_paths["step4_ttp"]),
        (source_paths["step4_report"], default_paths["step4_report"]),
        (source_paths["step4_thesis"], default_paths["step4_thesis"]),
        (source_paths["summary"], default_paths["summary"]),
    ]
    optional_mapping = [
        (source_paths.get("step3_edge_labels"), default_paths.get("step3_edge_labels")),
        (source_paths.get("step4_llm_report"), default_paths.get("step4_llm_report")),
        (source_paths.get("step4_llm_report_meta"), default_paths.get("step4_llm_report_meta")),
    ]
    for name in ["file_alerts.json", "account_alerts.json", "parasitic_alerts.json", "audit_alerts.json"]:
        mapping.append((source_paths["alerts_dir"] / name, default_paths["alerts_dir"] / name))
    for src, dst in mapping:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    for src, dst in optional_mapping:
        if src and dst and src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
    return default_paths


def _resolve_repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def _set_reproducible_seed(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except Exception:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except Exception:
        pass


def _split_graphs(graphs, seed: int):
    graphs = list(graphs)
    random.Random(seed).shuffle(graphs)
    total = len(graphs)
    if total == 0:
        return [], [], []
    if total == 1:
        return graphs, graphs, graphs
    if total == 2:
        return graphs[:1], graphs[1:], graphs[1:]

    train_count = max(1, int(total * 0.7))
    val_count = max(1, int(total * 0.15))
    if train_count + val_count >= total:
        train_count = max(1, total - 2)
        val_count = 1
    train_graphs = graphs[:train_count]
    val_graphs = graphs[train_count:train_count + val_count]
    test_graphs = graphs[train_count + val_count:]
    return train_graphs, val_graphs, test_graphs or val_graphs


def _pruning_metrics_from_actions(actions, labels):
    pairs = [(int(action), int(label)) for action, label in zip(actions, labels) if int(label) >= 0]
    if not pairs:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "core_recall": 0.0,
            "ckc": 0.0,
            "cpr": 0.0,
            "wpc": 0.0,
            "wkr": 0.0,
            "labeled_edges": 0.0,
            "label_coverage": 0.0,
        }

    ckc = sum(1 for action, label in pairs if action == 0 and label == 1)
    cpr = sum(1 for action, label in pairs if action == 1 and label == 0)
    wpc = sum(1 for action, label in pairs if action == 1 and label == 1)
    wkr = sum(1 for action, label in pairs if action == 0 and label == 0)
    total = max(len(pairs), 1)
    accuracy = (ckc + cpr) / total
    precision = cpr / max(cpr + wpc, 1)
    recall = cpr / max(cpr + wkr, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    core_recall = ckc / max(ckc + wpc, 1)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "core_recall": core_recall,
        "ckc": float(ckc),
        "cpr": float(cpr),
        "wpc": float(wpc),
        "wkr": float(wkr),
        "labeled_edges": float(total),
        "label_coverage": 1.0,
    }


def _evaluate_action_rule_baseline(graphs):
    important_actions = {"ssh_login", "vpn_connect", "file_access", "url_access", "execve", "connect", "read"}
    important_relations = {
        "web_to_account",
        "account_to_file",
        "web_to_file",
        "stage_transition",
        "controlled_chain_member",
        "same_fingerprint",
        "same_session",
    }
    metrics = []
    for graph in graphs:
        labels = getattr(graph, "y", None)
        edges_info = getattr(graph, "edges_info", [])
        if labels is None:
            continue
        label_values = labels.long().cpu().tolist()
        actions = [
            0 if edge.get("action") in important_actions or edge.get("relation_type") in important_relations else 1
            for edge in edges_info
        ]
        metrics.append(_pruning_metrics_from_actions(actions, label_values))
    if not metrics:
        return _pruning_metrics_from_actions([], [])
    return {key: sum(item[key] for item in metrics) / len(metrics) for key in metrics[0]}


def _install_dqn_checkpoint(checkpoint_path: Path):
    target = build_default_paths()["step3_checkpoint"]
    target.parent.mkdir(parents=True, exist_ok=True)
    result = {"installed_checkpoint": rel(target)}
    if target.exists():
        backup = target.with_name(f"{target.stem}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}{target.suffix}")
        backup.write_bytes(target.read_bytes())
        result["previous_checkpoint_backup"] = rel(backup)
    target.write_bytes(checkpoint_path.read_bytes())
    return result


def _read_label_class_counts(label_file: Path) -> Dict[str, int]:
    with open(label_file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    values = []
    if isinstance(payload, dict):
        values = list(payload.values())
    elif isinstance(payload, list):
        values = [item.get("label") for item in payload if isinstance(item, dict) and item.get("label") is not None]

    counts = Counter()
    for value in values:
        try:
            label = str(int(float(value)))
        except (TypeError, ValueError):
            label = "other"
        counts[label] += 1
    return {key: int(counts.get(key, 0)) for key in ["1", "0", "other"]}


def _apply_manual_labels_to_training_graphs(graphs, label_file: Path):
    """Overlay controlled-scenario labels onto weak labels for DQN training."""
    labeled_graphs = []
    coverages = []
    for graph in graphs:
        weak_labels = graph.y.clone() if hasattr(graph, "y") and graph.y is not None else None
        labeled = attach_manual_labels(graph, str(label_file), strict=False)
        coverage = getattr(labeled, "manual_label_coverage", None)
        if coverage is not None:
            coverages.append(float(coverage))
        if weak_labels is not None:
            missing_mask = labeled.y < 0
            labeled.y[missing_mask] = weak_labels[missing_mask]
        labeled_graphs.append(labeled)
    avg_coverage = sum(coverages) / len(coverages) if coverages else 0.0
    return labeled_graphs, avg_coverage


def train_dqn_experiment(
    graph_path: Path,
    output_dir: Path,
    num_graphs: int,
    epochs: int,
    patience: int,
    lr: float,
    seed: int,
    augment: bool,
    label_file: Path = None,
    train_with_manual_labels: bool = False,
    require_label_balance: bool = False,
    install_checkpoint: bool = False,
    device: str = "cpu",
):
    if not _load_dqn_tools() or load_graphs_for_training is None:
        reason = f"step3 DQN dependencies unavailable: {DQN_IMPORT_ERROR}"
        raise RuntimeError(reason)

    graph_path = _resolve_repo_path(graph_path)
    output_dir = _resolve_repo_path(output_dir)
    label_file = _resolve_repo_path(label_file) if label_file else None
    if not graph_path.exists():
        raise FileNotFoundError(f"graph path not found: {graph_path}")
    if label_file and not label_file.exists():
        raise FileNotFoundError(f"label file not found: {label_file}")
    manual_label_class_counts = _read_label_class_counts(label_file) if label_file else {}
    label_balance_warning = ""
    if train_with_manual_labels:
        if not label_file:
            raise ValueError("--train-with-manual-labels requires --label-file")
        has_core = manual_label_class_counts.get("1", 0) > 0
        has_noise = manual_label_class_counts.get("0", 0) > 0
        if not has_core or not has_noise:
            label_balance_warning = (
                "manual labels do not contain both core edges (1) and noise edges (0); "
                "this run can validate chain retention but should not be claimed as a full pruning experiment"
            )
            if require_label_balance:
                raise ValueError(label_balance_warning)

    _set_reproducible_seed(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output_dir / "checkpoints" / "dqn_best.pt"
    pruned_path = output_dir / "pruned_graph.json"
    summary_path = output_dir / "dqn_experiment_summary.json"
    thesis_path = output_dir / "thesis_analysis_after_dqn.md"

    graphs = load_graphs_for_training(
        str(graph_path),
        num_graphs=num_graphs,
        augment=augment,
        base_seed=seed,
    )
    training_manual_label_coverage = None
    if train_with_manual_labels:
        graphs, training_manual_label_coverage = _apply_manual_labels_to_training_graphs(graphs, label_file)
    train_graphs, val_graphs, test_graphs = _split_graphs(graphs, seed)

    trainer_device = None if str(device).lower() == "auto" else device
    trainer = DQNTrainer(lr=lr, epochs=epochs, patience=patience, device=trainer_device)
    trainer.train(train_graphs, val_graphs, save_path=str(checkpoint_path))

    train_metrics = trainer._evaluate(train_graphs)
    val_metrics = trainer._evaluate(val_graphs)
    test_metrics = trainer.evaluate_on_test(test_graphs)
    baseline_metrics = _evaluate_action_rule_baseline(test_graphs)

    manual_metrics = None
    manual_label_coverage = None
    if label_file:
        manual_graph = attach_manual_labels(load_graph_from_file(str(graph_path)), str(label_file), strict=False)
        manual_label_coverage = getattr(manual_graph, "manual_label_coverage", None)
        manual_metrics = trainer.evaluate_on_test([manual_graph])

    pruned = trainer.predict_and_prune(str(graph_path), str(pruned_path))
    stats = pruned.get("pruning_stats", {})
    stats["mode"] = "dqn_reproducible_experiment"
    stats["checkpoint"] = rel(checkpoint_path)
    pruned["pruning_stats"] = stats
    dump_json(pruned_path, pruned)

    converter = GraphToTextConverter()
    converter.save(converter.convert_to_thesis_analysis(pruned), str(thesis_path))

    install_info = _install_dqn_checkpoint(checkpoint_path) if install_checkpoint else {}
    summary = {
        "mode": "train-dqn",
        "generated_at": datetime.now().isoformat(),
        "graph_path": rel(graph_path),
        "output_dir": rel(output_dir),
        "config": {
            "seed": seed,
            "num_graphs": num_graphs,
            "augment": augment,
            "epochs": epochs,
            "patience": patience,
            "lr": lr,
            "device": device,
            "label_source": (
                "manual_controlled_labels_override_weak_labels"
                if train_with_manual_labels
                else "deterministic_weak_labels"
            ),
            "manual_label_eval_file": rel(label_file) if label_file else "",
            "manual_labels_used_for_training": bool(train_with_manual_labels),
            "training_manual_label_coverage": training_manual_label_coverage,
            "manual_label_class_counts": manual_label_class_counts,
            "label_balance_warning": label_balance_warning,
            "require_label_balance": bool(require_label_balance),
        },
        "splits": {
            "train_graphs": len(train_graphs),
            "validation_graphs": len(val_graphs),
            "test_graphs": len(test_graphs),
        },
        "graph_statistics": get_graph_statistics(str(graph_path)),
        "metrics": {
            "train": train_metrics,
            "validation": val_metrics,
            "test": test_metrics,
            "action_rule_baseline_test": baseline_metrics,
            "manual_label_eval": manual_metrics,
            "manual_label_coverage": manual_label_coverage,
        },
        "outputs": {
            "checkpoint": rel(checkpoint_path),
            "pruned_graph": rel(pruned_path),
            "thesis_analysis_after_dqn": rel(thesis_path),
            "summary": rel(summary_path),
            **install_info,
        },
        "note": (
            "By default labels are deterministic weak labels derived from edge actions. "
            "When --train-with-manual-labels is set, controlled-scenario labels override weak labels "
            "for matching edge_ids and unmatched edges retain weak labels for trainability."
        ),
    }
    dump_json(summary_path, summary)
    print_summary({
        "mode": "train-dqn",
        "deployment_count": 0,
        "total_alerts": 0,
        "alert_counts": {},
        "graph": {
            "nodes": summary["graph_statistics"]["num_nodes"],
            "edges": summary["graph_statistics"]["num_edges"],
        },
        "pruning_stats": pruned.get("pruning_stats", {}),
        "outputs": summary["outputs"],
    })
    print(f"DQN metrics: {json.dumps(summary['metrics'], ensure_ascii=False)}")
    return summary


def simulate(run_dir: Path, write_defaults: bool):
    paths = build_run_paths(run_dir)
    deployments = create_simulated_deployments()
    groups = enrich_simulated_alert_groups(create_simulated_honeypot_alerts())
    alerts, split_paths = write_split_and_unified(groups, paths, deployments=deployments)
    graph_data, pruned, _prompts = run_steps_from_unified(alerts, paths)
    if write_defaults:
        copy_run_to_defaults(paths)
    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "simulate", deployments=deployments)
    print_summary(summary)
    return summary


def export_live(hours: int, run_dir: Path = None):
    paths = build_run_paths(run_dir) if run_dir else build_default_paths()
    ensure_dirs(paths)
    end_time = datetime.now()
    start_time = None if hours <= 0 else end_time - timedelta(hours=hours)
    collector = DataCollector(config=build_live_analysis_collector_config())
    collector_sources = collector.describe_sources()
    try:
        live_alerts = collect_live_alerts_from_systemwire2_api(hours)
        collector_sources["analysis_source_mode"] = "systemwire2_unified_api"
        collector_sources["analysis_source_detail"] = "flask_server.alert_store.build_unified_alert_api_rows"
    except Exception as exc:
        print(f"[-] unified API export path unavailable, fallback to unified store collector: {exc}")
        live_alerts = collector.collect_all(start_time, end_time)
        collector_sources["analysis_source_mode"] = "systemwire2_unified_store_fallback"
        collector_sources["analysis_source_detail"] = str(exc)
    alerts = [a.to_dict() for a in live_alerts]
    alerts.sort(key=lambda item: item.get("timestamp") or "")

    if len(alerts) > MAX_ALERTS_FOR_LIVE_ANALYSIS:
        raise ValueError(
            f"analysis window contains {len(alerts)} alerts, exceeds safe limit {MAX_ALERTS_FOR_LIVE_ANALYSIS}; "
            "please narrow the time range before running post-alert analysis"
        )

    groups = {"file": [], "account": [], "parasitic": [], "audit": []}
    for item in alerts:
        groups.setdefault(item.get("alert_type", "audit"), []).append(item)

    split_paths = {
        "file": paths["alerts_dir"] / "file_alerts.json",
        "account": paths["alerts_dir"] / "account_alerts.json",
        "parasitic": paths["alerts_dir"] / "parasitic_alerts.json",
        "audit": paths["alerts_dir"] / "audit_alerts.json",
    }
    for name, path in split_paths.items():
        dump_json(path, groups.get(name, []))

    dump_json(paths["collected_alerts"], alerts)
    dump_json(paths["step1"], alerts)
    dump_json(paths["canonical_events"], [alert.to_canonical_event() for alert in live_alerts])
    graph_data, pruned, _prompts = run_steps_from_unified(alerts, paths)
    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "export-live")
    summary["analysis_window_hours"] = hours
    summary["analysis_window"] = {
        "start_time": start_time.isoformat() if start_time else None,
        "end_time": end_time.isoformat(),
    }
    summary["collector_sources"] = collector_sources
    summary["analysis_source_mode"] = collector_sources.get("analysis_source_mode") or "mixed"
    summary["analysis_include_alert_types"] = collector_sources.get("analysis_include_alert_types") or []
    summary["experiment_semantics"] = {
        "dataset_role": "raw_live_observation",
        "validity": "Use for real-world deployment distribution, attack surface observation, and timeline replay.",
        "limitation": "Class imbalance is preserved and may not be suitable for fair model comparison by itself.",
        "fabricated_alerts": False,
    }
    dump_json(paths["summary"], summary)
    print_summary(summary)
    return summary


def export_balanced_live(hours: int, run_dir: Path, per_type: int, exclude_ips=None):
    paths = build_run_paths(run_dir)
    ensure_dirs(paths)
    end_time = datetime.now()
    start_time = None if hours <= 0 else end_time - timedelta(hours=hours)
    collector = DataCollector(config=build_live_analysis_collector_config())
    collector_sources = collector.describe_sources()
    try:
        live_alerts = collect_live_alerts_from_systemwire2_api(hours)
        collector_sources["analysis_source_mode"] = "systemwire2_unified_api"
        collector_sources["analysis_source_detail"] = "flask_server.alert_store.build_unified_alert_api_rows"
    except Exception as exc:
        print(f"[-] unified API export path unavailable, fallback to unified store collector: {exc}")
        live_alerts = collector.collect_all(start_time, end_time)
        collector_sources["analysis_source_mode"] = "systemwire2_unified_store_fallback"
        collector_sources["analysis_source_detail"] = str(exc)

    balanced_alerts, balance_metadata = build_balanced_alert_subset(
        live_alerts,
        per_type=per_type,
        exclude_ips=exclude_ips,
    )
    alerts = [a.to_dict() for a in balanced_alerts]
    alerts.sort(key=lambda item: item.get("timestamp") or "")

    groups = {"file": [], "account": [], "parasitic": [], "audit": []}
    for item in alerts:
        groups.setdefault(item.get("alert_type", "audit"), []).append(item)

    split_paths = {
        "file": paths["alerts_dir"] / "file_alerts.json",
        "account": paths["alerts_dir"] / "account_alerts.json",
        "parasitic": paths["alerts_dir"] / "parasitic_alerts.json",
        "audit": paths["alerts_dir"] / "audit_alerts.json",
    }
    for name, path in split_paths.items():
        dump_json(path, groups.get(name, []))

    dump_json(paths["collected_alerts"], alerts)
    dump_json(paths["step1"], alerts)
    dump_json(paths["canonical_events"], [alert.to_canonical_event() for alert in balanced_alerts])
    graph_data, pruned, _prompts = run_steps_from_unified(alerts, paths)
    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "export-balanced-live")
    summary["analysis_window_hours"] = hours
    summary["analysis_window"] = {
        "start_time": start_time.isoformat() if start_time else None,
        "end_time": end_time.isoformat(),
    }
    summary["collector_sources"] = collector_sources
    summary["analysis_source_mode"] = collector_sources.get("analysis_source_mode") or "mixed"
    summary["analysis_include_alert_types"] = collector_sources.get("analysis_include_alert_types") or []
    summary["balance"] = balance_metadata
    summary["experiment_semantics"] = {
        "dataset_role": "balanced_real_alert_subset",
        "validity": "Use for fair cross-honeypot comparison, DQN/pruning ablation, and balanced downstream analysis.",
        "limitation": "This subset does not represent the natural prevalence of attacks in the public deployment.",
        "fabricated_alerts": False,
        "sampling_note": "Only real collected alerts are filtered and sampled; no synthetic alerts are inserted.",
    }
    dump_json(paths["summary"], summary)
    print_summary(summary)
    print(f"Balance: {balance_metadata}")
    return summary


def export_scenario_live(
    start_time: datetime,
    end_time: datetime,
    run_dir: Path,
    scenario_id: str,
    chain_actor_id: str,
    chain_ips=None,
    chain_fingerprints=None,
    chain_sessions=None,
    chain_alert_ids=None,
):
    """Export a controlled live scenario from real collected alerts.

    The function does not fabricate or insert alerts. It only annotates exported
    events in the isolated run directory so the thesis pipeline can evaluate
    controlled-chain recall and background-noise filtering.
    """
    paths = build_run_paths(run_dir)
    ensure_dirs(paths)

    live_alerts = collect_live_alerts_between(start_time, end_time)
    if len(live_alerts) > MAX_ALERTS_FOR_LIVE_ANALYSIS:
        raise ValueError(
            f"scenario window contains {len(live_alerts)} alerts, exceeds safe limit {MAX_ALERTS_FOR_LIVE_ANALYSIS}; "
            "please narrow the experiment window"
        )

    annotated_alerts = annotate_controlled_scenario_alerts(
        live_alerts,
        scenario_id=scenario_id,
        chain_actor_id=chain_actor_id,
        chain_ips=chain_ips,
        chain_fingerprints=chain_fingerprints,
        chain_sessions=chain_sessions,
        chain_alert_ids=chain_alert_ids,
    )

    groups = {"file": [], "account": [], "parasitic": [], "audit": []}
    for alert in annotated_alerts:
        groups.setdefault(_alert_type_value(alert), []).append(alert)

    alerts, split_paths = write_split_and_unified(groups, paths, deployments=None)
    graph_data, pruned, _prompts = run_steps_from_unified(alerts, paths)

    labels = build_edge_labels_from_scenario(graph_data)
    label_meta = write_edge_labels(graph_data, paths)
    controlled_eval_before_guard = evaluate_pruned_graph_against_labels(graph_data, pruned, labels)
    pruned = apply_controlled_label_guardrail(graph_data, pruned, labels)
    controlled_eval = evaluate_pruned_graph_against_labels(graph_data, pruned, labels)
    controlled_eval["label_file"] = label_meta.get("file", "")
    controlled_eval["before_guardrail"] = controlled_eval_before_guard
    pruned["controlled_label_eval"] = controlled_eval
    pruned.setdefault("pruning_stats", {})["controlled_label_eval"] = controlled_eval
    dump_json(paths["step3"], pruned)
    write_step4_outputs(paths, graph_data, pruned)

    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "export-scenario-live")
    role_counts = Counter((alert.details or {}).get("scenario_role", "unknown") for alert in annotated_alerts)
    chain_type_counts = Counter(
        _alert_type_value(alert)
        for alert in annotated_alerts
        if (alert.details or {}).get("scenario_role") == "controlled_chain"
    )
    noise_type_counts = Counter(
        _alert_type_value(alert)
        for alert in annotated_alerts
        if (alert.details or {}).get("scenario_role") == "controlled_noise"
    )
    summary["analysis_window"] = {
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }
    summary["analysis_source_mode"] = "systemwire2_unified_api_windowed"
    summary["analysis_include_alert_types"] = ["file", "account", "parasitic"]
    summary["scenario"] = {
        "scenario_id": scenario_id,
        "chain_actor_id": chain_actor_id,
        "role_counts": dict(role_counts),
        "chain_alert_counts": dict(chain_type_counts),
        "noise_alert_counts": dict(noise_type_counts),
        "chain_has_all_honeypots": {"account", "file", "parasitic"}.issubset(set(chain_type_counts.keys())),
        "chain_identifiers": {
            "chain_ips": sorted(_normalize_identifier_set(chain_ips)),
            "chain_fingerprints": sorted(_normalize_identifier_set(chain_fingerprints)),
            "chain_sessions": sorted(_normalize_identifier_set(chain_sessions)),
            "chain_alert_ids": sorted(_normalize_identifier_set(chain_alert_ids)),
        },
    }
    summary["edge_labels"] = label_meta
    summary["controlled_label_eval"] = controlled_eval
    summary["experiment_semantics"] = {
        "dataset_role": "controlled_multihoneypot_chain_with_real_background_noise",
        "validity": "Use for controlled-chain reconstruction, graph-pruning evaluation, and explainable LLM report generation.",
        "limitation": "Scenario labels are experiment annotations over real alerts and do not represent natural public-Internet prevalence.",
        "fabricated_alerts": False,
        "annotation_note": "Original alert records are not modified; scenario labels exist only in this export run directory.",
    }
    dump_json(paths["summary"], summary)
    print_summary(summary)
    print(f"Scenario: {summary['scenario']}")
    print(f"Controlled label evaluation: {controlled_eval}")
    return summary


def print_summary(summary):
    print("\n=== Honeypot Experiment Export Summary ===")
    print(f"Mode: {summary['mode']}")
    print(f"Deployment count: {summary['deployment_count']}")
    print(f"Total alerts: {summary['total_alerts']}")
    print(f"Alert counts: {summary['alert_counts']}")
    print(f"Graph: {summary['graph']['nodes']} nodes, {summary['graph']['edges']} edges")
    print(f"Pruning: {summary['pruning_stats']}")
    print("Outputs:")
    for key, value in summary["outputs"].items():
        print(f"  - {key}: {value}")


def main():
    parser = argparse.ArgumentParser(description="Export honeypot alerts into the step1-step4 experiment pipeline.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sim_parser = subparsers.add_parser("simulate", help="run an isolated three-honeypot simulation")
    sim_parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN_DIR, help="simulation output directory")
    sim_parser.add_argument("--write-defaults", action="store_true", help="also copy simulation outputs into normal deployment/step output paths")

    live_parser = subparsers.add_parser("export-live", help="collect live logs and export to step outputs")
    live_parser.add_argument("--hours", type=int, default=24, help="time window for live collection")
    live_parser.add_argument("--run-dir", type=Path, default=None, help="optional isolated output directory instead of normal output paths")

    balanced_parser = subparsers.add_parser("export-balanced-live", help="collect live logs and export a real-data balanced analysis subset")
    balanced_parser.add_argument("--hours", type=int, default=24, help="time window for live collection")
    balanced_parser.add_argument("--run-dir", type=Path, required=True, help="isolated output directory for the balanced subset")
    balanced_parser.add_argument("--per-type", type=int, default=50, help="maximum real alerts to keep for each honeypot type")
    balanced_parser.add_argument("--exclude-ip", action="append", default=[], help="source IP to exclude from the balanced subset; repeatable")

    scenario_parser = subparsers.add_parser("export-scenario-live", help="export a controlled real-alert scenario with chain/noise annotations")
    scenario_parser.add_argument("--start", required=True, help="scenario start time, e.g. '2026-06-29 14:00:00'")
    scenario_parser.add_argument("--end", required=True, help="scenario end time, e.g. '2026-06-29 14:30:00'")
    scenario_parser.add_argument("--run-dir", type=Path, required=True, help="isolated output directory for the controlled scenario")
    scenario_parser.add_argument("--scenario-id", default="", help="stable scenario id; defaults to controlled_chain_<timestamp>")
    scenario_parser.add_argument("--chain-actor-id", default="controlled_actor_001", help="actor id used only in experiment annotations")
    scenario_parser.add_argument("--chain-ip", action="append", default=[], help="source IP considered part of the core controlled chain; repeatable")
    scenario_parser.add_argument("--chain-fingerprint", action="append", default=[], help="browser fingerprint considered part of the core controlled chain; repeatable")
    scenario_parser.add_argument("--chain-session", action="append", default=[], help="session id considered part of the core controlled chain; repeatable")
    scenario_parser.add_argument("--chain-alert-id", action="append", default=[], help="explicit alert id considered part of the core controlled chain; repeatable")

    dqn_parser = subparsers.add_parser("train-dqn", help="train and evaluate a reproducible DQN pruning experiment")
    dqn_parser.add_argument("--graph-path", type=Path, default=build_default_paths()["step2"], help="causal_graph.json used for DQN training/evaluation")
    dqn_parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "experiments" / "runs" / "dqn_reproducible", help="DQN experiment output directory")
    dqn_parser.add_argument("--num-graphs", type=int, default=80, help="number of deterministic augmented graphs")
    dqn_parser.add_argument("--epochs", type=int, default=80, help="training epochs")
    dqn_parser.add_argument("--patience", type=int, default=15, help="early-stop patience measured in validation checks")
    dqn_parser.add_argument("--lr", type=float, default=1e-3, help="learning rate")
    dqn_parser.add_argument("--seed", type=int, default=42, help="reproducibility seed")
    dqn_parser.add_argument("--no-augment", action="store_true", help="disable graph augmentation")
    dqn_parser.add_argument("--label-file", type=Path, default=None, help="optional human edge-label JSON for extra evaluation")
    dqn_parser.add_argument("--train-with-manual-labels", action="store_true", help="use --label-file labels during training; matching edge_ids override weak labels")
    dqn_parser.add_argument("--require-label-balance", action="store_true", help="fail when manual labels lack either keep/core edges or prune/noise edges")
    dqn_parser.add_argument("--install-checkpoint", action="store_true", help="copy the trained checkpoint to the default step3 checkpoint path")
    dqn_parser.add_argument("--device", default="cpu", help="cpu, cuda, or auto")

    args = parser.parse_args()
    if args.mode == "simulate":
        simulate(args.run_dir, args.write_defaults)
    elif args.mode == "export-live":
        export_live(args.hours, args.run_dir)
    elif args.mode == "export-balanced-live":
        export_balanced_live(args.hours, args.run_dir, args.per_type, args.exclude_ip)
    elif args.mode == "export-scenario-live":
        start_time = _parse_scenario_timestamp(args.start)
        end_time = _parse_scenario_timestamp(args.end)
        scenario_id = args.scenario_id.strip() or f"controlled_chain_{start_time.strftime('%Y%m%d_%H%M%S')}"
        export_scenario_live(
            start_time=start_time,
            end_time=end_time,
            run_dir=args.run_dir,
            scenario_id=scenario_id,
            chain_actor_id=args.chain_actor_id,
            chain_ips=args.chain_ip,
            chain_fingerprints=args.chain_fingerprint,
            chain_sessions=args.chain_session,
            chain_alert_ids=args.chain_alert_id,
        )
    else:
        train_dqn_experiment(
            graph_path=args.graph_path,
            output_dir=args.output_dir,
            num_graphs=args.num_graphs,
            epochs=args.epochs,
            patience=args.patience,
            lr=args.lr,
            seed=args.seed,
            augment=not args.no_augment,
            label_file=args.label_file,
            train_with_manual_labels=args.train_with_manual_labels,
            require_label_balance=args.require_label_balance,
            install_checkpoint=args.install_checkpoint,
            device=args.device,
        )


if __name__ == "__main__":
    main()
