"""
Export honeypot alerts into the thesis experiment pipeline.

This script separates the useful data-export path from the old one-click
installation/deployment path.

Workflows:`r`n1. simulate: create a reproducible three-honeypot experiment under generated_runs/.
2. export-live: collect live logs and write the normal step1-step4 pipeline files.
"""

import argparse
import json
import sys
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from step1_data_collection import AlertType, DataCollector, UnifiedAlert
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
from step4_graph_to_text import GraphToTextConverter

try:
    from step3_dqn_pruning import DQNTrainer
    DQN_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
    if getattr(exc, "name", "") != "torch":
        raise
    DQNTrainer = None
    DQN_IMPORT_ERROR = exc


DEFAULT_RUN_DIR = REPO_ROOT / "generated_runs" / "three_honeypot_pipeline"
MAX_ALERTS_FOR_LIVE_ANALYSIS = 10000
MAX_DQN_EDGES = 5000
MAX_SIMULATED_KEPT_EDGES = 5000
MAX_PROMPT_EDGES = 200


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
        "step3_checkpoint": REPO_ROOT / "step3_dqn_pruning" / "output" / "checkpoints" / "dqn_best.pt",
        "step4_intent": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_intent_analysis.txt",
        "step4_ttp": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_ttp_mapping.txt",
        "step4_report": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_report.txt",
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
        "step3_checkpoint": REPO_ROOT / "step3_dqn_pruning" / "output" / "checkpoints" / "dqn_best.pt",
        "step4_intent": run_dir / "step4" / "llm_prompt_intent_analysis.txt",
        "step4_ttp": run_dir / "step4" / "llm_prompt_ttp_mapping.txt",
        "step4_report": run_dir / "step4" / "llm_prompt_report.txt",
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
        "step4_intent",
        "step4_ttp",
        "step4_report",
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

    subset = {
        "graph_meta": meta,
        "nodes": nodes,
        "edges": kept_edges,
        "triples": triples,
        "event_sequence": event_sequence,
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
                    evidence=data.get("evidence") or {},
                )
            )
    return items


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
    edges = graph_data.get("edges", [])
    kept = [edge for edge in edges if edge.get("action") in important_actions]
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


def run_dqn_pruning(paths, graph_data):
    if len(graph_data.get("edges", [])) > MAX_DQN_EDGES:
        return None, f"edge_count_exceeds_{MAX_DQN_EDGES}"

    checkpoint = paths.get("step3_checkpoint")
    if not checkpoint or not checkpoint.exists():
        return None, "dqn_checkpoint_missing"

    if DQNTrainer is None:
        reason = "torch_not_installed"
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
    prompt_graph = build_prompt_graph(pruned)
    converter = GraphToTextConverter()
    prompts = {
        "intent_analysis": converter.convert_to_llm_prompt(prompt_graph, "intent_analysis"),
        "ttp_mapping": converter.convert_to_llm_prompt(prompt_graph, "ttp_mapping"),
        "report": converter.convert_to_llm_prompt(prompt_graph, "report"),
    }
    converter.save(prompts["intent_analysis"], str(paths["step4_intent"]))
    converter.save(prompts["ttp_mapping"], str(paths["step4_ttp"]))
    converter.save(prompts["report"], str(paths["step4_report"]))
    return graph_data, pruned, prompts


def summarize(alerts, graph_data, pruned, split_paths, paths, mode, deployments=None) -> Dict[str, Any]:
    type_counts = Counter(a.get("alert_type") for a in alerts)
    action_counts = Counter(e.get("action") for e in graph_data.get("edges", []))
    summary = {
        "mode": mode,
        "generated_at": datetime.now().isoformat(),
        "deployment_count": len(deployments or []),
        "alert_counts": dict(type_counts),
        "total_alerts": len(alerts),
        "graph": {
            "nodes": len(graph_data.get("nodes", [])),
            "edges": len(graph_data.get("edges", [])),
            "event_edges": graph_data.get("graph_meta", {}).get("event_edge_count", 0),
            "correlation_edges": graph_data.get("graph_meta", {}).get("correlation_edge_count", 0),
            "triples": len(graph_data.get("triples", [])),
            "event_sequence": len(graph_data.get("event_sequence", [])),
            "attack_paths": len(graph_data.get("attack_paths", [])),
            "edge_actions": dict(action_counts),
        },
        "pruning_stats": pruned.get("pruning_stats", {}),
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
            "step4_intent_analysis": rel(paths["step4_intent"]),
            "step4_ttp_mapping": rel(paths["step4_ttp"]),
            "step4_report": rel(paths["step4_report"]),
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
        (source_paths["summary"], default_paths["summary"]),
    ]
    for name in ["file_alerts.json", "account_alerts.json", "parasitic_alerts.json", "audit_alerts.json"]:
        mapping.append((source_paths["alerts_dir"] / name, default_paths["alerts_dir"] / name))
    for src, dst in mapping:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    return default_paths


def simulate(run_dir: Path, write_defaults: bool):
    paths = build_run_paths(run_dir)
    deployments = create_simulated_deployments()
    groups = create_simulated_honeypot_alerts()
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
    live_alerts = collector.collect_all(start_time, end_time)
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
    dump_json(paths["summary"], summary)
    print_summary(summary)
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

    args = parser.parse_args()
    if args.mode == "simulate":
        simulate(args.run_dir, args.write_defaults)
    else:
        export_live(args.hours, args.run_dir)


if __name__ == "__main__":
    main()
