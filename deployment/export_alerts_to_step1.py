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

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from step1_data_collection import AlertType, DataCollector, UnifiedAlert
from step2_causal_graph import CausalGraphBuilder, CausalGraphVisualizer
from step4_graph_to_text import GraphToTextConverter


DEFAULT_RUN_DIR = REPO_ROOT / "generated_runs" / "three_honeypot_pipeline"


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
        "step2": REPO_ROOT / "step2_causal_graph" / "output" / "causal_graph.json",
        "step2_mermaid": REPO_ROOT / "step2_causal_graph" / "output" / "causal_graph.mmd",
        "step3": REPO_ROOT / "step3_dqn_pruning" / "output" / "pruned_graph.json",
        "step4": REPO_ROOT / "step4_graph_to_text" / "output" / "llm_prompt_intent_analysis.txt",
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
        "step2": run_dir / "step2" / "causal_graph.json",
        "step2_mermaid": run_dir / "step2" / "causal_graph.mmd",
        "step3": run_dir / "step3" / "pruned_graph.json",
        "step4": run_dir / "step4" / "llm_prompt_intent_analysis.txt",
        "summary": run_dir / "summary.json",
    }


def ensure_dirs(paths):
    for key in ["alerts_dir", "deployment_output_dir"]:
        paths[key].mkdir(parents=True, exist_ok=True)
    for key in ["deployments", "collected_alerts", "step1", "step2", "step2_mermaid", "step3", "step4", "summary"]:
        paths[key].parent.mkdir(parents=True, exist_ok=True)


def dump_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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
            "listen_port": 2222,
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
                "dst_port": "2222",
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
                "dst_port": "2222",
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
    for name, alerts in alert_groups.items():
        data = [alert_to_dict(a) if isinstance(a, UnifiedAlert) else a for a in alerts]
        dump_json(split_paths[name], data)
        all_alerts.extend(data)

    all_alerts.sort(key=lambda item: item.get("timestamp") or "")
    dump_json(paths["collected_alerts"], all_alerts)
    dump_json(paths["step1"], all_alerts)
    return all_alerts, split_paths


def simulate_pruning(graph_data, paths):
    important_actions = {"ssh_login", "file_access", "url_access", "read", "connect", "execve"}
    edges = graph_data.get("edges", [])
    kept = [edge for edge in edges if edge.get("action") in important_actions]
    if not kept and edges:
        kept = edges[:1]

    pruned = deepcopy(graph_data)
    pruned["edges"] = kept
    pruned["pruning_stats"] = {
        "mode": "deterministic_simulation",
        "original_edges": len(edges),
        "kept_edges": len(kept),
        "pruned_edges": max(len(edges) - len(kept), 0),
        "compression_ratio": f"{(100 * (len(edges) - len(kept)) / len(edges)):.1f}%" if edges else "0.0%",
    }
    dump_json(paths["step3"], pruned)
    return pruned


def run_steps_from_unified(alerts, paths):
    builder = CausalGraphBuilder()
    graph_data = builder.build_from_alerts(alerts)
    dump_json(paths["step2"], graph_data)
    CausalGraphVisualizer.save_mermaid(graph_data, str(paths["step2_mermaid"]), title="Simulated Three-Honeypot Attack Graph")

    pruned = simulate_pruning(graph_data, paths)
    converter = GraphToTextConverter()
    prompt = converter.convert_to_llm_prompt(pruned, "intent_analysis")
    converter.save(prompt, str(paths["step4"]))
    return graph_data, pruned, prompt


def summarize(alerts, graph_data, pruned, split_paths, paths, mode, deployments=None):
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
            "step2_causal_graph": rel(paths["step2"]),
            "step2_mermaid": rel(paths["step2_mermaid"]),
            "step3_pruned_graph": rel(paths["step3"]),
            "step4_llm_prompt": rel(paths["step4"]),
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
        (source_paths["step2"], default_paths["step2"]),
        (source_paths["step2_mermaid"], default_paths["step2_mermaid"]),
        (source_paths["step3"], default_paths["step3"]),
        (source_paths["step4"], default_paths["step4"]),
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
    graph_data, pruned, _prompt = run_steps_from_unified(alerts, paths)
    if write_defaults:
        copy_run_to_defaults(paths)
    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "simulate", deployments=deployments)
    print_summary(summary)


def export_live(hours: int, run_dir: Path = None):
    paths = build_run_paths(run_dir) if run_dir else build_default_paths()
    ensure_dirs(paths)
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)
    collector = DataCollector()
    live_alerts = collector.collect_all(start_time, end_time)
    alerts = [a.to_dict() for a in live_alerts]
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
    graph_data, pruned, _prompt = run_steps_from_unified(alerts, paths)
    summary = summarize(alerts, graph_data, pruned, split_paths, paths, "export-live")
    print_summary(summary)


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

