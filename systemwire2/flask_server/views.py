# 视图
from collections import defaultdict, deque
import base64
import hashlib
from io import BytesIO
import json
import linecache
import math
import os
import random
import re
import socket
import sqlite3
import shutil
import sys
import tarfile
import traceback
from urllib.parse import unquote, urlparse
import zipfile
from pathlib import Path
import docker
# from flask_cors import cross_origin
import openpyxl
import requests
import sqlalchemy
import pytz

from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for,session as flask_session
import urllib3

from flask_server.utils.ag_crypto import generate_key, decrypt_data
from .models import *
from .exts import scheduler,login_manager
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from flask import jsonify, make_response, request, send_file
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import SQLAlchemyError
from flask_server.utils.common import *
from flask_server.controller.analyze_email import analyze_email
from flask_server.controller.generate_account import password_genaerate, username_generate
from flask_server.controller.get_email import delete_email_imap, get_email_imap, get_email_pop3
from flask_server.controller.get_token import getToken
from flask_server.controller.kafka_alert import send_alert_email, send_alert_file
from flask_server.controller.ms_excel import gen_tokened_excel, make_canary_msexcel2
from flask_server.controller.ms_word import gen_tokened_word, make_canary_msword_add
from flask_server.utils.common import *
from flask_server.utils.token import generate_random_str
from flask_login import  login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash,generate_password_hash
from  agent_server.proto import agent_pb2 as pb2
from agent_server.core.agent import Agent
from agent_server.server import get_grpc_server
from captcha.image import ImageCaptcha
from config.config import MANAGE_ADDRESS, LOCAL_BOOTSTRAP, LOCAL_API_BYPASS_AUTH, FLASK_HTTP_MODE, FLASK_PORT
from flask_server.alert_store import (
    UnifiedAlertEvent,
    _normalize_proxy_fields,
    _resolve_possible_proxy,
    build_parasitic_logs_payload,
    build_parasitic_target_analysis,
    build_unified_alert_api_rows,
    build_unified_alert_statistics,
    get_account_alert_page_rows,
    get_file_alert_page_rows,
    ingest_account_alert,
    ingest_file_alert,
    ingest_parasitic_alert,
    refresh_file_alert_metadata,
)

# 蓝图
api = Blueprint("api", __name__)

PARASITIC_BUILTIN_JS_FILES = [
    "sessionToken.js",
    "client.min.js",
    "fingerprint.js",
    "network.js",
    "bot.js",
]


def _repo_root_path(*parts):
    return os.path.abspath(os.path.join(project_path, "..", *parts))


def _analysis_repo_root():
    repo_root = Path(_repo_root_path()).resolve()
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    return repo_root


def _resolve_analysis_run_dir(run_dir_value):
    if not run_dir_value:
        return None
    repo_root = _analysis_repo_root()
    candidate = Path(str(run_dir_value).strip())
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError("run_dir must stay within repository workspace") from exc
    return candidate


def _default_balanced_analysis_run_dir():
    repo_root = _analysis_repo_root()
    now = datetime.now(pytz.timezone("Asia/Shanghai"))
    date_dir = now.strftime("%Y-%m-%d")
    stamp = now.strftime("%H%M%S")
    return repo_root / "experiments" / "runs" / date_dir / f"ui_balanced_live_{stamp}"


def _default_live_analysis_run_dir():
    repo_root = _analysis_repo_root()
    now = datetime.now(pytz.timezone("Asia/Shanghai"))
    date_dir = now.strftime("%Y-%m-%d")
    stamp = now.strftime("%H%M%S")
    return repo_root / "experiments" / "runs" / date_dir / f"ui_live_{stamp}"


def _default_scenario_analysis_run_dir():
    repo_root = _analysis_repo_root()
    now = datetime.now(pytz.timezone("Asia/Shanghai"))
    date_dir = now.strftime("%Y-%m-%d")
    stamp = now.strftime("%H%M%S")
    return repo_root / "experiments" / "runs" / date_dir / f"ui_controlled_scenario_{stamp}"


def _latest_analysis_pointer_path():
    repo_root = _analysis_repo_root()
    return repo_root / "deployment" / "output" / "latest_analysis_run.json"


def _write_latest_analysis_run(run_dir_path, summary=None):
    if not run_dir_path:
        return
    pointer_path = _latest_analysis_pointer_path()
    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_dir": _analysis_run_dir_text(run_dir_path),
        "updated_at": datetime.now(pytz.timezone("Asia/Shanghai")).isoformat(),
        "mode": (summary or {}).get("mode", ""),
        "generated_at": (summary or {}).get("generated_at", ""),
        "total_alerts": (summary or {}).get("total_alerts", 0),
    }
    pointer_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _latest_analysis_run_dir():
    pointer_path = _latest_analysis_pointer_path()
    if not pointer_path.exists():
        return None
    try:
        payload = json.loads(pointer_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    run_dir = str(payload.get("run_dir") or "").strip()
    if not run_dir:
        return None
    try:
        resolved = _resolve_analysis_run_dir(run_dir)
    except ValueError:
        return None
    if not resolved.exists():
        return None
    return resolved


def _analysis_run_dir_text(run_dir_path):
    if not run_dir_path:
        return ""
    repo_root = _analysis_repo_root()
    try:
        return str(Path(run_dir_path).resolve().relative_to(repo_root)).replace("\\", "/")
    except ValueError:
        return str(run_dir_path)


def _analysis_paths(run_dir_value=None):
    _analysis_repo_root()
    from deployment.export_alerts_to_step1 import build_default_paths, build_run_paths, rel

    run_dir = _resolve_analysis_run_dir(run_dir_value) if run_dir_value else _latest_analysis_run_dir()
    paths = build_run_paths(run_dir) if run_dir else build_default_paths()
    rel_paths = {}
    for key, value in paths.items():
        if isinstance(value, Path):
            rel_paths[key] = rel(value)
    return paths, rel_paths


def _read_analysis_json(path, default=None):
    target = Path(path)
    if not target.exists():
        return default
    with target.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_analysis_text(path, default=""):
    target = Path(path)
    if not target.exists():
        return default
    return target.read_text(encoding="utf-8")


def _compact_analysis_value(value):
    if isinstance(value, dict):
        value_type = str(value.get("type") or "").strip()
        label = str(value.get("label") or value.get("name") or value.get("id") or "").strip()
        value_id = str(value.get("id") or "").strip()
        if value_type and label:
            return f"{value_type}:{label}"
        if label:
            return label
        if value_id:
            return value_id
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return " / ".join(_compact_analysis_value(item) for item in value if item is not None)
    if value is None:
        return ""
    return str(value)


def _normalize_analysis_triple_rows(triples):
    rows = []
    for idx, triple in enumerate(triples or [], 1):
        if isinstance(triple, (list, tuple)) and len(triple) >= 3:
            subject = triple[0]
            predicate = triple[1]
            obj = triple[2]
            row = {
                "id": idx,
                "subject": _compact_analysis_value(subject),
                "predicate": _compact_analysis_value(predicate),
                "object": _compact_analysis_value(obj),
                "subject_type": subject.get("type") if isinstance(subject, dict) else "",
                "object_type": obj.get("type") if isinstance(obj, dict) else "",
                "stage": "",
                "confidence": "",
                "timestamp": "",
            }
        elif isinstance(triple, dict):
            subject = triple.get("subject") or triple.get("source") or ""
            obj = triple.get("object") or triple.get("target") or ""
            row = {
                "id": idx,
                "triple_id": triple.get("triple_id") or triple.get("id") or idx,
                "event_id": triple.get("event_id") or "",
                "subject": _compact_analysis_value(subject),
                "predicate": _compact_analysis_value(
                    triple.get("predicate") or triple.get("relation") or triple.get("action") or ""
                ),
                "object": _compact_analysis_value(obj),
                "subject_type": subject.get("type") if isinstance(subject, dict) else triple.get("subject_type", ""),
                "object_type": obj.get("type") if isinstance(obj, dict) else triple.get("object_type", ""),
                "stage": triple.get("stage") or "",
                "confidence": triple.get("confidence", ""),
                "timestamp": triple.get("timestamp") or "",
            }
        else:
            row = {
                "id": idx,
                "subject": _compact_analysis_value(triple),
                "predicate": "",
                "object": "",
                "subject_type": "",
                "object_type": "",
                "stage": "",
                "confidence": "",
                "timestamp": "",
            }
        rows.append(row)
    return rows


def _analysis_availability(paths):
    return {
        "summary": Path(paths["summary"]).exists(),
        "step1": Path(paths["step1"]).exists(),
        "canonical_events": Path(paths["canonical_events"]).exists(),
        "step2": Path(paths["step2"]).exists(),
        "step2_mermaid": Path(paths["step2_mermaid"]).exists(),
        "step2_triples": Path(paths["step2_triples"]).exists(),
        "step3": Path(paths["step3"]).exists(),
        "step4_intent": Path(paths["step4_intent"]).exists(),
        "step4_ttp": Path(paths["step4_ttp"]).exists(),
        "step4_report": Path(paths["step4_report"]).exists(),
        "step4_llm_report": Path(paths["step4_llm_report"]).exists(),
        "step4_llm_report_meta": Path(paths["step4_llm_report_meta"]).exists(),
    }


def _analysis_not_ready_response(paths, rel_paths, message="尚未检测到分析结果，请先运行实时分析。"):
    return jsonify({
        "code": 1,
        "message": message,
        "data": {
            "available": _analysis_availability(paths),
            "paths": rel_paths,
        }
    })


def _analysis_error_message(prefix, exc):
    text = str(exc).strip()
    if "No module named 'torch'" in text or "No module named \"torch\"" in text:
        return f"{prefix}：当前环境未安装 PyTorch，系统已切换为非 DQN 裁剪模式，请重新点击“运行实时分析”。"
    return f"{prefix}：{text}" if text else prefix


def _normalize_triple_rows(triples):
    rows = []
    for idx, triple in enumerate(triples or [], 1):
        if isinstance(triple, (list, tuple)) and len(triple) >= 3:
            rows.append({
                "id": idx,
                "subject": triple[0],
                "predicate": triple[1],
                "object": triple[2],
            })
        elif isinstance(triple, dict):
            rows.append({
                "id": idx,
                "subject": triple.get("subject") or triple.get("source") or "",
                "predicate": triple.get("predicate") or triple.get("relation") or triple.get("action") or "",
                "object": triple.get("object") or triple.get("target") or "",
            })
    return rows


def _parasitic_server_base_url():
    base_url = str(getattr(Server_config, "parasitic_alert_server_address", "") or "").strip()
    return base_url.rstrip("/")


def _parasitic_manage_base_url():
    base_url = str(getattr(Server_config, "alert_server_manage_address", "") or "").strip()
    return base_url.rstrip("/")


def _parasitic_ws_base_url():
    base_url = _parasitic_server_base_url()
    if not base_url:
        raise ValueError("PARASITIC_ALERT_SERVER is not configured")
    if base_url.startswith("https://"):
        return "wss://" + base_url[len("https://"):]
    if base_url.startswith("http://"):
        return "ws://" + base_url[len("http://"):]
    return base_url


def _parasitic_logs_api_url():
    base_url = _parasitic_manage_base_url() or _parasitic_server_base_url()
    if not base_url:
        raise ValueError("PARASITIC_ALERT_SERVER is not configured")
    return f"{base_url}/api/logs"


_ALERT_SERVER_HEALTH_STATE = {
    "down_since": {},
    "last_log_at": {},
}


def _alert_server_health_key(label, method, url):
    return f"{str(label or '').strip()}::{str(method or 'GET').upper()}::{str(url or '').strip()}"


def _alert_server_request(label, method, url, *, timeout=15, log_cooldown_seconds=60, **kwargs):
    method = str(method or "GET").upper()
    health_key = _alert_server_health_key(label, method, url)
    state = _ALERT_SERVER_HEALTH_STATE
    now_ts = time.time()

    try:
        response = requests.request(method, url, timeout=timeout, **kwargs)
    except Exception as exc:
        down_since = state["down_since"].setdefault(health_key, now_ts)
        last_log_at = state["last_log_at"].get(health_key, 0)
        if (now_ts - last_log_at) >= max(int(log_cooldown_seconds or 0), 1):
            current_app.logger.warning(
                "[AlertServer] %s unavailable for %.1fs: %s %s (%s)",
                label,
                max(0.0, now_ts - down_since),
                method,
                url,
                exc,
            )
            state["last_log_at"][health_key] = now_ts
        return 1, f"{label} unavailable: {exc}"

    if health_key in state["down_since"]:
        down_since = state["down_since"].pop(health_key, now_ts)
        state["last_log_at"].pop(health_key, None)
        recover_after = max(0.0, now_ts - down_since)
        current_app.logger.info(
            "[AlertServer] %s recovered after %.1fs: %s %s",
            label,
            recover_after,
            method,
            url,
        )

    return 0, response


def _alert_server_health_snapshot():
    snapshot = {}
    down_since_map = _ALERT_SERVER_HEALTH_STATE.get("down_since", {})
    last_log_map = _ALERT_SERVER_HEALTH_STATE.get("last_log_at", {})
    now_ts = time.time()
    for key, down_since in down_since_map.items():
        snapshot[key] = {
            "status": "degraded",
            "down_for_seconds": round(max(0.0, now_ts - float(down_since or now_ts)), 1),
            "last_log_at": _datetime_to_text(datetime.fromtimestamp(last_log_map.get(key, 0), pytz.timezone("Asia/Shanghai"))) if last_log_map.get(key) else None,
        }
    return snapshot


def _alert_server_health_summary():
    snapshot = _alert_server_health_snapshot()
    if not snapshot:
        return {
            "status": "healthy",
            "degraded_targets": 0,
            "targets": {},
            "reason": "recent alert_server manage/business requests are healthy",
        }
    return {
        "status": "degraded",
        "degraded_targets": len(snapshot),
        "targets": snapshot,
        "reason": "one or more alert_server request targets are in temporary cooldown after connection failures",
    }


def _build_builtin_parasitic_runtime_router():
    config_json = json.dumps(
        {
            "httpBase": _parasitic_server_base_url(),
            "wsBase": _parasitic_ws_base_url(),
        },
        ensure_ascii=False,
    )
    return "\n".join(
        [
            "(function() {",
            "    if (window.__rtCfg__) {",
            "        return;",
            "    }",
            f"    var config = {config_json};",
            "",
            "    function trimRightSlash(value) {",
            "        return String(value || '').replace(/\\/+$/, '');",
            "    }",
            "",
            "    function joinBase(base, path) {",
            "        return trimRightSlash(base) + '/' + String(path || '').replace(/^\\/+/, '');",
            "    }",
            "",
            "    function pageTarget() {",
            "        try {",
            "            var href = window.location.href || '';",
            "            if (href && href !== 'about:blank') {",
            "                return href.split('#')[0];",
            "            }",
            "        } catch (err) {}",
            "        try {",
            "            if (window.location.host) {",
            "                return window.location.host;",
            "            }",
            "            if (window.location.pathname) {",
            "                return window.location.pathname;",
            "            }",
            "        } catch (err) {}",
            "        return 'unknown';",
            "    }",
            "",
            "    function tryParseUrl(value) {",
            "        try {",
            "            return new URL(value, window.location.href || 'http://localhost/');",
            "        } catch (err) {",
            "            return null;",
            "        }",
            "    }",
            "",
            "    function rewriteHttpTarget(target) {",
            "        if (typeof target !== 'string') {",
            "            return target;",
            "        }",
            "        var value = target.trim();",
            "        if (!value) {",
            "            return target;",
            "        }",
            "        var aliases = {",
            "            './cdn/analytics': joinBase(config.httpBase, 'cdn/analytics'),",
            "            './cdn/analytics/': joinBase(config.httpBase, 'cdn/analytics'),",
            "            '/cdn/analytics': joinBase(config.httpBase, 'cdn/analytics'),",
            "            '/cdn/analytics/': joinBase(config.httpBase, 'cdn/analytics'),",
            "            'cdn/analytics': joinBase(config.httpBase, 'cdn/analytics'),",
            "            'cdn/analytics/': joinBase(config.httpBase, 'cdn/analytics'),",
            "            './cdn/analytics/geo': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            './cdn/analytics/geo/': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            '/cdn/analytics/geo': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            '/cdn/analytics/geo/': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            'cdn/analytics/geo': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            'cdn/analytics/geo/': joinBase(config.httpBase, 'cdn/analytics/geo'),",
            "            './cdn/security/verify': joinBase(config.httpBase, 'cdn/security/verify'),",
            "            '/cdn/security/verify': joinBase(config.httpBase, 'cdn/security/verify'),",
            "            'cdn/security/verify': joinBase(config.httpBase, 'cdn/security/verify'),",
            "            './cdn/security/verify/': joinBase(config.httpBase, 'cdn/security/verify'),",
            "            '/cdn/security/verify/': joinBase(config.httpBase, 'cdn/security/verify')",
            "        };",
            "        if (Object.prototype.hasOwnProperty.call(aliases, value)) {",
            "            return aliases[value];",
            "        }",
            "        var parsed = tryParseUrl(value);",
            "        if (!parsed) {",
            "            return target;",
            "        }",
            "        var pathname = parsed.pathname || '';",
            "        if (pathname === '/cdn/analytics' || pathname === '/cdn/analytics/') {",
            "            return joinBase(config.httpBase, 'cdn/analytics');",
            "        }",
            "        if (pathname === '/cdn/analytics/geo' || pathname === '/cdn/analytics/geo/') {",
            "            return joinBase(config.httpBase, 'cdn/analytics/geo');",
            "        }",
            "        if (pathname === '/cdn/security/verify' || pathname === '/cdn/security/verify/') {",
            "            return joinBase(config.httpBase, 'cdn/security/verify');",
            "        }",
            "        return target;",
            "    }",
            "",
            "    function rewriteWsTarget(target) {",
            "        if (typeof target !== 'string') {",
            "            return target;",
            "        }",
            "        var value = target.trim();",
            "        if (!value) {",
            "            return target;",
            "        }",
            "        var resolved = joinBase(config.wsBase, 'socket');",
            "        var aliases = {",
            "            './socket': resolved,",
            "            '/socket': resolved,",
            "            'socket': resolved,",
            "            './socket/': resolved,",
            "            '/socket/': resolved,",
            "            'ws:///socket': resolved,",
            "            'wss:///socket': resolved,",
            "            'http:///socket': resolved,",
            "            'https:///socket': resolved",
            "        };",
            "        if (Object.prototype.hasOwnProperty.call(aliases, value)) {",
            "            return aliases[value];",
            "        }",
            "        var parsed = tryParseUrl(value);",
            "        if (!parsed) {",
            "            return target;",
            "        }",
            "        var pathname = parsed.pathname || '';",
            "        var protocol = parsed.protocol || '';",
            "        if (pathname !== '/socket' && pathname !== '/socket/') {",
            "            return target;",
            "        }",
            "        if (protocol !== 'ws:' && protocol !== 'wss:' && protocol !== 'http:' && protocol !== 'https:') {",
            "            return target;",
            "        }",
            "        return resolved;",
            "    }",
            "",
            "    if (typeof window.fetch === 'function' && !window.fetch._wrapped) {",
            "        var nativeFetch = window.fetch.bind(window);",
            "        var wrappedFetch = function(input, init) {",
            "            if (typeof input === 'string') {",
            "                input = rewriteHttpTarget(input);",
            "            } else if (typeof URL !== 'undefined' && input instanceof URL) {",
            "                input = rewriteHttpTarget(input.href);",
            "            }",
            "            return nativeFetch(input, init);",
            "        };",
            "        wrappedFetch._wrapped = true;",
            "        window.fetch = wrappedFetch;",
            "    }",
            "",
            "    if (window.XMLHttpRequest && window.XMLHttpRequest.prototype && !window.XMLHttpRequest.prototype.open._wrapped) {",
            "        var nativeXHROpen = window.XMLHttpRequest.prototype.open;",
            "        var wrappedOpen = function(method, url) {",
            "            if (typeof url === 'string') {",
            "                arguments[1] = rewriteHttpTarget(url);",
            "            }",
            "            return nativeXHROpen.apply(this, arguments);",
            "        };",
            "        wrappedOpen._wrapped = true;",
            "        window.XMLHttpRequest.prototype.open = wrappedOpen;",
            "    }",
            "",
            "    if (typeof window.WebSocket === 'function' && !window.WebSocket._wrapped) {",
            "        var NativeWebSocket = window.WebSocket;",
            "        var WrappedWebSocket = function(url, protocols) {",
            "            var rewrittenUrl = rewriteWsTarget(url);",
            "            if (protocols === undefined) {",
            "                return new NativeWebSocket(rewrittenUrl);",
            "            }",
            "            return new NativeWebSocket(rewrittenUrl, protocols);",
            "        };",
            "        WrappedWebSocket.prototype = NativeWebSocket.prototype;",
            "        WrappedWebSocket.OPEN = NativeWebSocket.OPEN;",
            "        WrappedWebSocket.CLOSED = NativeWebSocket.CLOSED;",
            "        WrappedWebSocket.CLOSING = NativeWebSocket.CLOSING;",
            "        WrappedWebSocket.CONNECTING = NativeWebSocket.CONNECTING;",
            "        WrappedWebSocket._wrapped = true;",
            "        window.WebSocket = WrappedWebSocket;",
            "    }",
            "",
            "    window.__rtCfg__ = {",
            "        httpBase: config.httpBase,",
            "        wsBase: config.wsBase,",
            "        buildHttpUrl: function(path) { return joinBase(config.httpBase, path); },",
            "        buildWsUrl: function(path) { return joinBase(config.wsBase, path); },",
            "        infoUrl: function() { return joinBase(config.httpBase, 'cdn/analytics'); },",
            "        ipsUrl: function() { return joinBase(config.httpBase, 'cdn/analytics/geo'); },",
            "        botUrl: function() { return joinBase(config.httpBase, 'cdn/security/verify'); },",
            "        wsUrl: function() { return joinBase(config.wsBase, 'socket'); },",
            "        rewriteHttpTarget: rewriteHttpTarget,",
            "        rewriteWsTarget: rewriteWsTarget,",
            "        pageTarget: pageTarget",
            "    };",
            "})();",
        ]
    )


def _rewrite_builtin_parasitic_js(content, filename=""):
    base_url = _parasitic_server_base_url()
    if not base_url:
        raise ValueError("PARASITIC_ALERT_SERVER is not configured")
    ws_base_url = _parasitic_ws_base_url()

    replacements = {
        '"./cdn/analytics"': json.dumps(f"{base_url}/cdn/analytics"),
        "'./cdn/analytics'": json.dumps(f"{base_url}/cdn/analytics"),
        '"./cdn/analytics/"': json.dumps(f"{base_url}/cdn/analytics"),
        "'./cdn/analytics/'": json.dumps(f"{base_url}/cdn/analytics"),
        '`./cdn/analytics/geo`': f'`{base_url}/cdn/analytics/geo`',
        '`./cdn/analytics/geo/`': f'`{base_url}/cdn/analytics/geo`',
        '"./socket"': json.dumps(f"{ws_base_url}/socket"),
        "'./socket'": json.dumps(f"{ws_base_url}/socket"),
        "'./cdn/security/verify'": json.dumps(f"{base_url}/cdn/security/verify"),
        '"./cdn/security/verify"': json.dumps(f"{base_url}/cdn/security/verify"),
    }
    for old, new in replacements.items():
        content = content.replace(old, new)
    if filename == "fingerprint.js":
        content = re.sub(
            r"path:\s*window\.location\.host\s*,",
            "path: (window.__rtCfg__ && window.__rtCfg__.pageTarget ? window.__rtCfg__.pageTarget() : (window.location.href || window.location.host || 'unknown')),"
            ,
            content,
            count=1,
        )
    return content


def _load_builtin_parasitic_js_bundle():
    js_dir = _repo_root_path("js")
    chunks = [_build_builtin_parasitic_runtime_router()]
    missing = []
    for filename in PARASITIC_BUILTIN_JS_FILES:
        js_path = os.path.join(js_dir, filename)
        if not os.path.isfile(js_path):
            missing.append(js_path)
            continue
        with open(js_path, "r", encoding="utf-8") as f:
            content = f.read()
        content = _rewrite_builtin_parasitic_js(content, filename=filename)
        chunks.append(content)
    if missing:
        raise FileNotFoundError("missing builtin parasitic js files: " + ", ".join(missing))
    return "\n\n".join(chunks)


def _absolute_agent_download_url(file_id):
    return f"{request.host_url.rstrip('/')}/api/agent/file/download/{file_id}"


def _local_agent_download_url(file_id):
    return f"{FLASK_HTTP_MODE}://127.0.0.1:{FLASK_PORT}/api/agent/file/download/{file_id}"


def _detail_to_dict(detail):
    if isinstance(detail, dict):
        return dict(detail)
    if isinstance(detail, str):
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _normalize_parasitic_target_dir(target):
    target = str(target or "").strip()
    if not target:
        return ""
    if target.lower().startswith("file://"):
        parsed = urlparse(target)
        target = unquote(parsed.path or target)
        if re.match(r"^/[A-Za-z]:", target):
            target = target[1:]
    target = target.replace("/", os.sep).replace("\\", os.sep)
    if os.path.splitext(target)[1].lower() in (".html", ".htm"):
        target = os.path.dirname(target)
    return os.path.normpath(target)


def _is_valid_parasitic_target_dir(target):
    target = _normalize_parasitic_target_dir(target)
    if not target:
        return False
    if "?" in target:
        return False
    if re.match(r"^https?://", str(target), re.IGNORECASE):
        return False
    if re.match(r"^[A-Za-z][A-Za-z0-9+\-.]*:[\\/]{1,2}", str(target)) and not re.match(r"^[A-Za-z]:[\\/]", str(target)):
        return False
    if not os.path.isabs(target):
        return False
    return True

@api.before_request
def before_request():
    if (
        LOCAL_BOOTSTRAP
        and LOCAL_API_BYPASS_AUTH
        and request.path.startswith("/api/")
    ):
        return None

    # 排除登录和注册页面，不然会进入无限循环
    # 同时排除Agent专用文件下载端点，让Agent无需认证即可下载文件
    if request.endpoint not in ['api.login','api.captcha','api.register', 'api.static', 'api.agent_file_download', 'api.account_alert_pull', 'api.account_alert_receive'] and not current_user.is_authenticated:
        return redirect(url_for('api.login'))

# 蜜点运行状态检测
def honeypoint_mode_check(func):
    def warp(*args, **kwargs):
        """
        检测当前蜜点是独立运行还是被蜜阵接管，
        若被蜜阵接管则禁止在蜜点管理界面进行操作
        """
        # 检测调用接口的身份
        user = request.headers.get("authentication")
        # TODO:判断是否为蜜阵用户
        if user != "蜜阵用户":
            # 非蜜阵用户操作则检测蜜点接管状态
            base_info = get_base_info()[1]
            status = base_info.get("runMode")
            if status != 0:  # 非独立运行
                return jsonify(
                    {"code": 1, "message": "Prohibited operation! The system is currently running in takeover mode",
                     "data": {}})


@api.route("/<name>")
def hello_world(name):
    return f"<p>Hello, {(name)}</p>"
############################# 登录 ############################
@api.route('/manage/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('api.register'))

        # 检查密码是否一致
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('api.register'))

        # 加密密码并存储用户
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('api.login'))

    return render_template('register.html')
# 生成随机验证码文本
def generate_captcha_text(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# 生成验证码图片
@api.route('/captcha')
def captcha():
    captcha_text = generate_captcha_text()
    flask_session['captcha'] = captcha_text  # 将验证码存储到 session 中
    res = flask_session.get('captcha')
    print(f"Captcha in session: {res}")  # 调试输出
    image = ImageCaptcha(width=280, height=90)  # 初始化验证码生成器
    data = image.generate(captcha_text)  # 生成验证码图片
    return send_file(data, mimetype='image/png')

# 登录
@api.route('/manage/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        input_captcha = request.form['captcha']  # 获取用户输入的验证码

        # 验证验证码
        if input_captcha.lower() != flask_session.get('captcha').lower():
            flash('验证码错误！')
            return render_template('login.html')

        # 验证用户
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('登录成功！')
            return redirect(url_for('api.index'))  # 登录成功后重定向到主页
        else:
            flash('用户名或密码错误！')

    return render_template('login.html')

@api.route('/manage/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('api.login'))

############################# 前端 #########################################
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@api.route("/manage/")
def index():
    return render_template('manage.html')

@api.route("/manage/file/list")
def manage_file_list():
    files = Honeyfile.query.all()
    file_list = []
    for file in files:
        file_list.append(file.to_json())
    data = {
        "file_list" : file_list
    }
    return render_template('file_list.html',**data)

@api.route("/manage/file/all")
def get_all_files_json():
    """
    提供所有蜜点文件信息的JSON API。
    """
    files = Honeyfile.query.all()
    file_list = []
    for file in files:
        # to_json() 方法应该返回一个Python字典，包含所有文件信息
        file_list.append(file.to_json())
    
    return jsonify({"code": 0, "message": "success", "data": {"files": file_list}})

@api.route("/manage/file/deploy")
def manage_file_deploy():
    deps = Filedeploy.query.all()
    dep_infos = []
    total = len(deps)
    if deps is None:
        return jsonify(
            {"code": 0, "message": "Success", "data": dep_infos, "total": total}
        )
    for each in deps:
        dep_json = each.to_json()
        dep_json["company"] = each.honeyfile.message.split("-")[0]
        dep_json["filename"] = each.honeyfile.name
        dep_json["honeypoint_name"] = each.honeyfile.honeypoint_name
        # dep_json["deploy_at"] = each.deploy_at.strftime("%Y-%m-%d %H:%M:%S")
        dep_infos.append(dep_json)
    data={
        "dep_infos":dep_infos
    }
    return render_template('file_deploy.html',**data)

# 管理-蜜点文件管理-创建文件
@api.route("/manage/file/create")
def manage_file_create():
    return render_template('file_create.html')

# 管理-蜜点文件管理-创建文件蜜点网页
@api.route("/manage/honeypot/generator")
def manage_honeypot_generator():
    """
    渲染文件蜜点网页创建页面，并获取文件和模板列表。
    """
    # 获取蜜点文件列表
    file_list = []
    try:
        generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
        if not os.path.exists(generate_dir):
            os.makedirs(generate_dir)
        
        if os.path.isdir(generate_dir):
            files = os.listdir(generate_dir)
            for idx, file_name in enumerate(files, 1):
                file_path = os.path.join(generate_dir, file_name)
                if os.path.isfile(file_path):
                    file_stats = os.stat(file_path)
                    create_time = datetime.fromtimestamp(file_stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                    file_list.append({
                        "id": str(idx),
                        "name": file_name,
                        "create_time": create_time
                    })
    except Exception as e:
        current_app.logger.error(f"获取文件列表失败: {e}")
        file_list = []

    # 准备模板列表
    template_list = []
    try:
        template_dir = os.path.join(project_path, "flask_server", "templates", "honeypot")
        if os.path.isdir(template_dir):
            for item in os.listdir(template_dir):
                item_path = os.path.join(template_dir, item)
                # 检查是否为目录，且包含对应的HTML文件
                if os.path.isdir(item_path):
                    html_file = os.path.join(item_path, f"{item}.html")
                    if os.path.exists(html_file):
                        template_list.append({
                            "name": item,
                            "display_name": item.replace("_", " ").title()
                        })
                # 兼容旧的单独HTML文件格式
                elif item.endswith(".html"):
                    template_list.append({
                        "name": os.path.splitext(item)[0],
                        "display_name": item.replace(".html", "").replace("_", " ").title()
                    })
        if not template_list:  # 如果没有找到模板文件，使用默认模板
            template_list = [
                {'name': 'download_page', 'display_name': '下载页面'},
                {'name': 'list_page', 'display_name': '列表页面'}
            ]
    except Exception as e:
        current_app.logger.error(f"无法获取模板列表: {e}")
        template_list = [
            {'name': 'download_page', 'display_name': '下载页面'},
            {'name': 'list_page', 'display_name': '列表页面'}
        ]

    return render_template('honeypot_generator.html', file_list=file_list, template_list=template_list)

def _normalize_file_token(token_value):
    token = str(token_value or "").strip()
    if "/static/img/logo-" in token:
        token = token.rsplit("/static/img/logo-", 1)[-1]
        if token.endswith(".png"):
            token = token[:-4]
    if "/contact/" in token:
        token = token.rsplit("/contact/", 1)[-1]
    return token.strip("/")


def _first_present(mapping, *keys, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


def _file_alert_public_token_url(token):
    token = _normalize_file_token(token)
    base = getattr(Server_config, "file_alert_server_address", "") or Server_config.alert_server_manage_address
    return f"{base.rstrip('/')}/static/img/logo-{token}.png" if token else ""


def _build_deterministic_file_token(alert_addr, alert_msg):
    payload = f"{str(alert_addr or '')}{str(alert_msg or '')}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _issue_file_alert_token(alert_addr, alert_msg):
    err, token_or_msg = getToken(alert_addr, alert_msg)
    if err:
        normalized_message = str(token_or_msg or "")
        if "msg is used" in normalized_message.lower():
            return 0, _file_alert_public_token_url(_build_deterministic_file_token(alert_addr, alert_msg))
        return err, token_or_msg
    return 0, token_or_msg


def _alert_server_token_db_path():
    db_path = Path(_repo_root_path("alert_server", "data", "token.db")).resolve()
    if db_path.exists():
        return db_path
    return None


def _alert_server_has_live_file_token(token_value):
    token = _normalize_file_token(token_value)
    if not token:
        return False

    db_path = _alert_server_token_db_path()
    if db_path is None:
        return None

    db_uri = f"file:{str(db_path).replace(os.sep, '/')}" + "?mode=ro"
    try:
        conn = sqlite3.connect(db_uri, uri=True, timeout=2)
        try:
            row = conn.execute(
                "SELECT 1 FROM token_infos WHERE token = ? AND deleted_at IS NULL LIMIT 1",
                (token,),
            ).fetchone()
            return bool(row)
        finally:
            conn.close()
    except Exception as exc:
        try:
            current_app.logger.warning("file token liveness check failed for %s: %s", token, exc)
        except Exception:
            pass
        return None


def _is_live_file_alert_token(token_value):
    token_text = str(token_value or "").strip()
    if "local-demo-honeyfile" in token_text:
        return False
    normalized = _normalize_file_token(token_text)
    if not normalized:
        return False
    expected_prefix = (_file_alert_public_token_url("probe") or "").rsplit("/static/img/logo-", 1)[0].rstrip("/")
    if "/static/img/logo-" in token_text:
        current_prefix = token_text.rsplit("/static/img/logo-", 1)[0].rstrip("/")
    elif "/contact/" in token_text:
        current_prefix = token_text.rsplit("/contact/", 1)[0].rstrip("/")
    else:
        return False
    if not (bool(expected_prefix) and current_prefix == expected_prefix):
        return False

    token_live = _alert_server_has_live_file_token(normalized)
    if token_live is None:
        return True
    return token_live


def _find_honeyfile_by_token(token_value):
    token_raw = _normalize_file_token(token_value)
    if not token_raw:
        return None

    candidates = [token_raw]
    public_token = _file_alert_public_token_url(token_raw)
    if public_token and public_token not in candidates:
        candidates.append(public_token)

    for candidate in candidates:
        honeyfile = Honeyfile.query.filter_by(token=candidate).first()
        if honeyfile:
            return honeyfile
    return None


FILE_ALERT_LOGICAL_WINDOW_SECONDS = 60


def _file_alert_logical_key(token, report_ip="", report_agent="", alert_message=""):
    return (
        _normalize_file_token(token),
        str(report_ip or "").strip(),
        str(report_agent or "").strip(),
        str(alert_message or "").strip(),
    )


def _file_alert_seconds_between(left, right):
    try:
        return abs((left - right).total_seconds())
    except Exception:
        return FILE_ALERT_LOGICAL_WINDOW_SECONDS + 1


def _file_alert_in_same_open(left, right):
    if not left or not right:
        return False
    return _file_alert_seconds_between(left, right) <= FILE_ALERT_LOGICAL_WINDOW_SECONDS


def _extract_alert_server_trigger_infos(payload):
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return (
            data.get("triggerInfos")
            or data.get("trigger_infos")
            or data.get("alerts")
            or data.get("items")
            or []
        )
    return []


def _parse_alert_server_time(value):
    if value in (None, ""):
        return get_time_bj()
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 100000000000:
            number = number / 1000
        return datetime.fromtimestamp(number, tz=timezone.utc).astimezone(pytz.timezone("Asia/Shanghai"))
    parsed = parse(str(value))
    if parsed.tzinfo is None:
        return pytz.timezone("Asia/Shanghai").localize(parsed)
    return parsed.astimezone(pytz.timezone("Asia/Shanghai"))


def _format_endpoint(ip, port):
    ip = str(ip or "").strip()
    port = str(port or "").strip()
    if ip and port:
        return f"{ip}:{port}"
    return ip or "-"


def _classify_ssh_client(client_version):
    value = str(client_version or "").strip()
    lower = value.lower()
    if not value:
        return "未知客户端"
    if "putty" in lower:
        return "PuTTY 交互客户端"
    if "xshell" in lower:
        return "Xshell 交互客户端"
    if "finalshell" in lower:
        return "FinalShell 交互客户端"
    if "paramiko" in lower:
        return "Paramiko 自动化脚本"
    if "libssh2" in lower:
        return "libssh2 扫描/自动化工具"
    if "libssh" in lower:
        return "libssh 客户端"
    if "openssh" in lower:
        return "OpenSSH 客户端"
    if "go" in lower:
        return "Go SSH 客户端"
    return "SSH 客户端"


def _infer_account_attack_type(protocol, message, client_version, raw_event=None):
    protocol_value = str(protocol or "ssh").lower()
    message_value = str(message or "").lower()
    raw_text = ""
    if raw_event:
        try:
            raw_text = json.dumps(raw_event, ensure_ascii=False).lower()
        except Exception:
            raw_text = str(raw_event).lower()

    text = " ".join([protocol_value, message_value, str(client_version or "").lower(), raw_text])
    if "openvpn" in protocol_value or "vpn connection attempt" in text:
        return "OpenVPN 连接探测"
    if message_value == "connection" or "connection" in text:
        return "SSH 连接探测"
    if "request with password" in text or "password" in message_value:
        return "SSH 密码认证尝试"
    if "request with key" in text or "keytype" in text or "fingerprint" in text:
        return "SSH 公钥认证尝试"
    if protocol_value == "ssh":
        return "SSH 登录探测"
    return f"{protocol_value.upper()} 访问尝试"


def _enrich_account_alert_json(alert_info):
    raw_event = alert_info.get("raw_event")
    alert_info["src_endpoint"] = _format_endpoint(alert_info.get("src_ip"), alert_info.get("src_port"))
    alert_info["dst_endpoint"] = _format_endpoint(alert_info.get("dst_ip"), alert_info.get("dst_port"))
    alert_info["attack_type"] = _infer_account_attack_type(
        alert_info.get("protocol"),
        alert_info.get("message"),
        alert_info.get("client_version"),
        raw_event,
    )
    alert_info["client_family"] = _classify_ssh_client(alert_info.get("client_version"))
    try:
        alert_info["raw_event_json"] = json.dumps(raw_event or {}, ensure_ascii=False, indent=2)
    except Exception:
        alert_info["raw_event_json"] = str(raw_event or "")
    return alert_info


def _enrich_parasitic_alert_json(alert_info):
    info = alert_info.get("info")
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except Exception:
            info = {"raw": info}
    if not isinstance(info, dict):
        info = {"value": info}

    real_ips = (
        info.get("IPs")
        or info.get("ips")
        or info.get("real_ips")
        or info.get("webrtc_ips")
        or ([] if not alert_info.get("dst_ip") else [alert_info.get("dst_ip")])
    )
    if not isinstance(real_ips, list):
        real_ips = [real_ips]

    alert_info["info"] = info
    alert_info["info_json"] = json.dumps(info, ensure_ascii=False, indent=2)
    alert_info["real_ips"] = real_ips
    alert_info["real_ips_text"] = ", ".join([str(ip) for ip in real_ips if ip]) or "-"
    alert_info["browser"] = info.get("browser") or info.get("Browser") or info.get("browserName") or "-"
    alert_info["os"] = info.get("os") or info.get("OS") or info.get("osName") or "-"
    alert_info["browser_platform"] = info.get("platform") or info.get("navigatorPlatform") or "-"
    alert_info["user_agent"] = info.get("userAgent") or info.get("ua") or "-"
    alert_info["session_token"] = info.get("sessionToken") or info.get("session_token") or "-"
    alert_info["reason"] = info.get("reason") or "-"
    alert_info["target_url"] = alert_info.get("url") or info.get("path") or "-"
    proxy_headers = info.get("proxy_headers") or {}
    xff, forwarded, via = _normalize_proxy_fields(
        info.get("x_forwarded_for") or proxy_headers.get("x_forwarded_for"),
        info.get("forwarded") or proxy_headers.get("forwarded"),
        info.get("via") or proxy_headers.get("via"),
    )
    alert_info["x_forwarded_for"] = xff
    alert_info["forwarded"] = forwarded
    alert_info["via"] = via
    alert_info["possible_proxy"] = _resolve_possible_proxy(
        info.get("possible_proxy"),
        info.get("ProxyDetectResult") or info.get("proxy_detect_result"),
        xff,
        forwarded,
        via,
    )
    alert_info["proxy_note"] = info.get("proxy_note") or "若代理未写入 X-Forwarded-For/Via/Forwarded，服务端只能看到代理出口 IP。"
    return alert_info


def _parasitic_info_dict(row):
    info = row.info if isinstance(row.info, dict) else row.info
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except Exception:
            info = {"raw": info}
    if not isinstance(info, dict):
        info = {"value": info}
    return info


def _is_official_parasitic_alert_row(row):
    info = _parasitic_info_dict(row)
    source = str(info.get("source") or info.get("ingest_source") or "").strip().lower()
    return source in ("js/bot", "js_bot", "systemwire2_pull_js_bot")


def _parse_parasitic_trigger_time(value):
    beijing = pytz.timezone("Asia/Shanghai")
    if value in (None, ""):
        return datetime.now(beijing)
    if isinstance(value, (int, float)):
        trigger_number = float(value)
        if trigger_number > 100000000000:
            trigger_number = trigger_number / 1000
        return datetime.fromtimestamp(trigger_number, tz=timezone.utc).astimezone(beijing)

    text = str(value).strip()
    if text.isdigit():
        trigger_number = float(text)
        if trigger_number > 100000000000:
            trigger_number = trigger_number / 1000
        return datetime.fromtimestamp(trigger_number, tz=timezone.utc).astimezone(beijing)

    parsed = parse(text)
    if parsed.tzinfo is None:
        parsed = beijing.localize(parsed)
    return parsed.astimezone(beijing)


def _parse_parasitic_log_info(raw_value):
    if isinstance(raw_value, dict):
        return dict(raw_value)
    if raw_value in (None, ""):
        return {}
    if isinstance(raw_value, str):
        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, dict):
                return parsed
            return {"raw": raw_value}
        except Exception:
            return {"raw": raw_value}
    return {"value": raw_value}


def _normalize_parasitic_ips(raw_value):
    if raw_value in (None, ""):
        return []
    if isinstance(raw_value, list):
        return [str(item).strip() for item in raw_value if str(item).strip()]
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
        if "," in text:
            return [item.strip() for item in text.split(",") if item.strip()]
        return [text]
    return [str(raw_value).strip()]


def _normalize_parasitic_row(item):
    if not isinstance(item, dict):
        return None

    def _clean_str(value):
        """将 Go 侧 <nil> / "null" / "None" 等脏值统一清洗为 None"""
        if value is None:
            return None
        s = str(value).strip()
        if s in ("<nil>", "null", "None", "<none>", "-"):
            return None
        return s or None

    # ── Go LogRecord JSON 标签均为 snake_case ──
    #    time / remote_ip / ips / proxy_detect_result /
    #    fingerprint_data / fingerprint / target /
    #    group_id / score / is_bot / reasons / bot_detect_method
    info = _parse_parasitic_log_info(
        item.get("fingerprint_data") or item.get("FingerprintData")
    )
    info.setdefault("source", "js/bot")
    info.setdefault("ingest_source", "systemwire2_pull_js_bot")
    info.setdefault("proxy_detect_result",
                    item.get("proxy_detect_result") or item.get("ProxyDetectResult"))
    if item.get("score") not in (None, ""):
        info.setdefault("bot_score", item.get("score"))
    if item.get("is_bot") not in (None, ""):
        info.setdefault("is_bot", item.get("is_bot"))
    elif item.get("isBot") not in (None, ""):
        info.setdefault("is_bot", item.get("isBot"))
    if item.get("reasons") not in (None, ""):
        info.setdefault("bot_reasons", item.get("reasons"))

    _raw_target = str(item.get("target") or "").strip()
    if _raw_target in ("<nil>", "null", "None", "<none>"):
        _raw_target = ""
    target = (
        _raw_target
        or str(info.get("path") or info.get("Path") or "").strip()
        or "unknown"
    )
    remote_ip = str(item.get("remote_ip") or item.get("RemoteIP") or "").strip()
    ips = _normalize_parasitic_ips(
        item.get("ips")
        or item.get("IPs")
        or info.get("IPs")
        or info.get("ips")
        or info.get("real_ips")
        or info.get("webrtc_ips")
    )
    if ips:
        info["real_ips"] = ips
        info["IPs"] = ips
    if target and "path" not in info:
        info["path"] = target

    fingerprint = str(item.get("fingerprint") or info.get("fingerprint") or info.get("Fingerprint") or "").strip()
    if fingerprint in ("<nil>", "null", "None"):
        fingerprint = ""
    group_id = item.get("group_id")
    try:
        if group_id not in (None, ""):
            info["group_id"] = int(group_id)
    except Exception:
        info["group_id"] = group_id

    try:
        trigger_time = _parse_parasitic_trigger_time(item.get("time"))
    except Exception:
        return None

    return {
        "src_ip": remote_ip,
        "dst_ip": _clean_str(ips[0] if ips else None),
        "url": _clean_str(target) or "unknown",
        "trigger_time": trigger_time,
        "fingerprint": _clean_str(fingerprint),
        "info": info,
    }


def _parasitic_logical_key(payload):
    trigger_time = payload.get("trigger_time")
    bucket = ""
    if trigger_time:
        try:
            bucket = int(math.floor(trigger_time.timestamp() / 60))
        except Exception:
            bucket = str(trigger_time)[:16]
    return (
        str(payload.get("src_ip") or "").strip(),
        str(payload.get("url") or "").strip(),
        str(payload.get("fingerprint") or "").strip(),
        str(payload.get("info", {}).get("sessionToken") or payload.get("info", {}).get("session_token") or "").strip(),
        bucket,
    )


def get_parasitic_alert(last_query_time, page_size=100):
    # ── 修复 SQLite 读回 naive datetime 导致与 aware datetime 比较报错 ──
    if last_query_time is not None and last_query_time.tzinfo is None:
        last_query_time = pytz.timezone("Asia/Shanghai").localize(last_query_time)

    page = 1
    inserted = 0
    seen_keys = set()
    query_time_text = last_query_time.isoformat() if last_query_time else ""
    headers = {
        "Authorization": f"Bearer {Server_config.api_key}",
        "Content-Type": "application/json",
    }
    while True:
        req_err, response = _alert_server_request(
            "parasitic logs pull",
            "GET",
            _parasitic_logs_api_url(),
            params={"page": page, "size": page_size},
            headers=headers,
            timeout=15,
        )
        if req_err:
            return 1, str(response)
        if response.status_code != 200:
            return 1, f"js/bot logs status={response.status_code}"
        try:
            payload = response.json()
        except Exception as e:
            return 1, f"js/bot returned non-json response: {e}"

        rows = payload.get("data") or []
        if not rows:
            break

        for item in rows:
            normalized = _normalize_parasitic_row(item)
            if not normalized:
                continue
            if last_query_time and normalized["trigger_time"] <= last_query_time:
                continue

            logical_key = _parasitic_logical_key(normalized)
            if logical_key in seen_keys:
                continue
            seen_keys.add(logical_key)

            duplicate_start = normalized["trigger_time"] - timedelta(seconds=60)
            duplicate_end = normalized["trigger_time"] + timedelta(seconds=60)
            existing = UrlAlertInfo.query.filter(
                UrlAlertInfo.trigger_time >= duplicate_start,
                UrlAlertInfo.trigger_time <= duplicate_end,
                UrlAlertInfo.src_ip == normalized["src_ip"],
                UrlAlertInfo.url == normalized["url"],
                UrlAlertInfo.fingerprint == normalized["fingerprint"],
            ).all()
            if any(_is_official_parasitic_alert_row(row) for row in existing):
                continue

            record = UrlAlertInfo(
                honeypoint_id=1,
                src_ip=normalized["src_ip"],
                dst_ip=normalized["dst_ip"],
                url=normalized["url"],
                trigger_time=normalized["trigger_time"],
                report_time=datetime.now(pytz.timezone("Asia/Shanghai")),
                fingerprint=normalized["fingerprint"] or None,
                info=normalized["info"],
            )
            db.session.add(record)
            db.session.flush()
            ingest_parasitic_alert(
                source_service="systemwire2_pull_js_bot",
                source_event_id=f"pull-parasitic-{record.id}",
                trigger_time=record.trigger_time,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                url=record.url,
                fingerprint=record.fingerprint or "",
                info_payload=record.info,
                raw_payload=item,
                legacy_row_id=record.id,
            )
            inserted += 1

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return 1, f"insert parasitic alert error: {e}"

        total = int(payload.get("total") or 0)
        if total <= page * page_size or len(rows) < page_size:
            break
        page += 1

    current_app.logger.info("[Parasitic Alert] pulled %s official js/bot rows since %s", inserted, query_time_text or "-")
    return 0, inserted


def _enrich_file_alert_json(alert_info):
    token_raw = _normalize_file_token(alert_info.get("token"))
    alert_info["token_raw"] = token_raw
    alert_info["source"] = "alert_server -> systemwire2"
    alert_info["filename"] = "-"
    alert_info["filename_tag"] = "-"
    alert_info["honeypoint_name"] = "-"
    alert_info["company"] = "-"
    alert_info["deployment_summary"] = "-"
    alert_info["deployments"] = []

    if not token_raw:
        return alert_info

    honeyfile = _find_honeyfile_by_token(token_raw)
    if not honeyfile:
        return alert_info

    file_info = honeyfile.to_json()
    alert_info["honeyfile_id"] = honeyfile.id
    alert_info["filename"] = file_info.get("filename") or honeyfile.name
    alert_info["filename_tag"] = file_info.get("filename_tag") or honeyfile.name
    alert_info["honeypoint_name"] = file_info.get("honeypoint_name") or "-"
    alert_info["company"] = file_info.get("company") or "-"

    deployments = Filedeploy.query.filter_by(honeypoint_id=honeyfile.id).all()
    deploy_infos = [deploy.to_json() for deploy in deployments]
    alert_info["deployments"] = deploy_infos

    if deploy_infos:
        parts = []
        for deploy in deploy_infos[:3]:
            host = deploy.get("hostname") or deploy.get("host_ip") or "-"
            path = deploy.get("path") or "-"
            parts.append(f"{host}:{path}")
        if len(deploy_infos) > 3:
            parts.append(f"+{len(deploy_infos) - 3} more")
        alert_info["deployment_summary"] = "; ".join(parts)

    return alert_info


def _file_alert_to_view_info(record):
    alert_info = _enrich_file_alert_json(record.to_json())
    alert_info["alert_time"] = record.trigger_time.strftime("%Y-%m-%d %H:%M:%S")
    alert_info["_trigger_time"] = record.trigger_time
    alert_info["first_alert_time"] = alert_info["alert_time"]
    alert_info["last_alert_time"] = alert_info["alert_time"]
    alert_info["request_count"] = 1
    alert_info["raw_ids"] = [record.id]
    return alert_info


def _aggregate_file_alert_infos(records):
    grouped_alerts = []

    for record in records:
        alert_info = _file_alert_to_view_info(record)
        trigger_time = alert_info["_trigger_time"]
        key = _file_alert_logical_key(
            alert_info.get("token_raw") or alert_info.get("token"),
            alert_info.get("reportIp"),
            alert_info.get("reportAgent"),
            alert_info.get("alert_message"),
        )

        matched = None
        for group in grouped_alerts:
            if group["_logical_key"] != key:
                continue
            if any(_file_alert_in_same_open(trigger_time, seen_time) for seen_time in group["_seen_times"]):
                matched = group
                break

        if not matched:
            alert_info["_logical_key"] = key
            alert_info["_seen_times"] = [trigger_time]
            alert_info["_first_time"] = trigger_time
            alert_info["_last_time"] = trigger_time
            grouped_alerts.append(alert_info)
            continue

        matched["request_count"] += 1
        matched["raw_ids"].append(record.id)
        matched["_seen_times"].append(trigger_time)
        if trigger_time < matched["_first_time"]:
            matched["_first_time"] = trigger_time
            matched["first_alert_time"] = trigger_time.strftime("%Y-%m-%d %H:%M:%S")
        if trigger_time > matched["_last_time"]:
            matched["_last_time"] = trigger_time
            matched["last_alert_time"] = trigger_time.strftime("%Y-%m-%d %H:%M:%S")
            matched["alert_time"] = matched["last_alert_time"]
            matched["id"] = record.id

    for group in grouped_alerts:
        group["raw_ids_text"] = ", ".join(str(item) for item in sorted(group["raw_ids"]))
        group.pop("_logical_key", None)
        group.pop("_seen_times", None)
        group.pop("_first_time", None)
        group.pop("_last_time", None)
        group.pop("_trigger_time", None)

    return grouped_alerts


def _datetime_to_text(value):
    if not value or value == datetime.min:
        return ""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _tcp_listen_status(host, port, timeout=0.8):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return {"listening": sock.connect_ex((host, int(port))) == 0, "host": host, "port": int(port)}
    except Exception as exc:
        return {"listening": False, "host": host, "port": int(port), "error": str(exc)}
    finally:
        sock.close()


def _maybe_text(value):
    if value in (None, "", "-"):
        return None
    return str(value)


def _latest_alert_event_summary(alert_type):
    event = UnifiedAlertEvent.query.filter_by(alert_type=alert_type).order_by(UnifiedAlertEvent.alert_time.desc()).first()
    if not event:
        return None
    return {
        "id": event.id,
        "title": event.title,
        "src_ip": event.src_ip,
        "alert_time": _datetime_to_text(event.alert_time),
        "source_service": event.source_service,
    }


def _resolve_generated_honeyfile_path(file_obj):
    generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
    return os.path.join(generate_dir, file_obj.name)


def _honeyfile_upload_dir():
    return os.path.join(project_path, "Honeyfiles", "upload")


def _honeyfile_archive_dir():
    archive_dir = os.path.join(project_path, "Honeyfiles", "archive")
    os.makedirs(archive_dir, exist_ok=True)
    return archive_dir


def _safe_honeyfile_name(value, fallback):
    raw = str(value or "").strip().replace("\\", "_").replace("/", "_")
    raw = raw.replace(":", "_").replace("*", "_").replace("?", "_")
    raw = raw.replace('"', "_").replace("<", "_").replace(">", "_").replace("|", "_")
    return raw or fallback


def _infer_template_name_from_honeyfile(file_obj):
    source_file_name = str(getattr(file_obj, "source_file_name", "") or "").strip()
    if source_file_name:
        lowered = source_file_name.lower()
        if lowered.startswith("template-"):
            suffix = source_file_name[len("template-"):]
            if suffix.lower().endswith(f".{str(file_obj.doc_format or '').lower()}"):
                return suffix[: -(len(file_obj.doc_format) + 1)]
    generated_name = str(getattr(file_obj, "name", "") or "").strip()
    if generated_name.lower().startswith("word_placeholder_"):
        return ""
    if generated_name.lower().startswith("excel_placeholder_"):
        return ""
    return ""


def _resolve_honeyfile_source_path(file_obj):
    upload_dir = _honeyfile_upload_dir()
    archive_dir = _honeyfile_archive_dir()
    source = int(getattr(file_obj, "source", 0) or 0)

    if source == 1:
        candidates = []
        for attr_name in ("source_archive_name", "source_file_name"):
            candidate_name = str(getattr(file_obj, attr_name, "") or "").strip()
            if candidate_name:
                candidates.append(os.path.join(archive_dir, candidate_name))
                candidates.append(os.path.join(upload_dir, candidate_name))
        base_name = str(getattr(file_obj, "name", "") or "").strip()
        if base_name:
            raw_name = base_name.rsplit("-", 1)[0] + "." + str(file_obj.doc_format or "").lower()
            candidates.append(os.path.join(upload_dir, raw_name))
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    template_name = str(getattr(file_obj, "source_template_name", "") or "").strip()
    if not template_name:
        template_name = _infer_template_name_from_honeyfile(file_obj)
        if template_name:
            file_obj.source_template_name = template_name
    ext = str(file_obj.doc_format or "").lower()
    template_filename = f"template-{template_name}.{ext}" if template_name else f"template.{ext}"
    template_path = os.path.join(project_path, "template", template_filename)
    if os.path.isfile(template_path):
        file_obj.source_file_name = template_filename
        return template_path
    return None


def _archive_honeyfile_source(file_obj, source_path):
    if not source_path or not os.path.isfile(source_path):
        return None
    archive_dir = _honeyfile_archive_dir()
    ext = os.path.splitext(source_path)[1] or f".{str(file_obj.doc_format or '').lower()}"
    archive_name = _safe_honeyfile_name(
        getattr(file_obj, "source_archive_name", None),
        f"honeyfile-{file_obj.id}-source{ext}",
    )
    archive_path = os.path.join(archive_dir, archive_name)
    if os.path.abspath(source_path) != os.path.abspath(archive_path):
        shutil.copy2(source_path, archive_path)
    file_obj.source_archive_name = archive_name
    return archive_path


def _ensure_honeyfile_source_metadata(file_obj):
    changed = False
    source = int(getattr(file_obj, "source", 0) or 0)

    if not getattr(file_obj, "token_alert_msg", None):
        base_message = str(file_obj.message or "local-lab-demo").strip() or "local-lab-demo"
        file_obj.token_alert_msg = f"{base_message}::file::{file_obj.id}"
        changed = True

    if source == 1:
        if not getattr(file_obj, "source_file_name", None):
            base_name = str(file_obj.name or "").strip()
            if base_name:
                file_obj.source_file_name = base_name.rsplit("-", 1)[0] + "." + str(file_obj.doc_format or "").lower()
                changed = True
        source_path = _resolve_honeyfile_source_path(file_obj)
        if source_path:
            archive_path = _archive_honeyfile_source(file_obj, source_path)
            if archive_path:
                changed = True
    else:
        template_name = str(getattr(file_obj, "source_template_name", "") or "").strip()
        inferred_template = _infer_template_name_from_honeyfile(file_obj)
        if not template_name and inferred_template != "":
            file_obj.source_template_name = inferred_template
            template_name = inferred_template
            changed = True
        ext = str(file_obj.doc_format or "").lower()
        expected_template_filename = f"template-{template_name}.{ext}" if template_name else f"template.{ext}"
        if getattr(file_obj, "source_file_name", None) != expected_template_filename:
            file_obj.source_file_name = expected_template_filename
            changed = True

    return changed


def _regenerate_honeyfile_document(file_obj, token_url):
    source_path = _resolve_honeyfile_source_path(file_obj)
    if not source_path or not os.path.isfile(source_path):
        return 1, f"source document missing for honeyfile {file_obj.id}"

    generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
    os.makedirs(generate_dir, exist_ok=True)
    target_path = os.path.join(generate_dir, str(file_obj.name or "").strip())
    doc_format = str(file_obj.doc_format or "").lower()

    try:
        if doc_format == "docx":
            rendered_bytes = make_canary_msword_add(source_path, url=token_url)
        elif doc_format == "xlsx":
            rendered_bytes = make_canary_msexcel2(source_path, url=token_url)
        else:
            return 1, f"unsupported honeyfile format: {doc_format}"
        with open(target_path, "wb") as f:
            f.write(rendered_bytes)
        return 0, target_path
    except Exception as exc:
        return 1, str(exc)


def _ensure_local_honeyfile_is_live(file_obj, *, force_refresh=False):
    if file_obj is None:
        return 1, "missing file record"
    metadata_changed = _ensure_honeyfile_source_metadata(file_obj)
    if (not force_refresh) and _is_live_file_alert_token(file_obj.token):
        file_path = _resolve_generated_honeyfile_path(file_obj)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    if str(file_obj.token).encode("utf-8") in f.read():
                        if metadata_changed:
                            db.session.add(file_obj)
                            db.session.commit()
                        return 0, file_path
            except Exception:
                pass
        fallback = Honeyfile.query.filter(
            Honeyfile.id != file_obj.id,
            or_(
                Honeyfile.token.like("%/static/img/logo-%.png"),
                Honeyfile.token.like("%/contact/%"),
            ),
            Honeyfile.doc_format == file_obj.doc_format,
        ).order_by(Honeyfile.id.desc()).first()
        if fallback:
            fallback_path = _resolve_generated_honeyfile_path(fallback)
            if os.path.isfile(fallback_path):
                try:
                    with open(fallback_path, "rb") as f:
                        if str(fallback.token).encode("utf-8") in f.read():
                            if metadata_changed:
                                db.session.add(file_obj)
                                db.session.commit()
                            return 0, fallback_path
                except Exception:
                    pass

    try:
        token_seed = str(
            getattr(file_obj, "token_alert_msg", None)
            or f"{str(file_obj.message or 'local-lab-demo').strip() or 'local-lab-demo'}::file::{file_obj.id}"
        )
        err, token_or_msg = _issue_file_alert_token(file_obj.email or "local@example.com", token_seed)
        if err:
            return 1, f"apply live token failed: {token_or_msg}"
        file_obj.token = token_or_msg
        file_obj.token_alert_msg = token_seed
        code, target_path = _regenerate_honeyfile_document(file_obj, file_obj.token)
        if code:
            return 1, f"regenerate honeyfile failed: {target_path}"
        db.session.add(file_obj)
        db.session.commit()
        return 0, target_path
    except Exception as exc:
        db.session.rollback()
        return 1, str(exc)


def _iter_live_honeyfiles():
    for file_obj in Honeyfile.query.order_by(Honeyfile.id.asc()).all():
        if str(file_obj.doc_format or "").lower() not in ("docx", "xlsx"):
            continue
        yield file_obj


def _repair_all_local_honeyfiles(force_refresh=False):
    repaired = []
    skipped = []
    changed_sources = []
    for file_obj in _iter_live_honeyfiles():
        ensure_err, ensure_msg = _ensure_local_honeyfile_is_live(file_obj, force_refresh=force_refresh)
        if ensure_err:
            skipped.append({"file_id": file_obj.id, "filename": file_obj.name, "reason": str(ensure_msg)})
        else:
            repaired.append({"file_id": file_obj.id, "filename": file_obj.name, "path": str(ensure_msg)})
        if getattr(file_obj, "source_archive_name", None) or getattr(file_obj, "source_file_name", None):
            changed_sources.append(
                {
                    "file_id": file_obj.id,
                    "filename": file_obj.name,
                    "source_file_name": getattr(file_obj, "source_file_name", None),
                    "source_archive_name": getattr(file_obj, "source_archive_name", None),
                    "source_template_name": getattr(file_obj, "source_template_name", None),
                }
            )
    try:
        refresh_file_alert_metadata()
        db.session.commit()
    except Exception:
        db.session.rollback()
    return {
        "repaired": repaired,
        "skipped": skipped,
        "source_metadata": changed_sources,
        "force_refresh": bool(force_refresh),
        "repaired_count": len(repaired),
        "skipped_count": len(skipped),
    }


def _queue_agent_cmd(agent_id, cmd_type, payload, operate_type):
    grpc_server = get_grpc_server()
    agent = grpc_server.agent_list.get(agent_id)
    if agent is None or str(getattr(agent, "status", "offline") or "offline").lower() != "online":
        return 1, "agent is offline or does not exist"

    queue = grpc_server.commond_queue.get(agent_id)
    if queue is None:
        return 1, "agent command queue is not ready"

    cmd_id = generate_uint64_id()
    cmd_payload = json.dumps(payload, ensure_ascii=False)
    cmd_message = pb2.Cmd(id=cmd_id, type=cmd_type, data=cmd_payload)

    log = AgentControlLog()
    log.operate_id = cmd_id
    log.client_id = agent_id
    log.operate_type = operate_type
    log.detail = payload
    try:
        db.session.add(log)
        db.session.commit()
        queue.put(cmd_message)
        return 0, {"cmd_id": cmd_id, "agent_id": agent_id}
    except Exception as exc:
        db.session.rollback()
        current_app.logger.error("agent command enqueue failed: %s", exc)
        return 1, str(exc)


def _normalize_existing_file_payload(detail):
    payload = _detail_to_dict(detail)
    deploy_paths = [str(path).strip() for path in (payload.get("deploy_paths") or []) if str(path).strip()]

    file_items = []
    files = payload.get("files") or []
    if isinstance(files, dict):
        files = [files]
    if not files and (payload.get("file_id") or payload.get("filename")):
        files = [{
            "file_id": payload.get("file_id"),
            "filename": payload.get("filename"),
            "download_url": payload.get("download_url"),
        }]

    for item in files:
        if not isinstance(item, dict):
            item = {"file_id": item}
        try:
            file_id = int(item.get("file_id"))
        except (TypeError, ValueError):
            continue
        file_obj = Honeyfile.query.filter_by(id=file_id).first()
        if not file_obj:
            continue
        file_items.append({
            "file_id": file_id,
            "filename": item.get("filename") or file_obj.to_json().get("filename") or file_obj.name,
            "download_url": _local_agent_download_url(file_id),
        })

    if not deploy_paths or not file_items:
        return None

    return {
        "files": file_items,
        "file_ids": [item["file_id"] for item in file_items],
        "file_id": file_items[0]["file_id"],
        "filename": file_items[0]["filename"],
        "download_url": file_items[0]["download_url"],
        "deploy_paths": deploy_paths,
        "monitor": bool(payload.get("monitor", True)),
    }


def _replay_latest_file_deployments():
    replayed = []
    skipped = []
    rows = (
        AgentControlLog.query.filter(AgentControlLog.operate_type == "deploy_file_honeypot")
        .order_by(AgentControlLog.id.desc())
        .limit(200)
        .all()
    )
    seen_targets = set()
    for row in rows:
        payload = _normalize_existing_file_payload(row.detail)
        if payload is None:
            skipped.append({"log_id": row.id, "reason": "invalid deploy_file_honeypot detail"})
            continue

        dedupe_key = json.dumps(
            {
                "agent_id": row.client_id,
                "deploy_paths": payload.get("deploy_paths"),
                "file_ids": payload.get("file_ids"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if dedupe_key in seen_targets:
            continue
        seen_targets.add(dedupe_key)

        err, info = _queue_agent_cmd(row.client_id, 6, payload, "deploy_file_honeypot_repair")
        if err:
            skipped.append({"log_id": row.id, "agent_id": row.client_id, "reason": str(info)})
            continue
        replayed.append({"log_id": row.id, "agent_id": row.client_id, "cmd_id": info.get("cmd_id")})
    return {"replayed": replayed, "skipped": skipped}


def _normalize_existing_parasitic_payload(detail):
    payload = _detail_to_dict(detail)
    target_dir = _normalize_parasitic_target_dir(payload.get("target_dir"))
    if not target_dir or not _is_valid_parasitic_target_dir(target_dir):
        return None
    try:
        js_content = _load_builtin_parasitic_js_bundle()
    except Exception as exc:
        current_app.logger.warning("load builtin parasitic js bundle failed during repair: %s", exc)
        return None
    return {
        "target_dir": target_dir,
        "js_url": "",
        "js_content": js_content,
        "js_bundle": "builtin_root_js",
        "js_bundle_files": PARASITIC_BUILTIN_JS_FILES,
        "inject_mode": "inline",
        "backup": bool(payload.get("backup", True)),
    }


def _replay_latest_parasitic_deployments():
    replayed = []
    skipped = []
    rows = (
        AgentControlLog.query.filter(AgentControlLog.operate_type == "deploy_parasitic")
        .order_by(AgentControlLog.id.desc())
        .limit(200)
        .all()
    )
    seen_targets = set()
    for row in rows:
        payload = _normalize_existing_parasitic_payload(row.detail)
        if payload is None:
            skipped.append({"log_id": row.id, "reason": "invalid deploy_parasitic detail"})
            continue

        dedupe_key = json.dumps(
            {"agent_id": row.client_id, "target_dir": payload.get("target_dir")},
            ensure_ascii=False,
            sort_keys=True,
        )
        if dedupe_key in seen_targets:
            continue
        seen_targets.add(dedupe_key)

        err, info = _queue_agent_cmd(row.client_id, 7, payload, "deploy_parasitic_repair")
        if err:
            skipped.append({"log_id": row.id, "agent_id": row.client_id, "reason": str(info)})
            continue
        replayed.append({"log_id": row.id, "agent_id": row.client_id, "cmd_id": info.get("cmd_id")})
    return {"replayed": replayed, "skipped": skipped}


def repair_honeypot_delivery_chain():
    result = {
        "file_honeyfiles": _repair_all_local_honeyfiles(),
        "file_redeploy": {"replayed": [], "skipped": []},
        "parasitic_reinject": {"replayed": [], "skipped": []},
    }
    try:
        grpc_server = get_grpc_server()
        if getattr(grpc_server, "commond_queue", None) is not None:
            result["file_redeploy"] = _replay_latest_file_deployments()
            result["parasitic_reinject"] = _replay_latest_parasitic_deployments()
    except Exception as exc:
        current_app.logger.warning("honeypot delivery chain replay skipped: %s", exc)
        result["grpc_warning"] = str(exc)
    return result


@api.route("/api/honeypot/repair", methods=["POST"])
def api_honeypot_repair():
    try:
        result = repair_honeypot_delivery_chain()
        return jsonify({"code": 0, "message": "success", "data": result})
    except Exception as exc:
        current_app.logger.exception("honeypot repair failed")
        return jsonify({"code": 1, "message": f"honeypot repair failed: {exc}", "data": {}}), 500


@api.route("/api/honeypot/file/refresh-all", methods=["POST"])
def api_refresh_all_honeyfiles():
    try:
        force_refresh = str(request.args.get("force", "1")).strip().lower() not in ("0", "false", "no")
        result = _repair_all_local_honeyfiles(force_refresh=force_refresh)
        return jsonify({"code": 0, "message": "success", "data": result})
    except Exception as exc:
        current_app.logger.exception("refresh all honeyfiles failed")
        return jsonify({"code": 1, "message": f"refresh all honeyfiles failed: {exc}", "data": {}}), 500


def _file_honeypot_diagnostics():
    file_obj = Honeyfile.query.order_by(Honeyfile.id.asc()).first()
    payload = {
        "record_exists": file_obj is not None,
        "latest_alert": _latest_alert_event_summary("file"),
    }
    if file_obj is None:
        payload["status"] = "missing_honeyfile_record"
        return payload

    file_path = _resolve_generated_honeyfile_path(file_obj)
    payload.update(
        {
            "file_id": file_obj.id,
            "filename": file_obj.name,
            "token": file_obj.token,
            "live_token": _is_live_file_alert_token(file_obj.token),
            "file_exists": os.path.isfile(file_path),
            "file_path": file_path,
        }
    )
    if os.path.isfile(file_path):
        try:
            with open(file_path, "rb") as f:
                payload["token_embedded"] = str(file_obj.token or "").encode("utf-8") in f.read()
        except Exception as exc:
            payload["token_embedded"] = False
            payload["file_error"] = str(exc)
    else:
        payload["token_embedded"] = False

    fallback = Honeyfile.query.filter(
        Honeyfile.id != file_obj.id,
        Honeyfile.token.like("%/contact/%"),
        Honeyfile.doc_format == file_obj.doc_format,
    ).order_by(Honeyfile.id.desc()).first()
    if fallback:
        fallback_path = _resolve_generated_honeyfile_path(fallback)
        payload["fallback_file"] = fallback.name
        payload["fallback_ready"] = os.path.isfile(fallback_path)

    if not payload["live_token"]:
        payload["status"] = "fake_or_missing_token"
        payload["reason"] = "default honeyfile token is not a real /static/img/logo-<token>.png callback URL"
    elif not payload["file_exists"]:
        payload["status"] = "generated_file_missing"
        payload["reason"] = "database record exists, but the generated honeyfile is missing on disk"
    elif not payload["token_embedded"]:
        if payload.get("fallback_ready"):
            payload["status"] = "generated_file_stale_but_download_fallback_ready"
            payload["reason"] = "default demo file is stale, but agent downloads will fall back to another verified live-token honeyfile"
        else:
            payload["status"] = "generated_file_stale"
            payload["reason"] = "generated honeyfile exists, but the current live token is not embedded in the file"
    else:
        payload["status"] = "ready"
        payload["reason"] = "database token and generated file content are aligned"
    return payload


def _account_honeypot_diagnostics():
    last_record = AccountAlertInfo.query.order_by(AccountAlertInfo.trigger_time.desc()).first()
    payload = {
        "status": "ready" if _tcp_listen_status("127.0.0.1", 22).get("listening") else "ssh_not_listening",
        "ssh_listener": _tcp_listen_status("127.0.0.1", 22),
        "latest_raw_record_time": _datetime_to_text(last_record.trigger_time) if last_record else None,
        "latest_alert": _latest_alert_event_summary("account"),
    }
    if not payload["ssh_listener"]["listening"]:
        payload["reason"] = "ssh-vpn honeypot is not listening on port 22, so login tests cannot generate source events"
    else:
        payload["reason"] = "ssh honeypot listener is up; if alerts still do not appear, check whether clients are actually connecting to 22"
    return payload


def _parasitic_honeypot_diagnostics():
    last_record = UrlAlertInfo.query.order_by(UrlAlertInfo.trigger_time.desc()).first()
    payload = {
        "latest_raw_record_time": _datetime_to_text(last_record.trigger_time) if last_record else None,
        "latest_alert": _latest_alert_event_summary("parasitic"),
        "source_api": _parasitic_logs_api_url() if _parasitic_server_base_url() else None,
    }
    alert_server_status = _tcp_listen_status("127.0.0.1", 9090)
    payload["js_bot_server"] = alert_server_status
    if not alert_server_status.get("listening"):
        payload["status"] = "js_bot_not_listening"
        payload["reason"] = "alert_server/js-bot endpoint is unavailable on 9090"
    else:
        payload["status"] = "ready_but_needs_browser_execution"
        payload["reason"] = "injected HTML must be opened in a browser context that actually executes the inline JS and sends /info, /ips or /bot-check requests"
    return payload


def _agent_to_dict(agent, idx=None):
    client_id = getattr(agent, "client_id", None) or idx
    status = str(getattr(agent, "status", "offline") or "offline").lower()
    name = (
        getattr(agent, "client_name", None)
        or getattr(agent, "hostname", None)
        or getattr(agent, "name", None)
        or f"Agent-{client_id}"
    )
    return {
        "id": client_id,
        "client_id": client_id,
        "name": name,
        "client_name": name,
        "hostname": getattr(agent, "hostname", None) or "",
        "ope_sys": getattr(agent, "ope_sys", None) or "-",
        "ip": getattr(agent, "ip", None) or "",
        "status": status,
        "status_text": "在线" if status == "online" else "离线",
        "token": getattr(agent, "token", None) or "",
        "register_time": _datetime_to_text(getattr(agent, "register_time", None)),
        "last_beat_time": _datetime_to_text(getattr(agent, "last_beat_time", None)),
        "arch": getattr(agent, "arch", None) or "",
    }


def _build_agent_infos(grpc_server, include_offline=False):
    merged = {}

    for idx, agent in getattr(grpc_server, "agent_list", {}).items():
        info = _agent_to_dict(agent, idx)
        if include_offline or info["status"] == "online":
            merged[info["client_id"]] = info

    if include_offline:
        try:
            for row in ClientInfo.query.order_by(ClientInfo.id.desc()).all():
                info = row.to_json()
                client_id = info.get("client_id")
                if not client_id or client_id in merged:
                    continue
                merged[client_id] = _agent_to_dict(row, client_id)
        except Exception as e:
            current_app.logger.warning("Load offline agents from ClientInfo failed: %s", e)

    return sorted(
        merged.values(),
        key=lambda item: (item.get("status") != "online", item.get("client_name") or item.get("client_id") or ""),
    )


# 告警-文件
@api.route("/manage/alert/file")
def manage_alert_file():
    days = request.args.get("days", default=7, type=int)
    if days == "" or not days:
        days = 7    # 默认查询七天内的告警
    elif not isinstance(days,int):
        return jsonify({"code": 1, "message": "参数格式有误", "data": {}})
    elif days<0 or days>30: # 最多支持查询30天内告警
        return jsonify({"code": 1, "message": "最多支持查询30天内告警", "data": {}})
    alert_infos, raw_alert_total = get_file_alert_page_rows(days=days)
    if not alert_infos:
        time_period = get_time_bj() - timedelta(days=days)
        alerts = FileAlertInfo.query\
            .filter(FileAlertInfo.trigger_time>time_period)\
            .order_by(FileAlertInfo.trigger_time.desc())\
            .all()
        alert_infos = _aggregate_file_alert_infos(alerts)
        raw_alert_total = len(alerts)
    data = {
        "alert_infos":alert_infos,  # 查询结果
        "raw_alert_total":raw_alert_total,
        "last_days":days    # 上一次查询条件
    }
    return render_template('alert_file.html',**data)

# 寄生告警页面
@api.route("/manage/alert/parasitism")
def manage_alert_parasitism():
    days = request.args.get("days", default=7, type=int)
    data = {
        "last_days": days
    }
    return render_template('alert_parasitism.html', **data)

@api.route("/manage/alert/account")
def manage_alert_account():
    days = request.args.get("days", default=7, type=int)
    if days == "" or not days:
        days = 7
    elif not isinstance(days, int):
        return jsonify({"code": 1, "message": "Invalid parameter format", "data": {}})
    elif days < 0 or days > 30:
        return jsonify({"code": 1, "message": "Only support up to 30 days", "data": {}})

    alert_infos = get_account_alert_page_rows(days=days)
    if not alert_infos:
        time_period = get_time_bj() - timedelta(days=days)
        alerts = AccountAlertInfo.query\
            .filter(AccountAlertInfo.trigger_time > time_period)\
            .order_by(AccountAlertInfo.trigger_time.desc())\
            .all()
        alert_infos = []
        for item in alerts:
            alert_info = _enrich_account_alert_json(item.to_json())
            alert_info["alert_time"] = item.trigger_time.strftime("%Y-%m-%d %H:%M:%S")
            alert_infos.append(alert_info)
    data = {
        "alert_infos": alert_infos,
        "last_days": days
    }
    return render_template('alert_account.html', **data)

# 统一告警数据API
@api.route("/api/alerts/unified", methods=["GET"])
def api_alerts_unified():
    """获取统一格式的告警数据"""
    hours = request.args.get("hours", default=24, type=int)
    output = request.args.get("output", default="", type=str)

    try:
        alert_data = build_unified_alert_api_rows(hours=hours)

        if output:
            os.makedirs(os.path.dirname(output), exist_ok=True)
            with open(output, "w", encoding="utf-8") as f:
                json.dump(alert_data, f, ensure_ascii=False, indent=2)

        return jsonify({
            "code": 0,
            "message": "success",
            "data": {
                "alerts": alert_data,
                "total": len(alert_data),
                "hours": hours
            }
        })
    except Exception as e:
        current_app.logger.exception("Load unified alerts failed")
        return jsonify({
            "code": 1,
            "message": f"Load unified alerts failed: {e}",
            "data": {"alerts": [], "total": 0, "hours": hours}
        }), 500

# 告警统计API
@api.route("/api/alerts/statistics", methods=["GET"])
def api_alerts_statistics():
    """获取告警统计信息"""
    hours = request.args.get("hours", default=24, type=int)
    try:
        stats = build_unified_alert_statistics(hours)
        return jsonify({
            "code": 0,
            "message": "success",
            "data": stats
        })
    except Exception as e:
        current_app.logger.exception("Load alert statistics failed")
        return jsonify({"code": 1, "message": f"Load alert statistics failed: {e}", "data": {}}), 500

# 统一告警中心页面
@api.route("/manage/alert/unified")
def manage_alert_unified():
    return render_template('alert_unified.html')


@api.route("/manage/alert/analysis/live")
def manage_analysis_live():
    return render_template("analysis_live.html")


@api.route("/manage/analysis/live")
def manage_analysis_live_legacy():
    return redirect(url_for("api.manage_analysis_live"))


@api.route("/api/analysis/live", methods=["POST"])
def api_analysis_live():
    payload = request.get_json(silent=True) or {}
    hours = payload.get("hours", 24)
    run_dir = payload.get("run_dir")

    try:
        hours = int(hours)
    except (TypeError, ValueError):
        return jsonify({"code": 1, "message": "hours must be an integer", "data": {}}), 400

    if hours < 0:
        return jsonify({"code": 1, "message": "hours must be >= 0", "data": {}}), 400

    try:
        run_dir_path = _resolve_analysis_run_dir(run_dir) if run_dir else _default_live_analysis_run_dir()
    except ValueError as e:
        return jsonify({"code": 1, "message": str(e), "data": {}}), 400

    try:
        repo_root = _repo_root_path()
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from deployment.export_alerts_to_step1 import export_live as export_live_analysis

        summary = export_live_analysis(hours=hours, run_dir=run_dir_path)
        run_dir_text = _analysis_run_dir_text(run_dir_path)
        summary["run_dir"] = run_dir_text
        summary["analysis_result_url"] = url_for("api.manage_analysis_live", run_dir=run_dir_text)
        _write_latest_analysis_run(run_dir_path, summary)
        return jsonify({"code": 0, "message": "success", "data": summary})
    except Exception as e:
        current_app.logger.exception("Run live analysis failed")
        return jsonify({
            "code": 1,
            "message": _analysis_error_message("运行实时分析失败", e),
            "data": {"hours": hours, "run_dir": str(run_dir_path) if run_dir_path else ""},
        }), 500


@api.route("/api/analysis/live/balanced", methods=["POST"])
def api_analysis_live_balanced():
    payload = request.get_json(silent=True) or {}
    hours = payload.get("hours", 24)
    per_type = payload.get("per_type", 30)
    run_dir = payload.get("run_dir")
    exclude_ips = payload.get("exclude_ips", payload.get("exclude_ip", []))

    try:
        hours = int(hours)
    except (TypeError, ValueError):
        return jsonify({"code": 1, "message": "hours must be an integer", "data": {}}), 400

    if hours < 0:
        return jsonify({"code": 1, "message": "hours must be >= 0", "data": {}}), 400

    try:
        per_type = int(per_type)
    except (TypeError, ValueError):
        return jsonify({"code": 1, "message": "per_type must be an integer", "data": {}}), 400

    if per_type <= 0:
        return jsonify({"code": 1, "message": "per_type must be > 0", "data": {}}), 400
    if per_type > 1000:
        return jsonify({"code": 1, "message": "per_type must be <= 1000", "data": {}}), 400

    if isinstance(exclude_ips, str):
        exclude_ips = [item.strip() for item in exclude_ips.split(",") if item.strip()]
    elif isinstance(exclude_ips, (list, tuple, set)):
        exclude_ips = [str(item).strip() for item in exclude_ips if str(item).strip()]
    else:
        exclude_ips = []

    try:
        run_dir_path = _resolve_analysis_run_dir(run_dir) if run_dir else _default_balanced_analysis_run_dir()
    except ValueError as e:
        return jsonify({"code": 1, "message": str(e), "data": {}}), 400

    try:
        repo_root = _repo_root_path()
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from deployment.export_alerts_to_step1 import export_balanced_live as export_balanced_live_analysis

        summary = export_balanced_live_analysis(
            hours=hours,
            run_dir=run_dir_path,
            per_type=per_type,
            exclude_ips=exclude_ips,
        )
        run_dir_text = _analysis_run_dir_text(run_dir_path)
        summary["run_dir"] = run_dir_text
        summary["analysis_result_url"] = url_for("api.manage_analysis_live", run_dir=run_dir_text)
        _write_latest_analysis_run(run_dir_path, summary)
        return jsonify({"code": 0, "message": "success", "data": summary})
    except Exception as e:
        current_app.logger.exception("Run balanced live analysis failed")
        return jsonify({
            "code": 1,
            "message": _analysis_error_message("运行平衡分析失败", e),
            "data": {
                "hours": hours,
                "per_type": per_type,
                "run_dir": _analysis_run_dir_text(run_dir_path),
            },
        }), 500


@api.route("/api/analysis/live/scenario", methods=["POST"])
def api_analysis_live_scenario():
    payload = request.get_json(silent=True) or {}
    start_value = str(payload.get("start") or "").strip()
    end_value = str(payload.get("end") or "").strip()
    scenario_id = str(payload.get("scenario_id") or "").strip()
    chain_actor_id = str(payload.get("chain_actor_id") or "controlled_actor_001").strip() or "controlled_actor_001"
    run_dir = payload.get("run_dir")

    def normalize_list(value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    chain_ips = normalize_list(payload.get("chain_ips", payload.get("chain_ip", [])))
    chain_fingerprints = normalize_list(payload.get("chain_fingerprints", payload.get("chain_fingerprint", [])))
    chain_sessions = normalize_list(payload.get("chain_sessions", payload.get("chain_session", [])))
    chain_alert_ids = normalize_list(payload.get("chain_alert_ids", payload.get("chain_alert_id", [])))

    if not start_value or not end_value:
        return jsonify({"code": 1, "message": "start and end are required", "data": {}}), 400
    if not any([chain_ips, chain_fingerprints, chain_sessions, chain_alert_ids]):
        return jsonify({
            "code": 1,
            "message": "至少提供一个核心链标识：chain_ips、chain_fingerprints、chain_sessions 或 chain_alert_ids",
            "data": {},
        }), 400

    try:
        run_dir_path = _resolve_analysis_run_dir(run_dir) if run_dir else _default_scenario_analysis_run_dir()
    except ValueError as e:
        return jsonify({"code": 1, "message": str(e), "data": {}}), 400

    try:
        repo_root = _repo_root_path()
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from deployment.export_alerts_to_step1 import (
            _parse_scenario_timestamp,
            export_scenario_live as export_scenario_live_analysis,
        )

        start_time = _parse_scenario_timestamp(start_value)
        end_time = _parse_scenario_timestamp(end_value)
        if not scenario_id:
            scenario_id = f"controlled_chain_{start_time.strftime('%Y%m%d_%H%M%S')}"

        summary = export_scenario_live_analysis(
            start_time=start_time,
            end_time=end_time,
            run_dir=run_dir_path,
            scenario_id=scenario_id,
            chain_actor_id=chain_actor_id,
            chain_ips=chain_ips,
            chain_fingerprints=chain_fingerprints,
            chain_sessions=chain_sessions,
            chain_alert_ids=chain_alert_ids,
        )
        run_dir_text = _analysis_run_dir_text(run_dir_path)
        summary["run_dir"] = run_dir_text
        summary["analysis_result_url"] = url_for("api.manage_analysis_live", run_dir=run_dir_text)
        _write_latest_analysis_run(run_dir_path, summary)
        return jsonify({"code": 0, "message": "success", "data": summary})
    except Exception as e:
        current_app.logger.exception("Run controlled scenario analysis failed")
        return jsonify({
            "code": 1,
            "message": _analysis_error_message("运行受控实验分析失败", e),
            "data": {
                "start": start_value,
                "end": end_value,
                "run_dir": _analysis_run_dir_text(run_dir_path),
            },
        }), 500


@api.route("/api/analysis/live/llm-report", methods=["POST"])
def api_analysis_live_llm_report():
    payload = request.get_json(silent=True) or {}
    run_dir = str(payload.get("run_dir") or "").strip()
    task = str(payload.get("task") or "report").strip().lower()
    prompt_key_map = {
        "intent": "step4_intent",
        "intent_analysis": "step4_intent",
        "ttp": "step4_ttp",
        "ttp_mapping": "step4_ttp",
        "report": "step4_report",
    }
    prompt_key = prompt_key_map.get(task)
    if not prompt_key:
        return jsonify({"code": 1, "message": "task must be one of: intent, ttp, report", "data": {}}), 400

    try:
        paths, rel_paths = _analysis_paths(run_dir)
    except ValueError as e:
        return jsonify({"code": 1, "message": str(e), "data": {}}), 400

    prompt_path = Path(paths[prompt_key])
    if not prompt_path.exists():
        return _analysis_not_ready_response(
            paths,
            rel_paths,
            "尚未检测到 LLM prompt，请先运行实时分析或平衡分析。",
        )

    try:
        repo_root = _repo_root_path()
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from step4_graph_to_text.llm_client import generate_deepseek_report, load_deepseek_config

        config = load_deepseek_config()
        override_model = str(payload.get("model") or "").strip()
        if override_model:
            config.model = override_model
        if "temperature" in payload:
            try:
                config.temperature = max(0.0, min(1.5, float(payload.get("temperature"))))
            except (TypeError, ValueError):
                return jsonify({"code": 1, "message": "temperature must be a number", "data": {}}), 400
        if "max_tokens" in payload:
            try:
                config.max_tokens = max(256, min(12000, int(payload.get("max_tokens"))))
            except (TypeError, ValueError):
                return jsonify({"code": 1, "message": "max_tokens must be an integer", "data": {}}), 400

        prompt_text = _read_analysis_text(prompt_path, default="")
        result = generate_deepseek_report(prompt_text, config=config)
        meta = result.get("meta") or {}
        meta.update({
            "task": task,
            "prompt_path": rel_paths.get(prompt_key, ""),
            "report_path": rel_paths.get("step4_llm_report", ""),
            "meta_path": rel_paths.get("step4_llm_report_meta", ""),
            "run_dir": run_dir,
            "experiment_role": "llm_assisted_interpretation",
            "data_integrity_note": "LLM output is generated from Step4 prompt only and is not used as raw alert data or model-training label.",
        })

        if not result.get("ok"):
            status = result.get("status") or "llm_error"
            http_status = 400 if status in {"llm_config_missing", "prompt_missing"} else 502
            return jsonify({
                "code": 1,
                "message": result.get("message") or "Generate LLM report failed",
                "data": {"status": status, "meta": meta},
            }), http_status

        report_path = Path(paths["step4_llm_report"])
        report_meta_path = Path(paths["step4_llm_report_meta"])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(result.get("content") or "", encoding="utf-8")
        report_meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        return jsonify({
            "code": 0,
            "message": "success",
            "data": {
                "llm_report": result.get("content") or "",
                "llm_report_meta": meta,
                "paths": {
                    "prompt": rel_paths.get(prompt_key, ""),
                    "llm_report": rel_paths.get("step4_llm_report", ""),
                    "llm_report_meta": rel_paths.get("step4_llm_report_meta", ""),
                },
            },
        })
    except Exception as e:
        current_app.logger.exception("Generate LLM analysis report failed")
        return jsonify({"code": 1, "message": _analysis_error_message("生成 LLM 告警分析报告失败", e), "data": {}}), 500


@api.route("/api/analysis/live/summary", methods=["GET"])
def api_analysis_live_summary():
    run_dir = request.args.get("run_dir", "", type=str).strip()
    try:
        paths, rel_paths = _analysis_paths(run_dir)
        if not Path(paths["summary"]).exists():
            return _analysis_not_ready_response(paths, rel_paths)
        summary = _read_analysis_json(paths["summary"], default={}) or {}
        summary.setdefault("outputs", {})
        summary["paths"] = rel_paths
        if rel_paths.get("base_dir") and rel_paths.get("base_dir") != ".":
            summary.setdefault("run_dir", rel_paths.get("base_dir"))
        summary["available"] = _analysis_availability(paths)
        return jsonify({"code": 0, "message": "success", "data": summary})
    except Exception as e:
        current_app.logger.exception("Load analysis summary failed")
        return jsonify({"code": 1, "message": _analysis_error_message("读取分析摘要失败", e), "data": {}}), 500


@api.route("/api/analysis/live/events", methods=["GET"])
def api_analysis_live_events():
    run_dir = request.args.get("run_dir", "", type=str).strip()
    alert_type = request.args.get("type", "all", type=str).strip().lower()
    limit = request.args.get("limit", default=500, type=int)
    limit = max(1, min(limit, 5000))
    try:
        paths, rel_paths = _analysis_paths(run_dir)
        event_path = Path(paths["step1"])
        if not event_path.exists():
            return _analysis_not_ready_response(paths, rel_paths, "尚未检测到统一事件输出，请先运行实时分析。")
        events = _read_analysis_json(event_path, default=[]) or []
        if alert_type and alert_type != "all":
            events = [item for item in events if str(item.get("alert_type") or "").lower() == alert_type]
        total = len(events)
        events = events[:limit]
        return jsonify({
            "code": 0,
            "message": "success",
            "data": {
                "events": events,
                "total": total,
                "returned": len(events),
                "type": alert_type or "all",
                "paths": {
                    "step1": rel_paths.get("step1", ""),
                    "canonical_events": rel_paths.get("canonical_events", ""),
                },
            }
        })
    except Exception as e:
        current_app.logger.exception("Load analysis events failed")
        return jsonify({"code": 1, "message": _analysis_error_message("读取统一事件失败", e), "data": {"events": []}}), 500


@api.route("/api/analysis/live/triples", methods=["GET"])
def api_analysis_live_triples():
    run_dir = request.args.get("run_dir", "", type=str).strip()
    limit = request.args.get("limit", default=500, type=int)
    limit = max(1, min(limit, 5000))
    try:
        paths, rel_paths = _analysis_paths(run_dir)
        triple_path = Path(paths["step2_triples"])
        if not triple_path.exists():
            return _analysis_not_ready_response(paths, rel_paths, "尚未检测到标准三元组输出，请先运行实时分析。")
        rows = _normalize_analysis_triple_rows(_read_analysis_json(triple_path, default=[]))
        total = len(rows)
        rows = rows[:limit]
        return jsonify({
            "code": 0,
            "message": "success",
            "data": {
                "triples": rows,
                "total": total,
                "returned": len(rows),
                "paths": {
                    "step2_triples": rel_paths.get("step2_triples", ""),
                },
            }
        })
    except Exception as e:
        current_app.logger.exception("Load analysis triples failed")
        return jsonify({"code": 1, "message": _analysis_error_message("读取标准三元组失败", e), "data": {"triples": []}}), 500


@api.route("/api/analysis/live/graph", methods=["GET"])
def api_analysis_live_graph():
    run_dir = request.args.get("run_dir", "", type=str).strip()
    pruned = request.args.get("pruned", default=0, type=int)
    try:
        paths, rel_paths = _analysis_paths(run_dir)
        graph_key = "step3" if pruned else "step2"
        graph_path = Path(paths[graph_key])
        if not graph_path.exists():
            message = "尚未检测到裁剪图谱输出，请先运行实时分析。" if pruned else "尚未检测到攻击图谱输出，请先运行实时分析。"
            return _analysis_not_ready_response(paths, rel_paths, message)
        graph_data = _read_analysis_json(graph_path, default={}) or {}
        mermaid_text = _read_analysis_text(paths["step2_mermaid"], default="")
        graph_data["paths"] = {
            "graph": rel_paths.get(graph_key, ""),
            "mermaid": rel_paths.get("step2_mermaid", ""),
        }
        graph_data["mermaid"] = mermaid_text
        graph_data["mode"] = "pruned" if pruned else "full"
        return jsonify({"code": 0, "message": "success", "data": graph_data})
    except Exception as e:
        current_app.logger.exception("Load analysis graph failed")
        return jsonify({"code": 1, "message": _analysis_error_message("读取攻击图谱失败", e), "data": {}}), 500


@api.route("/api/analysis/live/text", methods=["GET"])
def api_analysis_live_text():
    run_dir = request.args.get("run_dir", "", type=str).strip()
    try:
        paths, rel_paths = _analysis_paths(run_dir)
        thesis_text = _read_analysis_text(paths["step4_thesis"], default="")
        llm_report_text = _read_analysis_text(paths["step4_llm_report"], default="")
        llm_report_meta = _read_analysis_json(paths["step4_llm_report_meta"], default={}) or {}
        prompt_files = {
            "intent_prompt": paths["step4_intent"],
            "ttp_prompt": paths["step4_ttp"],
            "report_prompt": paths["step4_report"],
        }
        prompt_payload = {}
        for key, path in prompt_files.items():
            prompt_payload[key] = _read_analysis_text(path, default="")

        payload = {
            "llm_report": llm_report_text,
            "llm_report_meta": llm_report_meta,
            "thesis_analysis": thesis_text,
            "intent_analysis": thesis_text or llm_report_text or prompt_payload.get("intent_prompt", ""),
            "ttp_mapping": thesis_text or llm_report_text or prompt_payload.get("ttp_prompt", ""),
            "report": llm_report_text or thesis_text or prompt_payload.get("report_prompt", ""),
            "debug_prompts": prompt_payload,
        }
        available = bool(llm_report_text.strip()) or bool(thesis_text.strip()) or any(bool(text.strip()) for text in prompt_payload.values())
        if not available:
            return _analysis_not_ready_response(paths, rel_paths, "尚未检测到图转文本结果，请先运行实时分析。")
        payload["paths"] = {
            "step4_intent": rel_paths.get("step4_intent", ""),
            "step4_ttp": rel_paths.get("step4_ttp", ""),
            "step4_report": rel_paths.get("step4_report", ""),
            "step4_thesis": rel_paths.get("step4_thesis", ""),
            "step4_llm_report": rel_paths.get("step4_llm_report", ""),
            "step4_llm_report_meta": rel_paths.get("step4_llm_report_meta", ""),
        }
        if llm_report_text.strip():
            payload["display_mode"] = "llm_report"
        elif thesis_text.strip():
            payload["display_mode"] = "thesis_analysis"
        else:
            payload["display_mode"] = "debug_prompt_fallback"
        return jsonify({"code": 0, "message": "success", "data": payload})
    except Exception as e:
        current_app.logger.exception("Load analysis texts failed")
        return jsonify({"code": 1, "message": _analysis_error_message("读取图转文本结果失败", e), "data": {}}), 500


@api.route("/api/alerts/diagnostics", methods=["GET"])
def api_alerts_diagnostics():
    diagnostics = {
        "services": {
            "systemwire2_5001": _tcp_listen_status("127.0.0.1", 5001),
            "alert_server_9090": _tcp_listen_status("127.0.0.1", 9090),
            "alert_server_9091": _tcp_listen_status("127.0.0.1", 9091),
        "ssh_honeypot_22": _tcp_listen_status("127.0.0.1", 22),
        },
        "alert_server_health": _alert_server_health_summary(),
        "file_honeypot": _file_honeypot_diagnostics(),
        "account_honeypot": _account_honeypot_diagnostics(),
        "parasitic_honeypot": _parasitic_honeypot_diagnostics(),
        "generated_at": datetime.now(pytz.timezone("Asia/Shanghai")).isoformat(),
    }
    return jsonify({"code": 0, "message": "success", "data": diagnostics})

@api.route("/manage/company", methods=["GET"])
def manage_company_list():
    # adress = Server_config.alert_server_manage_address
    adress = "http://192.168.3.105:8081"
    response = requests.get(adress+"/companys")  # 查询公司信息
    
    if 200<= response.status_code < 300:
        response_json = response.json()
        company_infos = response_json.get('data')
        data = {
            "company_infos":company_infos
        }
        return render_template('company_list.html',**data)
    else:
        jsonify({"code": 1, "message": f"{response.status_code}:{response.text}", "data": ""})
        
@api.route("/manage/company", methods=["POST"])
def manage_company_create():
    return

@api.route("/manage/agent/list")
def manage_agent_list():
    grpc_server = get_grpc_server()
    agents_infos = _build_agent_infos(grpc_server, include_offline=True)
    data = {
        "agents_infos":agents_infos,  # 查询结果
    }
    return render_template('agent_list.html',**data)

@api.route("/api/agent/list")  # ????????????
def api_agent_list():
    grpc_server = get_grpc_server()
    include_offline = request.args.get("all", default="0", type=str).lower() in ("1", "true", "yes")
    agents_infos = _build_agent_infos(grpc_server, include_offline=include_offline)
    return jsonify({"agents_infos": agents_infos})


# 查询发布命令记录
@api.route("/manage/agent/command/list")
def manage_agent_command_list():
    commands = AgentControlLog().query.all()
    commands_infos = []
    for item in commands:
        commands_infos.append(item.to_json())
    data = {
        "commands_infos":commands_infos,  # 查询结果
    }
    return render_template('agent_command_list.html',**data)

# 查询监控告警
@api.route("/manage/agent/alert")
def manage_agent_alert():
    alerts = MonitorAlert.query.all()
    alert_infos = []
    for item in alerts:
        alert_info = item.to_json()
        alert_info["trigger_time"] = _datetime_to_text(alert_info.get("trigger_time"))
        alert_info["report_time"] = _datetime_to_text(alert_info.get("report_time"))
        alert_info["proctitle_json"] = json.dumps(alert_info.get("proctitle") or {}, ensure_ascii=False, indent=2)
        alert_info["path_json"] = json.dumps(alert_info.get("path") or {}, ensure_ascii=False, indent=2)
        alert_infos.append(alert_info)
    data = {
        "infos":alert_infos,  # 查询结果
    }
    return render_template('agent_alert.html',**data)

# 文件蜜点部署页面
@api.route("/manage/honeypot/file")
def manage_honeypot_file():
    return render_template('file_honeypot_deploy.html')

# 账户蜜点部署页面
@api.route("/manage/honeypot/account")
def manage_honeypot_account():
    return render_template('account_deploy.html')

# 寄生蜜点部署页面
@api.route("/manage/honeypot/parasitic")
def manage_honeypot_parasitic():
    return render_template('parasitic_deploy.html')

# 向Agent发送命令API
@api.route("/api/agent/command", methods=["POST"])
def api_agent_command():
    data = request.get_json() or {}
    agent_id = data.get("agent_id")
    cmd_type = data.get("cmd_type")
    cmd_data = data.get("cmd_data", "")

    if not agent_id or cmd_type is None:
        return jsonify({"code": 1, "message": "missing agent_id or cmd_type", "data": {}})

    try:
        cmd_type = int(cmd_type)
    except (TypeError, ValueError):
        return jsonify({"code": 1, "message": "cmd_type must be an integer", "data": {}})

    grpc_server = get_grpc_server()
    agent = grpc_server.agent_list.get(agent_id)
    if agent is None or getattr(agent, "status", "offline") != "online":
        return jsonify({"code": 1, "message": "agent is offline or does not exist", "data": {}})

    queue = grpc_server.commond_queue.get(agent_id)
    if queue is None:
        return jsonify({"code": 1, "message": "agent command queue is not ready", "data": {}})

    from agent_server.proto import agent_pb2 as pb2

    cmd_id = generate_uint64_id()
    detail_for_log = cmd_data
    operate_type_map = {
        4: "add_account",
        6: "deploy_file_honeypot",
        7: "deploy_parasitic",
    }

    if cmd_type == 6:
        try:
            payload = json.loads(cmd_data) if isinstance(cmd_data, str) else dict(cmd_data)
        except Exception as e:
            return jsonify({"code": 1, "message": f"invalid file honeypot payload: {e}", "data": {}})

        deploy_paths = payload.get("deploy_paths") or []
        deploy_paths = [str(path).strip() for path in deploy_paths if str(path).strip()]
        if not deploy_paths:
            return jsonify({"code": 1, "message": "deploy_paths must contain at least one target directory", "data": {}})
        payload["deploy_paths"] = deploy_paths

        file_items = []
        if isinstance(payload.get("files"), list):
            file_items.extend(payload.get("files") or [])
        elif isinstance(payload.get("file_ids"), list):
            file_items.extend({"file_id": file_id} for file_id in payload.get("file_ids") or [])
        elif payload.get("file_id"):
            file_items.append({
                "file_id": payload.get("file_id"),
                "filename": payload.get("filename"),
                "download_url": payload.get("download_url"),
            })

        normalized_files = []
        for item in file_items:
            if not isinstance(item, dict):
                item = {"file_id": item}
            try:
                file_id = int(item.get("file_id"))
            except (TypeError, ValueError):
                return jsonify({"code": 1, "message": f"invalid file_id: {item.get('file_id')}", "data": {}})

            file_obj = Honeyfile.query.filter_by(id=file_id).first()
            if not file_obj:
                return jsonify({"code": 1, "message": f"honeyfile not found: {file_id}", "data": {}})

            download_url = str(item.get("download_url") or "").strip()
            if not download_url:
                download_url = _absolute_agent_download_url(file_id)
            elif download_url.startswith("/"):
                download_url = f"{request.host_url.rstrip('/')}{download_url}"

            normalized_files.append({
                "file_id": file_id,
                "filename": item.get("filename") or file_obj.to_json().get("filename") or file_obj.name,
                "download_url": download_url,
            })

        if not normalized_files:
            return jsonify({"code": 1, "message": "file honeypot payload requires file_id, file_ids or files", "data": {}})

        payload["files"] = normalized_files
        payload["file_id"] = normalized_files[0]["file_id"]
        payload["filename"] = normalized_files[0]["filename"]
        payload["download_url"] = normalized_files[0]["download_url"]

        detail_for_log = payload
        cmd_data = json.dumps(payload, ensure_ascii=False)
    elif cmd_type == 7:
        try:
            payload = json.loads(cmd_data) if isinstance(cmd_data, str) else dict(cmd_data)
        except Exception as e:
            return jsonify({"code": 1, "message": f"invalid parasitic payload: {e}", "data": {}})

        target_dir = _normalize_parasitic_target_dir(payload.get("target_dir"))
        if not target_dir:
            return jsonify({"code": 1, "message": "target_dir is required", "data": {}})
        if not os.path.isabs(target_dir):
            return jsonify({"code": 1, "message": "parasitic target_dir must be an absolute directory path", "data": {}})
        payload["target_dir"] = target_dir

        js_bundle = str(payload.get("js_bundle") or "").strip()
        js_url = str(payload.get("js_url") or "").strip()
        js_content = payload.get("js_content") or ""
        if js_bundle == "builtin_root_js":
            try:
                payload["js_content"] = _load_builtin_parasitic_js_bundle()
                payload["js_url"] = ""
                payload["inject_mode"] = "inline"
                payload["js_bundle_files"] = PARASITIC_BUILTIN_JS_FILES
            except Exception as e:
                return jsonify({"code": 1, "message": f"failed to load builtin js bundle: {e}", "data": {}})
            js_url = ""
            js_content = payload["js_content"]

        if js_url and not re.match(r"^https?://", js_url, re.IGNORECASE) and os.path.isfile(js_url):
            try:
                with open(js_url, "r", encoding="utf-8") as f:
                    payload["js_content"] = f.read()
                payload["js_url"] = ""
                if payload.get("inject_mode") == "script_tag":
                    payload["inject_mode"] = "inline"
            except Exception as e:
                return jsonify({"code": 1, "message": f"failed to load local js file: {e}", "data": {}})
        elif not js_url and not js_content:
            return jsonify({"code": 1, "message": "provide js_url or js_content", "data": {}})

        detail_for_log = payload
        cmd_data = json.dumps(payload, ensure_ascii=False)
    elif cmd_type == 4:
        if isinstance(cmd_data, str) and cmd_data.startswith("auto:"):
            return jsonify({"code": 1, "message": "automatic account generation is not supported by the current agent", "data": {}})
        if not isinstance(cmd_data, str):
            return jsonify({"code": 1, "message": "account command data must be a string", "data": {}})
        parts = cmd_data.split(":")
        account_type = parts[0].strip().lower() if parts else ""
        if account_type in ("xshell", "finalshell", "finall"):
            if len(parts) < 5:
                return jsonify({"code": 1, "message": "account payload requires type:host:port:username:password", "data": {}})
        elif account_type == "openvpn":
            if len(parts) < 3:
                return jsonify({"code": 1, "message": "openvpn payload requires openvpn:host:port", "data": {}})
        else:
            return jsonify({"code": 1, "message": f"unsupported account type: {account_type or '-'}", "data": {}})

        try:
            port = int(str(parts[2]).strip())
        except (TypeError, ValueError):
            return jsonify({"code": 1, "message": f"invalid port: {parts[2] if len(parts) > 2 else '-'}", "data": {}})
        if port < 1 or port > 65535:
            return jsonify({"code": 1, "message": f"invalid port: {port}, expected 1-65535", "data": {}})

    cmd_message = pb2.Cmd(
        id=cmd_id,
        type=cmd_type,
        data=cmd_data
    )

    log = AgentControlLog()
    log.operate_id = cmd_id
    log.client_id = agent_id
    log.operate_type = operate_type_map.get(cmd_type, f"cmd_{cmd_type}")
    log.detail = detail_for_log
    try:
        db.session.add(log)
        db.session.commit()
        queue.put(cmd_message)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"agent command enqueue failed: {e}")
        return jsonify({"code": 1, "message": f"failed to enqueue command: {e}", "data": {}})

    return jsonify({"code": 0, "message": "command queued", "data": {"cmd_id": cmd_id}})

############################# Honeyfile #############################################
# 蜜点文件创建
# @api.route("/file/create", methods=["POST"])
def file_create_old():
    # 获取参数
    user = request.headers.get("user_key")
    if user is None:
        user = "admin"
    data = json.loads(
        request.form.get("data")
    )  # 注意，客户端在发送请求时，将JSON数据编码为字符串，并将其作为表单数据发送。

    # 生成文件
    if data["source"] == 0:  # 系统模板生成:0, 用户上传:1
        file_name = get_random_string(random.randint(5, 15))  # 随机生成文件名
        token = getToken(
            data["email"], data["message"] + "-" + get_random_string(10)
        )  # 获取token
        if token[0] == "m":
            return jsonify(
                {
                    "code": 1,
                    "message": "Message is used in this email,create failed",
                    "data": {},
                }
            )
        elif token is None:
            return jsonify({"code": 1, "message": "get token failed", "data": {}})
        if data["format"] == "docx" or data["format"] == "word":
            data["format"] = "  docx"
            err, file_name = self_gen_token_word(token, file_name)  # 生成带token的docx文件
        elif data["format"] == "xlsx" or data["format"] == "excel":
            data["format"] = "xlsx"
            err, file_name = self_gen_token_excel(token, file_name)  # 生成带token的xlsx文件
        new_file = Honeyfile()  # 数据实例
        new_file.name = file_name
        if (
                re.match(
                    r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", data["email"]
                )
                is None
        ):
            return jsonify({"code": 1, "message": "email format error", "data": {}})
        new_file.user = user
        new_file.token = token
        new_file.email = data["email"]
        new_file.source = data["source"]
        new_file.server = data["server"]  # 外部告警服务器(external) or 内部告警服务器(internal)
        new_file.message = data["message"]
        new_file.doc_format = data["format"]
        # new_file.position = data["position"]
        new_file.honeypoint_name = data["honeypoint_name"]
        try:
            db.session.add(new_file)
            db.session.commit()
        except Exception as e:
            print("[ERROR]:", str(e))
            return jsonify({"code": 1, "message": "File insert error", "data": e})
        return jsonify({"code": 0, "message": "Success", "data": {}})
    else:
        # 参数检查
        if "file" not in request.files:
            return jsonify({"code": 1, "message": "未检测到上传文件!", "data": {}})
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"code": 1, "message": "no selected file", "data": {}})
        if (
                re.match(
                    r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", data["email"]
                )
                is None
        ):
            return jsonify({"code": 1, "message": "email format error", "data": {}})
        file_name = file.filename
        file.save(file_name)
        token = getToken(data["email"], data["message"] + "-" + get_random_string(10))
        if token is None:
            pass
            return jsonify({"code": 1, "message": "get token failed", "data": {}})
        elif token == "msg is used!":
            return jsonify(
                {
                    "code": 1,
                    "message": "Message is used in this email,create failed",
                    "data": {},
                }
            )

        # 创建文件数据库表项
        new_file = Honeyfile()
        print(file_name)
        new_file.email = data["email"]
        new_file.message = data["message"]
        new_file.name = file_name
        new_file.server = data["server"]
        new_file.token = token
        new_file.user = user
        # new_file.position = data["position"]
        new_file.honeypoint_name = data["honeypoint_name"]
        new_file.source = data["source"]
        if data["format"] == "docx" or data["format"] == "word":
            new_file.doc_format = "docx"
            gen_tokened_word(file_name, token, data["source"])  # word嵌入token
        elif data["format"] == "xlsx" or data["format"] == "excel":
            new_file.doc_format = "xlsx"
            gen_tokened_excel(file_name, token, data["source"])  # excel嵌入token
        else:
            return jsonify(
                {"code": 1, "message": "File format not allowed", "data": {}}
            )
        try:
            db.session.add(new_file)
            db.session.commit()
        except Exception as e:
            return jsonify({"code": 1, "message": "File exist", "data": {}})
        return jsonify({"code": 0, "message": "Success", "data": {}})


# 蜜点文件创建
@api.route("/file/create", methods=["POST"])
def file_create():
    return _file_create_v2()

    # legacy implementation kept below for reference; current path returns early
    try:
        # 获取参数
        data = json.loads(request.form.get("data"))
        user = request.headers.get("user_key")
        auth = request.cookies.get("Authorization")
        
        honeypoint_name = data.get("honeypoint_name")
        email = data.get("email")
        message = data.get("message")
        server = data.get("server")
        source = data.get("source")
        format = data.get("format")

        # 参数完整性校验
        required_fields = {
            "honeypoint_name": honeypoint_name,
            "email": email,
            "message": message,
            "server": server,
            "source": source,
            "format": format
        }

        # 检查必填字段是否为空
        for field_name, field_value in required_fields.items():
            if not field_value:  # None 或 空字符串时都为 False
                return jsonify({"code": 1, "message": f"Incomplete parameters: {field_name} is missing", "data": {}})

        # 尝试将 source 转为 int
        try:
            data['source'] = int(source)
        except ValueError:
            return jsonify({"code": 1, "message": "Invalid parameter: source must be an integer", "data": {}})

        # 检查配置
        if not Server_config.gateway_addr:
            return jsonify({"code": 1, "message": "缺少配置信息: [gateway] server_addr", "data": {}})

        # 继续处理其他逻辑...

    except (json.JSONDecodeError, TypeError):
        return jsonify({"code": 1, "message": "Invalid JSON format or missing data field", "data": {}})
    
    if Server_config.Env_mode == "server":
        if user is not None and user != "": # 用户身份校验
            err,info = user_auth(auth)
            if err:
                return jsonify({"code": 1, "message": info, "data": {}})
            user = info
        if user == "client":
            pass
        else:
            return jsonify({"code": 1, "message": "未知身份", "data": {}})

    if data.get("email") and data.get("email") != "":   # 是否需要邮箱告警
        if validate_email_account(data["email"]):  # 邮箱格式校验
            return jsonify({"code": 1, "message": "email format error", "data": {}})

    # 根据不同的模式生成蜜点文件
    if data["source"] == 0:
        err, res = getToken(data["email"], data["message"] + "-" + get_random_string(10))   # 获取token_url
        if err:
            return jsonify({"code": 1, "message": res, "data": {}})
        token = res

        if data["format"] == "docx" or data["format"] == "word":    # word文件
            data["format"] = "docx"
            file_format = "docx"
            err, info = gen_tokened_word(
                data.get("template_name"), token, data["source"]
            )  # word嵌入token
        elif data["format"] == "xlsx" or data["format"] == "excel": # excel文件
            data["format"] = "xlsx"
            file_format = "xlsx"
            # err, info = self_gen_token_excel(token, file_name)  # 生成带token的xlsx文件
            template_name = data.get("template_name")
            err, info = gen_tokened_excel(data.get("template_name"), token, data["source"])  # excel嵌入token
        else:
            return jsonify(
                {"code": 1, "message": "File format not allowed", "data": {}}
            )
        if err != 0:
            return jsonify({"code": 1, "message": str(info), "data": {}})
    else:   # 根据用户上传的文件生成文件蜜点
        # 参数检查
        if "file" not in request.files or request.files["file"].filename == "":
            return jsonify({"code": 1, "message": "未检测到上传的文件", "data": {}})
        file = request.files["file"]
        if str.lower(file.filename.split(".")[-1]) not in ["docx", "xlsx"]:
            return jsonify({"code": 1, "message": "不支持该类型文件!", "data": {}})
        
        file_format = str.lower(file.filename.split(".")[-1])   # 文件类型
        
        err, res = getToken(data["email"], data["message"] + "-" + get_random_string(10))   # 获取token_url
        if err:
            current_app.logger.error(res)
            return jsonify({"code": 1, "message": res, "data": {}})
        token = res
        
        file_name = file.filename
        current_app.logger.info(f"[File] 用户上传文件：{file_name}")
        # file.save("./Honeyfiles/upload/" + file_name)   # 保存文件
        file.save(project_path+"/Honeyfiles/upload/" + file_name)   # 保存文件
        if file_format == "docx" or file_format == "word":
            file_format = "docx"
            err, info = gen_tokened_word(file_name, token, data["source"])  # word嵌入token
        elif file_format == "xlsx" or file_format == "excel":
            file_format = "xlsx"
            err, info = gen_tokened_excel(file_name, token, data["source"])  # excel嵌入token
        if err != 0:
            return jsonify({"code": 1, "message": str(info), "data": {}})
    file_name = info
    
    # 创建文件数据
    new_file = Honeyfile()
    new_file.user = user
    new_file.token = token
    new_file.name = file_name
    new_file.email = data["email"]
    new_file.source = data["source"]
    new_file.server = data["server"]
    new_file.message = data["message"]
    new_file.doc_format = file_format
    new_file.honeypoint_name = data["honeypoint_name"]
    try:
        db.session.add(new_file)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify({"code": 1, "message": "File info insert error", "data": {}})
    return jsonify({"code": 0, "message": "Success", "data": {"id": new_file.id}})

#生成文件网页
def _file_create_v2():
    try:
        data = json.loads(request.form.get("data"))
        user = request.headers.get("user_key")
        auth = request.cookies.get("Authorization")

        required_fields = {
            "honeypoint_name": data.get("honeypoint_name"),
            "email": data.get("email"),
            "message": data.get("message"),
            "server": data.get("server"),
            "source": data.get("source"),
            "format": data.get("format"),
        }
        for field_name, field_value in required_fields.items():
            if field_value in (None, ""):
                return jsonify({"code": 1, "message": f"Incomplete parameters: {field_name} is missing", "data": {}})

        try:
            data["source"] = int(data.get("source"))
        except (TypeError, ValueError):
            return jsonify({"code": 1, "message": "Invalid parameter: source must be an integer", "data": {}})

        if not Server_config.gateway_addr:
            return jsonify({"code": 1, "message": "Missing config: [gateway] server_addr", "data": {}})
    except (json.JSONDecodeError, TypeError):
        return jsonify({"code": 1, "message": "Invalid JSON format or missing data field", "data": {}})

    if Server_config.Env_mode == "server":
        if user is not None and user != "":
            err, info = user_auth(auth)
            if err:
                return jsonify({"code": 1, "message": info, "data": {}})
            user = info
        if user != "client":
            return jsonify({"code": 1, "message": "未知身份", "data": {}})

    if data.get("email") and validate_email_account(data["email"]):
        return jsonify({"code": 1, "message": "email format error", "data": {}})

    token_seed = f"{str(data['message']).strip() or 'file-alert'}::file::{get_random_string(10)}"
    token = ""
    file_format = ""
    generated_name = ""
    upload_source_name = ""

    if data["source"] == 0:
        err, res = _issue_file_alert_token(data["email"], token_seed)
        if err:
            return jsonify({"code": 1, "message": res, "data": {}})
        token = res

        if data["format"] in ("docx", "word"):
            file_format = "docx"
            err, generated_name = gen_tokened_word(data.get("template_name"), token, data["source"])
        elif data["format"] in ("xlsx", "excel"):
            file_format = "xlsx"
            err, generated_name = gen_tokened_excel(data.get("template_name"), token, data["source"])
        else:
            return jsonify({"code": 1, "message": "File format not allowed", "data": {}})
        if err != 0:
            return jsonify({"code": 1, "message": str(generated_name), "data": {}})
    else:
        if "file" not in request.files or request.files["file"].filename == "":
            return jsonify({"code": 1, "message": "未检测到上传的文件", "data": {}})
        file = request.files["file"]
        upload_source_name = file.filename
        file_ext = str.lower(upload_source_name.split(".")[-1])
        if file_ext not in ["docx", "xlsx"]:
            return jsonify({"code": 1, "message": "不支持该类型文件", "data": {}})

        err, res = _issue_file_alert_token(data["email"], token_seed)
        if err:
            current_app.logger.error(res)
            return jsonify({"code": 1, "message": res, "data": {}})
        token = res

        upload_dir = _honeyfile_upload_dir()
        os.makedirs(upload_dir, exist_ok=True)
        upload_path = os.path.join(upload_dir, upload_source_name)
        file.save(upload_path)
        current_app.logger.info("[File] user upload saved: %s", upload_source_name)

        if file_ext == "docx":
            file_format = "docx"
            err, generated_name = gen_tokened_word(upload_source_name, token, data["source"])
        else:
            file_format = "xlsx"
            err, generated_name = gen_tokened_excel(upload_source_name, token, data["source"])
        if err != 0:
            return jsonify({"code": 1, "message": str(generated_name), "data": {}})

    new_file = Honeyfile()
    new_file.user = user
    new_file.token = token
    new_file.name = generated_name
    new_file.email = data["email"]
    new_file.source = data["source"]
    new_file.server = data["server"]
    new_file.message = data["message"]
    new_file.doc_format = file_format
    new_file.honeypoint_name = data["honeypoint_name"]
    new_file.token_alert_msg = token_seed
    if data["source"] == 0:
        template_name = str(data.get("template_name") or "").strip()
        new_file.source_template_name = template_name
        new_file.source_file_name = f"template-{template_name}.{file_format}" if template_name else f"template.{file_format}"
    else:
        new_file.source_file_name = upload_source_name

    try:
        db.session.add(new_file)
        db.session.flush()
        if data["source"] == 1 and upload_source_name:
            upload_path = os.path.join(_honeyfile_upload_dir(), upload_source_name)
            _archive_honeyfile_source(new_file, upload_path)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(e)
        return jsonify({"code": 1, "message": "File info insert error", "data": {}})
    return jsonify({"code": 0, "message": "Success", "data": {"id": new_file.id}})


@api.route("/honeypot/generate_page", methods=["POST"])
def generate_honeypot_page():
    """
    接收前端请求，生成包含多个蜜点文件的静态 HTML 页面。
    """
    try:
        data = request.get_json()
        file_ids = data.get("file_ids", [])
        template_name = data.get("template_name")

        if not file_ids:
            return jsonify({"code": 1, "message": "文件列表为空", "data": {}})
        if not template_name:
            return jsonify({"code": 1, "message": "模板名称缺失", "data": {}})

        # 生成唯一的部署目录名（使用模板名和时间戳）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        deploy_dir_name = f"{template_name}_{timestamp}"

        # 创建新的部署目录
        base_deploy_dir = os.path.join(project_path, "Honeyfiles", "deploy")
        deploy_dir = os.path.join(base_deploy_dir, deploy_dir_name)
        os.makedirs(deploy_dir, exist_ok=True)

        # 根据文件ID（索引）从文件目录中获取文件信息
        generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
        # 对文件列表进行排序，确保ID（索引）与文件名一一对应
        all_file_names = sorted(os.listdir(generate_dir))
        
        files_to_deploy = []
        for file_id in file_ids:
            try:
                # 前端传递的ID是文件列表中的索引+1
                file_index = int(file_id) - 1
                if 0 <= file_index < len(all_file_names):
                    file_name = all_file_names[file_index]
                    file_path = os.path.join(generate_dir, file_name)
                    file_stats = os.stat(file_path)
                    create_time = datetime.fromtimestamp(file_stats.st_ctime)
                    
                    files_to_deploy.append({
                        "name": file_name,
                        "create_time": create_time
                    })
                else:
                    current_app.logger.warning(f"无效的文件ID: {file_id}")
            except (ValueError, IndexError) as e:
                current_app.logger.error(f"处理文件ID {file_id} 时出错: {e}")
        
        if not files_to_deploy:
            return jsonify({"code": 1, "message": "未找到指定文件", "data": {}})
            
        files_info_for_template = []
        for f in files_to_deploy:
            files_info_for_template.append({
                "name": f["name"],
                "url": f"/files/{f['name']}",
                "date": f["create_time"].strftime("%Y-%m-%d %H:%M:%S")
            })

        # 判断模板类型（目录结构 vs 单独HTML文件）
        template_dir = os.path.join(project_path, "flask_server", "templates", "honeypot", template_name)
        template_html_file = os.path.join(template_dir, f"{template_name}.html")
        
        if os.path.isdir(template_dir) and os.path.exists(template_html_file):
            # 新的目录结构模板
            rendered_html = render_template(f"honeypot/{template_name}/{template_name}.html", files=files_info_for_template)
            
            # 复制模板的静态资源
            for resource_dir in ['css', 'js', 'images', 'fonts']:
                src_resource_dir = os.path.join(template_dir, resource_dir)
                if os.path.exists(src_resource_dir):
                    dst_resource_dir = os.path.join(deploy_dir, resource_dir)
                    if os.path.exists(dst_resource_dir):
                        shutil.rmtree(dst_resource_dir)
                    shutil.copytree(src_resource_dir, dst_resource_dir)
                    current_app.logger.info(f"复制模板资源: {resource_dir}")
        else:
            # 旧的单独HTML文件模板（向后兼容）
            rendered_html = render_template(f"honeypot/{template_name}.html", files=files_info_for_template)
        
        # 将生成的HTML写入新目录
        with open(os.path.join(deploy_dir, "downloads.html"), "w", encoding="utf-8") as f:
            f.write(rendered_html)
            
        # 复制文件到新目录
        for f in files_to_deploy:
            src_path = os.path.join(generate_dir, f["name"])
            dst_path = os.path.join(deploy_dir, f["name"])
            if os.path.exists(src_path):
                shutil.copy(src_path, dst_path)
            else:
                current_app.logger.warning(f"源文件不存在，无法复制: {src_path}")

        return jsonify({
            "code": 0, 
            "message": "蜜点页面已生成并准备好部署", 
            "data": {
                "deploy_path": deploy_dir,
                "deploy_name": deploy_dir_name,
                "file_count": len(files_info_for_template)
            }
        })
    except Exception as e:
        current_app.logger.error(f"生成蜜点页面失败: {e}", exc_info=True)
        return jsonify({"code": 1, "message": f"操作失败: {str(e)}", "data": {}})


# 蜜点文件模板查询
@api.route("/file/template", methods=["POST"])
def file_template_search():
    data = request.get_json()
    template_infos = []
    # 参数：文件类型-format(可选)
    format = data.get("format")
    prefix = "template-"  # 模板文件名前缀

    # 不限制文件类型
    if format == None:
        # 查询 ./template/下所有以template开头的文件
        files = os.listdir("./template/")
        for file in files:
            if file.startswith(prefix):
                # filename = file.split("-")[1]
                # filename = file.lstrip(prefix)  # 去掉前缀
                filename = file[len(prefix):]  # 去掉前缀
                template_infos.append(filename)
    else:
        files = os.listdir("./template/")
        for file in files:
            if file.startswith(prefix) and file.endswith(format):
                filename = file.lstrip(prefix)
                # filename = file[len(prefix):]  # 去掉前缀
                template_infos.append(filename)
                print(filename)

    return jsonify({"code": 0, "message": "Success", "data": template_infos})

# 蜜点文件查询
@api.route("/file/search", methods=["POST"])
def file_search():
    data = request.get_json()
    page_num = data.get("page_num", 1)
    page_size = data.get("page_size", 100)
    file_infos = []

    query = Honeyfile.query
    if data.get("id")  is not None and data.get("id") != "":
        file = query.filter_by(id=data.get("id")).first()
        file_infos.append(file.to_json())
        return jsonify({"code": 0, "message": "Success", "data": file_infos})
    if data.get("source"):
        query = query.filter_by(source=data.get("source"))
    if data.get("format"):
        query = query.filter_by(doc_format=data.get("format"))
    if data.get("honeyName"):
        query = query.filter(Honeyfile.honeypoint_name.like("%" + data.get("honeyName") + "%"))
    if data.get("filename"):
        # filename = str.lower(data.get("filename"))
        filename = data.get("filename")
        # query = query.filter(Honeyfile.name.like("%"+data.get("filename")+"%"))
        query = query.filter(Honeyfile.name.like("%" + filename + "%"))
    files = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    if files is None:
        return jsonify({"code": 0, "data": file_infos, "message": "", "total": total})
    for file in files:
        info = file.to_json()
        info["created_at"] = file.created_at.replace(tzinfo=pytz.utc).astimezone(
            pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
        # print(file.created_at.tzinfo)
        file_infos.append(info)
    # return jsonify({"code":0,"message":"","data":file.to_json()})
    return jsonify(
        {"code": 0, "message": "Success", "data": file_infos, "total": total}
    )


# 获取文件蜜点数量
@api.route("/file/count", methods=["GET"])
def file_count():
    # 获取文件蜜点数量
    count = Honeyfile.query.count()
    return jsonify({"code": 0, "message": "Success", "data": {'count': count}})


# 蜜点文件删除
@api.route("/file/delete", methods=["POST"])
def file_delete():
    info = {}
    data = request.get_json()
    # 选一批文件删除
    # print(data.get("id"))
    if data.get("id") is None or (isinstance(data.get("id"), list) and len(data.get("id")) == 0):
        return jsonify({"code": 1, "message": "请选择要删除的蜜点!", "data": {}})
    if not isinstance(data["id"], list):
        id = [data["id"]]
    else:
        id = data["id"]
    id_deped = []  # 已部署的文件id
    for each in id:
        file = Honeyfile.query.filter_by(id=each).first()
        if file is None:
            return jsonify(
                {"code": 1, "message": "File id no exist:" + str(each), "data": {}}
            )
        if os.path.isfile("./Honeyfiles/generate/" + file.name):
            os.remove("./Honeyfiles/generate/" + file.name)
        elif os.path.isfile("./Honeyfiles/upload/" + file.name):
            os.remove("./Honeyfiles/upload/" + file.name)
        else:
            info[file.name] = "file not exists in server"
        db.session.delete(file)
        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError as e:
            id_deped.append(each)
            db.session.rollback()
    if len(id_deped) != 0:  # 有部分文件已经部署，无法删除
        return jsonify(
            {
                "code": 2,
                "message": "部分文件已被部署，无法删除",
                "data": id_deped,
            }
        )
    else:
        return jsonify({"code": 0, "message": "Success", "data": {}})


# 蜜点文件修改
@api.route("/file/modify", methods=["POST"])
def file_modify():
    data = request.get_json()
    file = Honeyfile.query.filter_by(id=id).first()
    if file is None:
        return jsonify({"code": 1, "message": "no such file", "data": {}})
    if data["position"] is not None and data["position"] != "":
        file.position = data["position"]
    # if data["recommand_path"] is not None and data["recommand_path"] != "":
    #     file.recommand_path = data["recommand_path"]
    db.session.add(file)
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


# 蜜点文件下载（需要认证）
@api.route("/file/download", methods=["GET","POST"])
def file_download():
    id = request.args.get("id")
    file = Honeyfile.query.filter_by(id=id).first()
    if file is None:
        return jsonify({"code": 1, "message": "no such file", "data": {}})
    try:
        ensure_err, ensure_msg = _ensure_local_honeyfile_is_live(file)
        if ensure_err:
            current_app.logger.warning("[Web] live honeyfile refresh skipped for file_id=%s: %s", id, ensure_msg)
        generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
        file_path = ensure_msg if not ensure_err and os.path.isfile(str(ensure_msg)) else os.path.join(generate_dir, file.name)
        
        if os.path.isfile(file_path):
            filename = file.to_json()["filename"]
            return send_file(file_path, as_attachment=True, download_name=filename)
        else:
            return jsonify(
                {"code": 1, "message": "file not exists in server", "data": {}}
            )
    except Exception as e:
        return jsonify({"code": 1, "message": str(e), "data": {}})


# Agent专用文件下载端点（无需认证）
@api.route("/api/agent/file/download/<int:file_id>", methods=["GET"])
def agent_file_download(file_id):
    file = Honeyfile.query.filter_by(id=file_id).first()
    if file is None:
        return jsonify({"code": 1, "message": "no such file", "data": {}})
    try:
        ensure_err, ensure_msg = _ensure_local_honeyfile_is_live(file)
        if ensure_err:
            current_app.logger.warning("[Agent] live honeyfile refresh skipped for file_id=%s: %s", file_id, ensure_msg)
        # 使用统一的路径处理方式
        generate_dir = os.path.join(project_path, "Honeyfiles", "generate")
        file_path = ensure_msg if not ensure_err and os.path.isfile(str(ensure_msg)) else os.path.join(generate_dir, file.name)
        
        if os.path.isfile(file_path):
            filename = file.to_json()["filename"]
            return send_file(file_path, as_attachment=True, download_name=filename)
        else:
            return jsonify(
                {"code": 1, "message": "file not exists in server", "data": {}}
            )
    except Exception as e:
        return jsonify({"code": 1, "message": str(e), "data": {}})


@api.route("/file/findby", methods=["POST"])
def file_findby():
    data = request.get_json()
    page_num = data["page_num"]
    page_size = data["page_size"]
    file_infos = []
    query = Honeyfile.query
    if data["source"]:
        query = query.filter_by(source=data["source"])
    if data["format"]:
        query = query.filter_by(doc_format=data["format"])
    if data["like_name"]:
        query = query.filter(Honeyfile.name.like("%" + data["like_name"] + "%"))
    files = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    if files is None:
        return jsonify({"code": 0, "data": file_infos, "message": "", "total": total})
    for file in files:
        file_infos.append(file.to_json())
    return jsonify({"code": 0, "data": file_infos, "message": "", "total": total})


# 路径生成
@api.route("/file/path_generate", methods=["POST"])
def file_path_generate():
    # 检查参数：操作系统类型-ope_sys、文件蜜点id-honeyfile_id、生成路径数-path_num
    data = request.get_json()
    if "ope_sys" not in data or "honeyfile_id" not in data or "path_num" not in data:
        return jsonify({"code": -1, "data": "", "message": "Incomplete parameters"})
    ope_sys = data["ope_sys"]
    honeyfile_id = data["honeyfile_id"]
    path_num = data["path_num"]
    # 根据文件id获取文件类型
    file = Honeyfile.query.get(honeyfile_id)
    if file is None:
        return jsonify({"code": 1, "data": "", "message": "file not exist"})
    file_type = file.to_json()["doc_format"]

    # 调用path生成api
    # url = Path_generate_addr
    err, info = get_nacos_service_info("honeypoint-commend")
    if err:
        return jsonify({"code": 1, "data": "", "message": "Path generation request error," + str(info)})
    service_ip = info["service_ip"]
    service_port = info["service_port"]
    url = f"http://{str(service_ip)}:{str(service_port)}/honeypoint_commend/generate_path"
    current_app.logger.info("Host info query url:" + url)
    param = {
        "ope_sys": ope_sys,
        "file_type": file_type,
        "path_num": path_num,
        "limit_path": "",
    }
    json_data = json.dumps(param)  # 发送json格式参数
    cookie = request.cookies.get("Authorization")
    cookies = {"Authorization": cookie}
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.post(url, data=json_data, headers=headers, cookies=cookies)
    if response.status_code != 200 or response.json().get("code") != 1:
        msg = response.json().get("message")
        return jsonify(
            {"code": 1, "data": "", "message": "Path generation request error," + str(msg)}
        )
    res = response.json()["data"]
    return jsonify({"code": 0, "data": res, "message": ""})


# 文件蜜点部署
@api.route("/file/deploy", methods=["POST"])
def file_deploy():
    # 获取部署参数
    user = request.headers.get("user_key")  # 访问API的用户，Header中的参数名为User-Key
    data = request.get_json()

    if data.get("deploy_type") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
    deploy_type = data.get("deploy_type")  # 部署类型：1-部署到容器，2-部署到主机

    if deploy_type == 1:  # 部署到容器
        file_id = data.get("id")  # 要部署的文件ID
        dep_path = data.get("path")  # 部署的路径
        hostname = data.get("hostname")  # 部署的容器名/主机
        ope_sys = data.get("ope_sys")  # 部署容器操作系统
        host_id = data.get("host_id")  # 部署节点id(容器id/主机id)
        if file_id is None or dep_path is None or hostname is None:
            return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

        # 获取部署容器的网络信息
        err, info = get_nacos_service_info("honeypoint")
        if err:
            return jsonify({"code": 1, "message": "Honeypoint info query error", "data": {}})
        service_ip = info["service_ip"]
        service_port = info["service_port"]
        url_docker_info = f"http://{str(service_ip)}:{str(service_port)}/service/instantiation/hp_manage/link/link_info_filter"
        data = {
            "server_name": hostname
        }
        try:
            response = requests.post(url_docker_info, json=data)
        except Exception as e:
            return jsonify({"code": 1, "message": f"Honeypoint info query error:{e}", "data": {}})
        if response.status_code != 200:
            return jsonify(
                {"code": 1, "message": f"Honeypoint info query error, Response{response.status_code}", "data": {}})
        docker_info = response.json()["data"]
        if len(docker_info) == 0:  # 服务绊线未部署至蜜点ip
            docker_info = {}
            docker_info["hp_ip"] = "Removed"
            docker_info["hp_port"] = "Removed"
            docker_info["ID"] = "Removed"  # 蜜点网络id
            docker_info["service_ip"] = "Removed"
        else:
            docker_info = docker_info[0]

        # 获取部署文件信息
        file = Honeyfile.query.filter_by(id=file_id).first()  # 查询文件信息
        if file is None:
            return jsonify({"code": 1, "message": "no such file", "data": {}})
        filename = file.to_json()["filename_tag"]
        local_path = "./Honeyfiles/generate/" + filename
        if not os.path.isfile(local_path):
            return jsonify({"code": 1, "message": "file not exists in server", "data": {}})
        try:
            # 部署文件到docker容器,获取目标容器
            client = docker.from_env()
            container = client.containers.get(hostname)

            print(len(dep_path))

            for i in range(len(dep_path)):
                # 部署信息
                new_deploy = Filedeploy()
                new_deploy.deploy_type = deploy_type  # 部署类型
                new_deploy.honeypoint_id = file_id
                new_deploy.user = user
                new_deploy.hostname = hostname  # 容器名
                new_deploy.ope_sys = ope_sys
                new_deploy.host_id = host_id  # 容器id
                new_deploy.path = dep_path[i]  # 部署路径
                new_deploy.host_ip = docker_info.get("hp_ip")  # 容器部署的蜜点
                new_deploy.network_id = docker_info.get("ID")  # 容器部署的蜜点网络id

                # 调试代码 测试容器中是否已经有目标文件夹test -d /app/data/ && echo "dir exists" || echo "dir not exists"
                exec_result = container.exec_run(
                    f'bash -c "test -d {dep_path[i]} && echo 文件夹存在 || echo 文件夹不存在"'
                )
                print(exec_result.output.decode().strip())
                # 制作tar文件
                tar_filename = local_path + ".tar"
                tar = tarfile.open(tar_filename, "w")
                tar.add(local_path, arcname=file.to_json()["filename"])
                tar.close()
                # 复制tar文件到容器中
                exec_result = container.exec_run(f"mkdir -p {dep_path[i]}")  # 创建多级文件夹
                print(exec_result.output.decode().strip())
                try:
                    with open(tar_filename, "rb") as f:
                        container.put_archive(dep_path[i], f.read())
                    new_deploy.status = 1  # 部署成功
                except Exception as e:
                    print(e)
                    new_deploy.status = 2  # 部署失败

                db.session.add(new_deploy)
                # 部署信息写入部署信息表
            db.session.commit()
        except Exception as e:
            traceback.print_exc()
            print(e)
            return jsonify({"code": 1, "message": "Record insert error", "data": {}})
        return jsonify({"code": 0, "message": "Success", "data": {}})

    elif deploy_type == 2:  # 部署到主机
        host_ip = data.get("ip")  # 部署的主机ip
        network = data.get("network")  # 部署的主机网络
        path = data.get("path")  # 部署的路径
        hostname = data.get("machine_name")  # 部署机制
        ope_sys = data.get("sys")  # 部署主机操作系统
        file_id = data.get("file_id")  # 要部署的文件ID

        if host_ip is None or network is None or path is None or hostname is None or ope_sys is None or file_id is None:
            return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
        current_app.logger.info("Deploy file to host")
        print("args:", data)

        # 查询主机的id及网络id
        print("Query host info")
        err, info = get_nacos_service_info("hostsinfo")
        if err:
            print(info)
            return jsonify({"code": 1, "message": info, "data": {}})
        service_ip = info["service_ip"]
        service_port = info["service_port"]
        print(info)
        url = f"http://{str(service_ip)}:{str(service_port)}/hostsinfo/allinfo"
        current_app.logger.info("Host info query url:" + url)
        args = {
            "page": 1,
            "page_size": 5,
            "host": host_ip
        }
        print("args:", args)
        try:
            response = requests.get(url, params=args, timeout=5)
        except Exception as e:
            current_app.logger.error("Host info query error")
            return jsonify({"code": 1, "message": "Host info query error", "data": {}})
        if response.status_code != 200:
            current_app.logger.error("Host info query error")
            return jsonify({"code": 1, "message": "Host info query error", "data": {}})
        if len(response.json()["data"]) == 0:
            current_app.logger.warning("No host info")
            host_id = "unknown"
            network_id = "unknown"
            network = network
            # ope_sys = ope_sys
            # return jsonify({"code": 1, "message": "No host info", "data": {}})
        else:
            host_info = response.json()["data"][0]
            host_id = host_info["id"]
            network_id = host_info["netid"]
            network = host_info["network"]
            # ope_sys = host_info["sys"]

        dep_info = Filedeploy()
        dep_info.deploy_type = deploy_type
        dep_info.honeypoint_id = file_id
        dep_info.hostname = hostname
        dep_info.host_id = host_id
        dep_info.host_ip = host_ip
        dep_info.network_id = network_id
        dep_info.ope_sys = ope_sys
        dep_info.path = path
        dep_info.user = "client"
        dep_info.status = 1
        dep_info.deploy_at = get_time_bj()
        try:
            db.session.add(dep_info)
            db.session.commit()
        except Exception as e:
            current_app.logger.error("Record insert error")
            db.session.rollback()
            print(e)
            return jsonify({"code": 1, "message": "Record insert error", "data": {}})
        return jsonify({"code": 0, "message": "Success", "data": {}})

    else:  # 部署类型错误
        return jsonify({"code": 1, "message": "deploy_type error", "data": {}})


# 手动添加部署信息
@api.route("/file/deploy_add", methods=[ "POST"])
def file_deploy_add():
    """手动添加部署信息
    支持批量添加路径；
    网络id(非必须)：可通过查询网络信息获取/可手动输入
    主机id(非必须)：通过查询主机信息(非必须)
    主机ip(非必须)：通过查询主机信息(非必须)
    操作系统:Windows/Linux
    
    """
    
    data = request.get_json()
    honeypoint_id = data.get("honeypoint_id")   # 文件id
    hostname = data.get("hostname")             # 主机名
    path = data.get("path")                     # 部署路径
    ope_sys = data.get("ope_sys")               # 操作系统
    network_id = data.get("network_id")         # 网络id
    host_ip = data.get("host_ip")               # 主机ip
    host_id = data.get("host_id")               # 主机id
    status = data.get("status")                 # 部署状态
    deploy_type = 3                             # 部署类型（手动部署）
    user = data.get("user")                     # 用户身份
    
    if Server_config.Env_mode == "server":  # 身份校验
        auth = request.cookies.get("Authorization") # 获取用户身份Authorization
        err, info = user_auth(auth)
        if err:
            return jsonify({"code": 1, "message": info, "data": {}})
        user = info

    if hostname is None or hostname=='' or status is None or status=='' or path is None or path=='' or ope_sys is None or ope_sys=='':  # 参数不完整
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    file = Honeyfile.query.filter_by(id=honeypoint_id).first()  # 查询文件信息
    if file is None:
        return jsonify({"code": 1, "message": "所选文件不存在", "data": {}})
    
    deploy_objects = []
    for item in path:
        dpl = Filedeploy(
            honeypoint_id=honeypoint_id,
            user = user,
            hostname = hostname,
            path = item,
            ope_sys = ope_sys,
            status = status,
            deploy_type = deploy_type,
            host_ip = host_ip,
            host_id = host_id,
            network_id = network_id
        )
        deploy_objects.append(dpl)
    try:
        db.session.bulk_save_objects(deploy_objects)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"code": 1, "message": str(e), "data": {}})

    return jsonify({"code": 0, "message": "Success", "data": {}})


# 查询部署情况
@api.route("/file/deploy_search", methods=["POST"])
def file_deploy_search():
    data = request.get_json()
    page_num = data.get("page_num", 1)
    page_size = data.get("page_size", 100)

    query = Filedeploy.query
    dep_infos = []
    if data.get("id"):
        try:
            id = int(data.get("id"))
            query = query.filter(Filedeploy.id.in_(id))
        except ValueError:
            pass  # 跳过无法转换为整数的值
    if data.get("hostname"):
        hostname = str.lower(data.get("hostname"))
        query = query.filter(Filedeploy.hostname.like("%" + hostname + "%"))
    if data.get("ope_sys"):
        ope_sys = str.lower(data.get("ope_sys"))
        query = query.filter(func.lower(Filedeploy.ope_sys) == ope_sys)
    if data.get("filename"):
        filename = str.lower(data.get("filename"))
        query = query.join(Honeyfile).filter(Honeyfile.name.like("%" + filename + "%"))
    deps = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    if deps is None:
        return jsonify(
            {"code": 0, "message": "Success", "data": dep_infos, "total": total}
        )
    for each in deps:
        dep_json = each.to_json()
        dep_json["filename"] = each.honeyfile.name
        dep_json["honeypoint_name"] = each.honeyfile.honeypoint_name
        # dep_json["deploy_at"] = each.deploy_at.strftime("%Y-%m-%d %H:%M:%S")
        dep_infos.append(dep_json)
    return jsonify({"code": 0, "message": "Success", "data": dep_infos, "total": total})


# 修改部署记录
@api.route("/file/deploy_modify", methods=["POST"])
def file_deploy_modify():
    data = request.get_json()
    record_id = data.get("id","")
    if record_id == "":
        return jsonify({"code": 1, "message": "参数缺失!", "data": {}})
    record = Filedeploy.query.filter_by(id=record_id).first()
    if record == None:
        jsonify({"code": 1, "message": "数据不存在!", "data": {}})
    
    # 修改部署记录
    ope_sys = data.get("opeSys")
    hostname = data.get("hostname")
    host_ip = data.get("hostIP")
    path = data.get("path")
    # host_id = request.get_json("hostId")
    # network_id = request.get_json("networkId")

    if ope_sys and ope_sys in ['windows','Windows','linux','Linux']:
        record.ope_sys = ope_sys
    elif ope_sys:
        return jsonify({"code": 1, "message": "操作系统类型不正确!", "data": {}})
    if hostname:
        record.hostname = hostname
    if host_ip and isIP(host_ip):
        record.host_ip = host_ip
    elif host_ip:
        return jsonify({"code": 1, "message": "IP格式不正确!", "data": {}})
    if path and validate_path(path):
        record.path = data['path']
    elif path:
        return jsonify({"code": 1, "message": "路径格式不正确!", "data": {}})
        
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(e)
        return jsonify({"code": 1, "message": "数据库操作失败!", "data": {}})

    return jsonify({"code": 0, "message": "Success", "data": {}})
    
        

# 删除已部署文件蜜点
@api.route("/file/deploy_remove", methods=["POST"])
def file_deploy_remove():
    # 获取参数: 全部删除deleteall、部署id
    data = request.get_json()
    # print(data)
    if data.get("deleteall") is None or data.get("deleteall") != "true":  # 未选择要取消部署的文件
        if data.get("id") is None or (isinstance(data.get("id"), list) and len(data.get("id")) == 0):  # 未选择要取消部署的文件
            return jsonify({"code": 1, "message": "请选择要取消部署的文件!", "data": {}})
    try:
        client = docker.from_env()
    except Exception as e:
        print("docker env error")
        return jsonify({"code": 1, "data": "", "message": str(e)})

    errmsg = {}
    if data.get("deleteall") and data.get("deleteall") == "true":  # 移除所有部署
        # print("移除全部文件部署")
        dep_files = Filedeploy.query.all()
        for dep_file in dep_files:
            # 操作docker删除指定文件
            container = client.containers.get(dep_file.hostname)
            result = container.exec_run(
                f"rm -rf {os.path.join(dep_file.path, dep_file.honeyfile.name)}"
            )
            if result.exit_code != 0:
                errmsg[dep_file.hostname] = result.output.decode()
                continue
            db.session.delete(dep_file)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"code": 1, "data": "", "message": str(e)})
        return jsonify({"code": 0, "data": "", "message": errmsg})
    elif data.get("id"):  # 移除指定文件的部署
        if not isinstance(data["id"], list):
            if not isinstance(data["id"], int):
                return jsonify({"code": 1, "data": "", "message": "id参数类型错误"})
            id = [data["id"]]
            print(id)
        else:
            for each in data["id"]:
                if not isinstance(each, int):
                    return jsonify({"code": 1, "data": "", "message": "id参数类型错误"})
            id = data["id"]
            print(id)
        for each in id:
            dep_file = Filedeploy.query.filter_by(id=each).first()
            if dep_file is None:
                return jsonify({"code": 1, "data": {}, "message": "id不存在" + str(each)})
            container_exists = False
            container_list = client.containers.list()  # 获取容器列表
            for container in container_list:
                if container.name == dep_file.hostname or container.id == dep_file.hostname:  # 判断容器的名称或 ID 是否匹配目标容器
                    container_exists = True
                    break
            if container_exists:
                # print("容器存在")
                current_app.logger.info(f"Container [{dep_file.hostname}] exists")
                container = client.containers.get(dep_file.hostname)
                result = container.exec_run(  # 操作docker删除指定文件
                    f"rm -rf {os.path.join(dep_file.path, dep_file.honeyfile.name)}"
                )
                if result.exit_code != 0:
                    current_app.logger.error(
                        f"Cant remove file [{dep_file.honeyfile.name}] from container [{dep_file.hostname}]")
                    return jsonify({"code": 1, "data": "", "message": result.output.decode()})  # 返回错误信息
            else:
                print("容器不存在")
            # 删除数据库部署信息
            try:
                db.session.delete(dep_file)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                return jsonify({"code": 1, "data": "", "message": str(e)})
        return jsonify({"code": 0, "data": "", "message": ""})
    elif data.get("hostname") or data.get("host_id"):  # 移除指定容器的部署
        # print("移除指定容器的部署")
        hostname = data.get("hostname")
        node_id = data.get("host_id")
        dep_files = Filedeploy.query.filter_by(hostname=hostname).all()
        # dep_files = Filedeploy.query.filter_by(host_id=host_id).all()
        for dep_file in dep_files:
            # 操作docker删除指定文件
            errmsg = {}
            container_exists = False
            container_list = client.containers.list()  # 获取容器列表
            for container in container_list:
                if container.name == dep_file.hostname or container.id == dep_file.hostname:  # 判断容器的名称或 ID 是否匹配目标容器
                    container_exists = True
                    break
            if container_exists:
                print("容器存在")
                current_app.logger.info(f"Container [{dep_file.hostname}] exists")
                container = client.containers.get(dep_file.hostname)
                result = container.exec_run(  # 操作docker删除指定文件
                    f"rm -rf {os.path.join(dep_file.path, dep_file.honeyfile.name)}"
                )
                if result.exit_code != 0:
                    current_app.logger.error(
                        f"Cant remove file [{dep_file.honeyfile.name}] from container [{dep_file.hostname}]")
                    errmsg[dep_file.hostname] = result.output.decode()
                    continue
            else:
                current_app.logger.info(f"Container [{dep_file.hostname}] not exists")
                print("容器不存在")
            # 删除数据库部署信息
            db.session.delete(dep_file)
        try:
            current_app.logger.info("Delete deploy info from database")
            db.session.commit()
        except Exception as e:
            current_app.logger.error("Delete deploy info from database failed")
            db.session.rollback()
            return jsonify({"code": 1, "data": "", "message": str(e)})
        return jsonify({"code": 0, "data": "", "message": errmsg})
    else:
        return jsonify({"code": 1, "data": "", "message": "Incomplete parameters"})


@api.route("/file/deploy_findby", methods=["POST"])
def file_deploy_findby():
    data = request.get_json()
    page_num = data["page_num"]
    page_size = data["page_size"]
    dep_infos = []
    query = Filedeploy.query
    if data["hostname"]:
        query = query.filter_by(hostname=data["hostname"])
    if data["ope_sys"]:
        query = query.filter_by(ope_sys=data["ope_sys"])
    if data["filename"]:
        query = query.filter(Honeyfile.name.like("%" + data["filename"] + "%"))
    deps = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    if deps is None:
        return jsonify({"code": 0, "data": dep_infos, "message": "", "total": total})
    for dep in deps:
        info = dep.to_json()
        info["filename"] = dep.honeyfile.name
        info["honeypoint_name"] = dep.honeyfile.honeypoint_name
        dep_infos.append(info)
    return jsonify({"code": 0, "data": dep_infos, "message": "", "total": total})


# 查询文件告警
@api.route("/file/alert/search", methods=["GET"])
def file_alert_search():
    last_query_time_str = request.args.get("last_query_time")
    if last_query_time_str is None:
        last_query_time = datetime.now() - timedelta(days=30)
    else:
        last_query_time = datetime.strptime(last_query_time_str, "%Y-%m-%d %H:%M:%S")

    alerts = FileAlertInfo.query \
        .filter(FileAlertInfo.trigger_time > last_query_time) \
        .order_by(FileAlertInfo.trigger_time.desc()) \
        .all()
    alert_infos = _aggregate_file_alert_infos(alerts)
    for alert_info in alert_infos:
        deployments = alert_info.get("deployments") or []
        if deployments:
            alert_info["hostname"] = deployments[0].get("hostname")
            alert_info["deploy_path"] = deployments[0].get("path")
    return jsonify({
        "code": 0,
        "message": "Success",
        "data": alert_infos,
        "total": len(alert_infos),
        "raw_total": len(alerts),
    })


############################# Honeyaccount #############################################
@api.route("/account/create", methods=["POST"])
def account_create():
    data = request.get_json()
    new_account = Honeyaccount()
    user = str(request.headers.get("user_key"))  # 之后根据API获取当前登录用户
    print(data)
    # 参数完整性校验
    if (
            not data.get("honeypot")
            or not data.get("username")
            or not data.get("password")
            or not data.get("honeypoint_name")
    ):
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
    new_account.username = data["username"]
    new_account.password = data["password"]
    new_account.user = user  # 操作用户id
    new_account.honeypoint_name = data["honeypoint_name"]
    new_account.function = "flow"  # 默认为引流功能
    # honeysite1 = "http://175.178.165.96:9099/"
    # honeysite2 = "http://175.178.165.96:9215/"
    if data.get("honeypot") == None or data["honeypot"] == "":
        # new_account.honeypot = random.choice([honeysite1, honeysite2])
        # print("random select honeypot")
        return jsonify({"code": 1, "message": "参数不完整", "data": {}})
    elif not validate_url_format(data["honeypot"]):
        return jsonify({"code": 1, "message": "引导url格式错误", "data": {}})
    else:
        new_account.honeypot = data["honeypot"]
    if data.get("position"):  # 位置信息可选
        new_account.position = data["position"]
    else:
        new_account.position = ""
    db.session.add(new_account)
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


@api.route("/account/random_generate", methods=["POST"])
def account_random_generate():
    account = {}
    try:
        username = linecache.getline(
            "./template/user500.txt", random.randint(1, 512)
        ).strip()
        password = linecache.getline(
            "./template/pass500.txt", random.randint(1, 501)
        ).strip()
    except Exception as e:
        return jsonify({"code": 1, "message": e, "data": {}})
    account[username] = password
    return jsonify({"code": 0, "message": "Success", "data": account})


@api.route("/account/search", methods=["POST"])
def account_search():
    data = request.get_json()
    page_num = data["page_num"]
    page_size = data["page_size"]
    account_infos = []
    # if data["findall"] == True:
    #     accounts = Honeyaccount.query.paginate(page=page_num,per_page=page_size,error_out=False)
    #     total = Honeyaccount.query.count()
    #     if accounts is None:
    #         return jsonify({"code":1,"message":"no such account","data":{}})
    #     for account in accounts:
    #         account_infos.append(account.to_json())
    #     return jsonify({"code":0,"message":"","data":account_infos,"total":total})
    # else:
    #     id  = data["id"]
    #     account = Honeyaccount.query.filter_by(id=id).first()
    #     if account is None:
    #         return jsonify({"code":1,"message":"no such account","data":{}})
    #     else:
    #         return jsonify({"code":0,"message":"","data":account.to_json()})
    query = Honeyaccount.query
    if data.get("url"):  # url查询
        url = str.lower(data.get("url"))
        query = query.filter(Honeyaccount.honeypot.like("%" + url + "%"))
    if data.get("username"):  # 账号名查询
        username = str.lower(data.get("username"))
        # query = query.filter(Honeyaccount.username.like("%" + username + "%"))
        query = query.filter(Honeyaccount.honeypoint_name.like("%" + username + "%"))
    if data.get("honeypoint_name"):  # 账号名查询
        honeypoint_name = str.lower(data.get("honeypoint_name"))
        query = query.filter(
            Honeyaccount.honeypoint_name.like("%" + honeypoint_name + "%")
        )
    accounts = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    for account in accounts:
        info = account.to_json()
        info["created_at"] = account.created_at.replace(tzinfo=pytz.utc).astimezone(
            pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
        account_infos.append(info)
    return jsonify(
        {"code": 0, "message": "Success", "data": account_infos, "total": total}
    )


# 获取账户蜜点数量
@api.route("/account/count", methods=["GET"])
def account_count():
    count = Honeyaccount.query.count()
    return jsonify({"code": 0, "message": "Success", "data": {'count': count}})


@api.route("/account/delete", methods=["POST"])
def account_delete():
    data = request.get_json()
    print(data)

    if data.get("id") is None or (isinstance(data.get("id"), list) and len(data.get("id")) == 0):
        return jsonify({"code": 1, "message": "请选择要删除的蜜点!", "data": {}})
    # if data["deleteall"] == True:
    #     accounts = Honeyaccount.query.all()
    #     for account in accounts:
    #         db.session.delete(account)
    #     db.session.commit()
    #     return jsonify({"code": 0, "message": "Success", "data": {}})
    # else:
    id = data.get("id")
    if not isinstance(id, list):
        id = [id]
    for each in id:
        if not isinstance(each, int):
            return jsonify({"code": 1, "message": "id参数类型错误", "data": {}})
    ids = []
    for each in id:
        account = Honeyaccount.query.filter_by(id=each).first()
        if account is None:
            ids.append(each)
            continue
            # return jsonify({"code": 1, "message": "no such account", "data": {}})
        db.session.delete(account)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"code": 1, "message": "no such account", "data": {}})
    return jsonify({"code": 0, "message": "Success", "data": {}})


@api.route("/account/modify", methods=["POST"])
def account_modify():
    data = request.get_json()
    id = int(data["id"])
    account = Honeyaccount.query.filter_by(id=id).first()
    if account is None:
        return jsonify({"code": 1, "message": "no such account", "data": {}})
    if data["honeypot"] != "" and data["honeypot"] is not None:
        if not validate_url_format(data["honeypot"]):
            return jsonify({"code": 1, "message": "引导url格式错误", "data": {}})
        account.honeypot = data["honeypot"]
    if data["username"] != "" and data["username"] is not None:
        account.username = data["username"]
    if data["password"] != "" and data["password"] is not None:
        account.password = data["password"]
    db.session.add(account)
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


# 下载账户信息
@api.route("/account/download", methods=["POST"])
def account_config_download():
    # 检查参数
    # id_str = request.args.getlist("id")
    data = request.get_json()
    id = data.get("id")
    if id is None or id == [] or id == "":
        return jsonify({"code": 1, "message": "No id provided", "data": {}})
    if not isinstance(data["id"], list):
        id = [data["id"]]
    else:
        id = data["id"]
    accounts = []
    if data.get("browser_type") is None:
        return jsonify({"code": 1, "message": "No browser type provided", "data": {}})
    browser_type = data["browser_type"]
    if (data.get("is_app") is None) or (data.get("is_app") != True):  # 是否包含app
        is_app = False
    else:
        is_app = True

    for each in id:
        account = Honeyaccount.query.filter_by(id=each).first()
        if account is None:
            break
        for each in accounts:
            if account.honeypot == each.honeypot:  # 判断url是否重复
                return jsonify({"code": 1, "message": "存在重复url", "data": {}})
        accounts.append(account)
    if len(accounts) == 0:
        return jsonify({"code": 1, "message": "no such account", "data": {}})

    start_time = datetime(2018, 1, 1)
    end_time = datetime.now()
    random_time = random_date(start_time, end_time)
    # print(random_time)
    with zipfile.ZipFile("./temp/honeyaccount.zip", "w") as zipf:
        if "firefox" in browser_type:
            with open("./temp/firefox.cfg", "w") as cfg:
                i = 1
                for account in accounts:
                    cfg.write("[credential" + str(i) + "]\n")
                    cfg.write(f"hostname:{account.honeypot}\n")
                    cfg.write(f"username:{account.username}\n")
                    cfg.write(f"password:{account.password}\n")
                    cfg.write(f"timeCreated:{random_time}\n")
                    cfg.write(
                        f"timeLastUsed:{random_time + timedelta(days=random.randint(20, 200))}\n"
                    )
                    cfg.write(f"timePasswordChanged:{random_time}\n")
                    cfg.write(f"timeUsed:{random.randint(20, 30)}\n")
                    i = i + 1
            zipf.write("./temp/firefox.cfg", "firefox.cfg")
        if "chrome" in browser_type:
            with open("./temp/chrome.cfg", "w") as cfg:
                i = 1
                for account in accounts:
                    cfg.write("[site" + str(i) + "]\n")
                    cfg.write(f"url={account.honeypot}\n")
                    cfg.write(f"username={account.username}\n")
                    cfg.write(f"password={account.password}\n")
                    cfg.write(f"date={random_time}\n")
                    i = i + 1
            zipf.write("./temp/chrome.cfg", "chrome.cfg")
        if "edge" in browser_type:
            with open("./temp/edge.cfg", "w") as cfg:
                i = 1
                for account in accounts:
                    cfg.write("[site" + str(i) + "]\n")
                    cfg.write(f"url={account.honeypot}\n")
                    cfg.write(f"username={account.username}\n")
                    cfg.write(f"password={account.password}\n")
                    cfg.write(f"date={random_time}\n")
                    i = i + 1
            zipf.write("./temp/edge.cfg", "edge.cfg")
        if is_app:
            zipf.write("./browser.exe")
    zipf.close()
    return send_file(project_path + "/temp/honeyaccount.zip", as_attachment=True)


@api.route("/systemwire/account/findby", methods=["POST"])
def account_findby():
    data = request.get_json()
    query = Honeyaccount.query
    page_num = data["page_num"]
    page_size = data["page_size"]
    account_infos = []
    if data.get("url"):  # url查询
        url = str.lower(data.get("url"))
        query = query.filter(Honeyaccount.position.like("%" + url + "%"))
    if data.get("username"):  # 账号名查询
        username = str.lower(data.get("username"))
        query = query.filter(Honeyaccount.honeypoint_name.like("%" + username + "%"))
    accounts = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    # if accounts is None:
    #     return jsonify({"code":0,"message":"","data":{},"total":0})
    for account in accounts:
        account_infos.append(account.to_json())
    return jsonify(
        {"code": 0, "message": "Success", "data": account_infos, "total": total}
    )


# ── 账户蜜点告警已迁移到 alert_server ──
# systemwire2 通过定时任务从 alert_server 拉取，见 get_account_alert()

@api.route("/email/add", methods=["POST"])
def email_account_add():
    # 参数完整性检验
    data = request.get_json()
    if (
            data.get("username") is None or data.get("username") == ""
            or data.get("password") is None or data.get("password") == ""
            or data.get("server") is None or data.get("server") == ""
            or data.get("protocol") is None or data.get("protocol") == ""
    ):
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    # 账号、密码、服务器检验
    if validate_email_account(data.get("username")):
        return jsonify(
            {"code": 1, "message": "邮箱账户格式有误(正确格式:xxx@xxx.xxx)", "data": {}}
        )  # 邮箱格式不正确
    elif validate_password(data.get("password")):
        return jsonify(
            {"code": 1, "message": "密码不符合要求(要求:长度5至16位、数字、大小写字母、特殊符号@#$_&.)", "data": {}}
        )  # 密码格式不正确
    # elif validate_domain(data.get("server")):
    #     return jsonify(
    #         {"code": 1, "message": "Server format is incorrect", "data": {}}
    #     )  # 服务器格式不正确

    # 检查账号是否已存在
    account = Honeyemail.query.filter_by(username=data["username"]).first()
    if account != None:
        return jsonify({"code": "1", "message": "该邮箱账户已存在", "data": {}})
    new_account = Honeyemail()
    new_account.username = data["username"]
    new_account.password = data["password"]
    new_account.server = data["server"]
    new_account.email_count = 0
    new_account.last_receive_count = 0
    new_account.last_receive_time = None
    new_account.pull_cycle = 10
    new_account.protocol = data["protocol"]
    db.session.add(new_account)
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


# 清除所有邮箱账号
@api.route("/email/clear", methods=["POST"])
def email_account_clear():
    data = request.get_json()
    errors = {}
    if data["clearall"] == True:
        accounts = Honeyemail.query.all()
        for account in accounts:  # 删除数据库中的账号
            # 删除账号文件夹
            dirname = account.username.split("@")[0]
            path = f"./email/{account.protocol}/" + dirname
            try:
                for filename in os.listdir(path):
                    file_path = os.path.join(path, filename)
                    try:
                        os.unlink(file_path)  # 删除文件
                    except Exception as e:
                        errors[account.username] = str(e)
                        continue
            except Exception as e:
                errors[account.username] = str(e)
                continue
        return jsonify({"code": 0, "message": "Success", "data": errors})
    else:
        account = Honeyemail.query.filter_by(id=data["id"]).first()
        if account is None:
            return jsonify({"code": 1, "message": "no such account", "data": {}})
        dirname = account.username.split("@")[0]
        path = f"./email/{account.protocol}/" + dirname
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                os.unlink(file_path)
            except Exception as e:
                return jsonify({"code": 1, "message": e, "data": {}})
        return jsonify({"code": 0, "message": "Success", "data": {}})


# 生成蜜点邮箱账号
@api.route("/email/generate", methods=["POST"])
def email_account_generate():
    # 参数完整性检验(form)
    # request.form.get()
    seeds = request.args.get("username")
    num = request.args.get("num")
    server = request.args.get("server")
    domain = request.args.get("domain")
    protocol = request.args.get("protocol")
    if (
            seeds is None
            or num is None
            or server is None
            or domain is None
            or protocol is None
    ):
        return jsonify({"code": 1, "message": "参数不完整", "data": {}})

    if validate_username(seeds):
        return jsonify(
            {"code": 1, "message": "种子账户格式不正确", "data": {}}
        )
    # if validate_domain(server) or validate_domain(domain):
    #     return jsonify(
    #         {"code": 1, "message": "Server or domain format is incorrect", "data": {}}
    #     )
    if num.isdigit() == False or int(num) <= 0:
        return jsonify({"code": 1, "message": "数据格式不正确", "data": {}})

    if "@" not in domain:
        domain = "@" + domain
    seed = seeds.split("@")[0]  # 去除邮箱后缀
    print("seed", seed)
    print("num", num)
    usernames = username_generate(seed, int(num))
    print("username", usernames)
    for index,username in enumerate(usernames):
        account = Honeyemail.query.filter_by(username=username).first()
        while account != None:
            usernames[index] = username_generate(seed, 1)[0]
            account = Honeyemail.query.filter_by(username=usernames[index]).first()
            
    for i in range(len(usernames)):
        usernames[i] = usernames[i] + domain
    passwords = password_genaerate(int(num))
    account = dict(zip(usernames, passwords))
    print(account)
    for username in usernames:
        new_account = Honeyemail()
        new_account.username = username
        new_account.password = account[username]
        new_account.server = server
        new_account.email_count = 0
        new_account.last_receive_count = 0
        new_account.last_receive_time = None
        new_account.pull_cycle = 10
        new_account.protocol = protocol
        try:
            db.session.add(new_account)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({"code": 1, "message": str(e), "data": {}})
        # 创建账号文件夹
        path = f"./email/{protocol}/" + username.split("@")[0]
        if not os.path.exists(path):
            os.makedirs(path)
    return jsonify({"code": 0, "message": "Success", "data": {}})


@api.route("/email/account_search", methods=["POST"])
def email_account_search():
    data = request.get_json()

    # 参数完整性检验
    page_num = data.get("page_num", 1)
    page_size = data.get("page_size", 100)

    account_infos = []
    query = Honeyemail.query
    if data.get("id"):
        id = int(data["id"])
        query = query.filter_by(id=id).first()
        if query is None:
            return jsonify({"code": 1, "message": "no such account", "data": {}})
        else:
            return jsonify(
                {"code": 0, "message": "Success", "data": query.to_json(), "total": 1}
            )
    if data.get("server"):
        server = data["server"]
        # query = query.filter_by(server=server)
        query = query.filter(Honeyemail.server.like("%" + server + "%"))
    if data.get("account"):
        account = data["account"]
        # query = query.filter_by(username=account)
        query = query.filter(Honeyemail.username.like("%" + account + "%"))
    if "status" in data:
        status = data["status"]
        if status == 0:  # 状态正常
            query = query.filter_by(last_receive_state="working")
        else:  # 状态异常
            if query != None:
                query = query.filter(
                    or_(
                        Honeyemail.last_receive_state != "working",
                        Honeyemail.last_receive_state == None,
                    )
                )  # query为空时filter()可能报错
    if data.get("protocal"):
        protocol = data["protocal"]
        query = query.filter_by(protocol=protocol)
    accounts = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    for account in accounts:
        info = account.to_json()
        info["created_time"] = account.created_at.strftime("%Y-%m-%d %H:%M:%S")
        if account.last_receive_time:
            info["last_receive_time"] = account.last_receive_time.replace(tzinfo=pytz.utc).astimezone(
                pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
        # if account.last_receive_state == "working":
        #     info["last_receive_state"] = "正常"
        # else:
        #     info["last_receive_state"] = "异常"
        account_infos.append(info)
    return jsonify(
        {"code": 0, "message": "Success", "data": account_infos, "total": total}
    )


# 获取邮箱账号数量
@api.route("/email/account/count", methods=["GET"])
def email_account_count():
    count = Honeyemail.query.count()
    return jsonify({"code": 0, "message": "Success", "data": {'count': count}})


# 删除邮箱账号
@api.route("/email/delete", methods=["POST"])
def email_account_delete():
    data = request.get_json()
    errors = {}
    # 参数校验
    if data.get("id") == None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    # 单个或批量删除
    if not isinstance(data["id"], list):
        id = [data["id"]]
    else:
        id = data["id"]

    for each in id:
        # 查询数据库中账户信息
        if not isinstance(each, int):
            return jsonify({"code": 1, "message": "Id must be int", "data": {}})
        account = Honeyemail.query.filter_by(id=each).first()
        if account is None:
            return jsonify(
                {"code": 1, "message": "no such account id:" + str(each), "data": {}}
            )

        # 删除数据库中账户信息
        try:
            db.session.delete(account)  # 删除数据库中账户信息
            db.session.commit()
        except SQLAlchemyError as e:  # 处理数据库操作异常
            db.session.rollback()
            current_app.logger.error("Email account data delete error" + str(e))
            # return jsonify({"code": 1, "message": str(e), "data": {}})
            errors[account.username] = str(e)
            continue

        # 删除账户文件夹
        dirname = account.username.split("@")[0]
        path = f"./email/{account.protocol}/" + dirname
        if not os.path.exists(path):  # 判断目录是否存在
            continue
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                os.unlink(file_path)  # 删除文件
            except OSError as e:  # 处理文件删除异常
                current_app.logger.error("Email account temp delete error" + str(e))
                # return jsonify({"code": 1, "message": str(e), "data": {}})
                errors[account.username] = str(e)
                continue
        os.rmdir(path)  # 删除空文件夹
    if errors != {}:
        return jsonify({"code": 1, "message": "部分邮件账户删除失败", "data": errors})
    return jsonify({"code": 0, "message": "Success", "data": {}})


# 导出邮件账号,以表格的形式
@api.route("/email/export", methods=["POST"])
def email_account_export():
    data = request.get_json()
    if data.get("id") is None or data.get("id") == []:
        accounts = Honeyemail.query.all()
    else:
        # 批量导出
        accounts = []
        id = data["id"]
        for each in id:
            account = Honeyemail.query.filter_by(id=each).first()
            if account is None:
                return jsonify(
                    {
                        "code": 1,
                        "message": "所选蜜点不存在!",
                        "data": {},
                    }
                )
            accounts.append(account)

    # 设置表格
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "邮箱账号"  # 表名
    sheet.column_dimensions["A"].width = 20  # 单元格的宽度
    sheet.column_dimensions["B"].width = 20
    font = openpyxl.styles.Font(size=14, bold=True)  # 字体
    sheet["A1"] = "账号"
    sheet["B1"] = "密码"
    sheet["A1"].font = font
    sheet["B1"].font = font
    for account in accounts:
        # 处理账号中的特殊字符
        username = re.sub(r"[^\x20-\x7E]+", "", account.username)
        # password = re.sub(r"[^\x20-\x7E]+", "", account.password)
        sheet.append([account.username, account.password])
    workbook.save("./email_account.xlsx")
    return send_file(project_path + "/email_account.xlsx", as_attachment=True)


# 修改邮箱账号信息
@api.route("/email/modify", methods=["POST"])
def email_account_modify():
    data = request.get_json()
    if data.get("id") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
    id = data["id"]
    account = Honeyemail.query.filter_by(id=id).first()
    if account is None:
        return jsonify({"code": 1, "message": "所选邮件账户不存在，请刷新页面", "data": {}})
    if data["password"] != "" and data["password"] != None:
        if validate_password(data["password"]):
            return jsonify(
                {"code": 1, "message": "Password format is incorrect", "data": {}}
            )
        account.password = data["password"]
    if data["server"] != "" and data["server"] is not None:
        if validate_domain(data["server"]):
            pass
            # return jsonify(
            #     {"code": 1, "message": "Server format is incorrect", "data": {}}
            # )
        account.server = data["server"]
    if data["username"] != "" and data["username"] is not None:
        if validate_email_account(data["username"]):
            return jsonify(
                {"code": 1, "message": "Username format is incorrect", "data": {}}
            )
        account.username = data["username"]
    db.session.add(account)
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


@api.route("/email/search", methods=["POST"])
def email_search():
    data = request.get_json()
    page_num = data.get("page_num", 1)
    page_size = data.get("page_size", 100)

    query = EmailInfo.query
    if data.get("account"):
        query = query.filter(EmailInfo.username.like("%" + data["account"] + "%"))
    if data.get("server"):
        query = query.filter(EmailInfo.server.like("%" + data["server"] + "%"))
    if data.get("start_time"):
        # print(data["start_time"])
        start_time = datetime.strptime(data["start_time"], "%Y-%m-%d %H:%M:%S")
        query = query.filter(EmailInfo.receive_time >= start_time)  # 查询start_time之后的邮件
    if data.get("end_time"):
        # print(data["end_time"])
        end_time = datetime.strptime(data["end_time"], "%Y-%m-%d %H:%M:%S")
        query = query.filter(EmailInfo.receive_time <= (end_time))  # 查询end_time之前的邮件
    if data.get("email_type") or data.get("email_type") == 0:
        if data["email_type"] == 1:
            query = query.filter(EmailInfo.email_type == "pfish")
        else:
            query = query.filter(EmailInfo.email_type == "spam")
    query = query.order_by(EmailInfo.receive_time.desc())  # 按时间降序排列
    emails = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    email_infos = []
    for result in emails:
        info = {
            "server": result.server,
            "account_id": result.account_id,
            "account": result.username,
            "sender": result.sender,
            "subject": result.subject,
            "type": result.email_type,
            "header": result.header,
            "email_id": result.email_id,
            "time": result.receive_time.strftime("%Y-%m-%d %H:%M:%S")
        }
        email_infos.append(info)

    return jsonify({"code": 0, "data": email_infos, "message": "", "total": total})


# 删除邮件
@api.route("/email/email_delete", methods=["POST"])
def email_delete():
    data = request.get_json()
    if data.get("account_id") is None or data.get("email_id") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
    account = Honeyemail.query.filter_by(id=data["account_id"]).first()
    if account is None:
        return jsonify({"code": 1, "message": "no such account", "data": {}})

    if account.protocol == "pop3":  # pop3协议不支持删除邮件
        return jsonify({"code": 1, "message": "当前邮箱的协议不支持删除操作.", "data": {}})

    if not isinstance(data["email_id"], list):
        email_id = [data["email_id"]]
    else:
        email_id = data["email_id"]
    for each in email_id:
        # 从邮箱中删除邮件
        msg, code = delete_email_imap(
            account.username, account.password, account.server, each
        )
        # 删除本地邮件文件
        # os.remove(f'./email/{emailinfo.username.split("@")[0]}/{emailinfo.email_id}.eml')

        # 从数据库中删除邮件分析结果
        emailinfo = EmailInfo.query.filter_by(email_id=each).first()
        if emailinfo is None:
            return jsonify({"code": 1, "message": "no such email", "data": {}})
        try:
            db.session.delete(emailinfo)
            db.session.commit()
        except Exception as e:
            return jsonify({"code": 1, "message": e, "data": {}})

    return jsonify({"code": 0, "message": "Email delete success", "data": {}})


@api.route("/email/pull", methods=["POST"])
def email_pull():
    data = request.get_json()
    errors = {}
    print("pull email")
    if data["pullall"] == True:
        accounts = Honeyemail.query.all()
        for account in accounts:
            if account.protocol == "pop3":
                error, receive_count = get_email_pop3(
                    account.username, account.password, account.server
                )
            else:
                error, receive_count = get_email_imap(
                    account.username, account.password, account.server
                )
            num = len(
                os.listdir(
                    f'./email/{account.protocol}/{account.username.split("@")[0]}'
                )
            )
            account.email_count = num
            account.last_receive_count = receive_count
            if error != None:
                account.last_receive_state = error[2:-1]
                errors[account.username] = error[2:-1]
            else:
                account.last_receive_state = "working"
            account.last_receive_time = get_time_bj()
            db.session.add(account)
            db.session.commit()
        return jsonify({"code": 0, "message": "Success", "data": errors})
        # return jsonify({"code": 0, "message": "Success", "data": {errors}})
    else:
        id = data["id"]
        account = Honeyemail.query.filter_by(id=id).first()
        if account is None:
            return jsonify({"code": 1, "message": "no such account", "data": {}})
        if account.protocol == "pop3":
            error, receive_count = get_email_pop3(
                account.username, account.password, account.server
            )
        else:
            error, receive_count = get_email_imap(
                account.username, account.password, account.server
            )
        num = len(
            os.listdir(f'./email/{account.protocol}/{account.username.split("@")[0]}')
        )
        account.email_count = num
        account.last_receive_count = receive_count
        if error != None:
            account.last_receive_state = error[2:-1]
        else:
            account.last_receive_state = "working"
        account.last_receive_time = get_time_bj()
        db.session.add(account)
        db.session.commit()
        return jsonify({"code": 0, "message": "", "data": {}})


@api.route("/email/analyze", methods=["POST"])
def email_analyze():
    data = request.get_json()
    email_infos = []
    if data["analyzeall"] == True:
        accounts = Honeyemail.query.all()
        for account in accounts:
            if account.email_count > 0 or account.last_receive_count >= 0:  # 若账号中有邮件
                if (os.path.exists(
                        f'./email/{account.protocol}/{account.username.split("@")[0]}') == False):  # 若账号文件夹不存在
                    continue
                for file in os.listdir(f'./email/{account.protocol}/{account.username.split("@")[0]}'):  # 遍历账号文件夹
                    path = os.path.join(
                        f'./email/{account.protocol}/{account.username.split("@")[0]}',
                        file,
                    )  # 获取文件路径
                    # 检查文件大小
                    if os.path.getsize(path) == 0:
                        continue
                    pfish, sender, subject, time_str, header, parse_info = analyze_email(path)  # 解析邮件
                    current_app.logger.debug(
                        f"[Email]Parse account:{account.username},subject:{subject},time_str:{time_str}")

                    email_id = int(file.split(".")[0].split("_")[1])  # 获取邮件id
                    email_type = "pfish" if pfish else "spam"  # 获取邮件类型
                    email_info = {
                        "server": account.server,
                        "account": account.username,
                        "sender": sender,
                        "subject": subject,
                        "time": time_str,
                        "type": email_type,
                        "header": header,
                        "email_id": email_id,
                    }
                    # 处理时间格式
                    # datetime_obj = timestr_to_datetime(time_str)
                    datetime_obj = get_time_bj(timestr_to_datetime(time_str))
                    if datetime_obj is None:
                        current_app.logger.error(
                            f"[Email]Parse time error,account:{account.username},subject:{subject},time_str:{time_str}")
                        continue
                        # return jsonify({"code": 1, "message": "邮件解析出错!", "data": {}})
                    emailInfo = EmailInfo.query.filter(
                        and_(
                            EmailInfo.username == account.username,
                            EmailInfo.email_id == email_id,
                        )
                    ).first()  # 查询数据库中是否有该邮件
                    if emailInfo is not None:
                        # print("emailInfo is not None "+emailInfo.username)
                        emailInfo.email_type = email_type
                        emailInfo.receive_time = datetime_obj
                        emailInfo.header = header
                        db.session.add(emailInfo)
                    else:
                        emailInfo = EmailInfo(
                            server=account.server,
                            account_id=account.id,
                            username=account.username,
                            sender=sender,
                            subject=subject,
                            receive_time=datetime_obj,
                            email_type=email_type,
                            header=header,
                            email_id=email_id,
                        )
                        # print("emailInfo is None"+emailInfo.username)
                        db.session.add(emailInfo)
                    db.session.commit()
                    email_infos.append(email_info)  # 将邮件信息添加到列表中
        return jsonify(
            {"code": 0, "message": "result saved in database", "data": email_infos}
        )
    else:
        account = Honeyemail.query.filter_by(id=data["id"]).first()
        if account is None:
            return jsonify({"code": 1, "message": "no such account", "data": {}})
        if account.email_count > 0 or account.last_receive_count >= 0:
            for file in os.listdir(
                    f'./email/{account.protocol}/{account.username.split("@")[0]}'
            ):
                path = os.path.join(
                    f'./email/{account.protocol}/{account.username.split("@")[0]}', file
                )
                # print(path)
                # 检查文件大小
                if os.path.getsize(path) == 0:
                    continue
                email_id = int(file.split(".")[0].split("_")[1])
                pfish, sender, subject, time_str, header, parse_info = analyze_email(path)
                email_type = "pfish" if pfish else "spam"
                email_info = {
                    "server": account.server,
                    "account": account.username,
                    "sender": sender,
                    "subject": subject,
                    "time": time_str,
                    "type": email_type,
                    "header": header,
                    "email_id": email_id,
                }
                # print(time_str.rsplit(' ',1)[0])
                # 处理时间格式
                datetime_obj = get_time_bj(timestr_to_datetime(time_str)) 

                emailInfo = EmailInfo.query.filter(
                    and_(
                        EmailInfo.username == account.username,
                        EmailInfo.email_id == email_id,
                    )
                ).first()
                if emailInfo is not None:
                    # print(emailInfo.email_id)
                    emailInfo.email_type = email_type
                    emailInfo.receive_time = datetime_obj
                    emailInfo.header = header
                else:
                    emailInfo = EmailInfo(
                        server=account.server,
                        username=account.username,
                        sender=sender,
                        subject=subject,
                        receive_time=datetime_obj,
                        email_type=email_type,
                        header=header,
                        email_id=email_id,
                    )
                    # print(emailInfo.email_id)
                    db.session.add(emailInfo)
                db.session.commit()
                email_infos.append(email_info)
        return jsonify(
            {"code": 0, "message": "result saved in database", "data": email_infos}
        )


# 邮件分析结果查询
@api.route("/email/analyze_result", methods=["POST"])
def email_analyze_search():
    data = request.get_json()
    page_num = data["page_num"]
    page_size = data["page_size"]
    try:
        analyze_results = EmailInfo.query.order_by(EmailInfo.receive_time.desc()).paginate(
            page=page_num, per_page=page_size, error_out=False
        )
        total = EmailInfo.query.count()
    except Exception as e:
        return jsonify({"code": 1, "message": str(e), "data": {}})
    infos = []
    for result in analyze_results:
        info = {
            "server": result.server,
            "account": result.username,
            "sender": result.sender,
            "subject": result.subject,
            "time": result.receive_time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": result.email_type,
            "header": result.header,
            "email_id": result.email_id,
        }
        infos.append(info)
    return jsonify({"code": 0, "message": "Success", "data": infos, "total": total})


# 邮件分析结果清空
@api.route("/email/analyze_result_clear", methods=["POST"])
def email_analyze_clear():
    emailInfos = EmailInfo.query.all()
    for emailInfo in emailInfos:
        try:
            db.session.delete(emailInfo)
        except:
            continue
    db.session.commit()
    return jsonify({"code": 0, "message": "Success", "data": {}})


# 邮件占用内存容量
@api.route("/email/capacity", methods=["GET"])
def email_capacity_export():
    full = 100  # 100MB 总容量
    total_size = 0
    for root, dirs, files in os.walk("./email"):
        for file in files:
            total_size += os.path.getsize(os.path.join(root, file))
    total_size = total_size / 1024 / 1024  # byte --> MB
    occupied = total_size / full
    total_size = round(total_size, 2)
    occupied = round(occupied, 4)
    return jsonify(
        {
            "code": 0,
            "message": "",
            "data": {
                "total_size": total_size,
                "full": full,
                "occupied": occupied,
                "unit": "MB",
            },
        }
    )


@api.route("/email/findby", methods=["GET"])
def email_findby():
    data = request.get_json()
    page_num = data["page_num"]
    page_size = data["page_size"]
    emailAccount_infos = []
    query = Honeyemail.query
    if data["username"]:
        query = query.username.like("%" + data["username"] + "%")
    if data["server"]:
        query = query.server.like("%" + data["server"] + "%")
    emailAccounts = query.paginate(page=page_num, per_page=page_size, error_out=False)
    total = query.count()
    if emailAccounts is None:
        return jsonify(
            {"code": 0, "data": emailAccount_infos, "message": "", "total": 0}
        )
    for emailAccount in emailAccounts:
        emailAccount_infos.append(emailAccount.to_json())
    return jsonify(
        {"code": 0, "data": emailAccount_infos, "message": "", "total": total}
    )


# 查询蜜点数量
@api.route("/info", methods=["GET"])
def systemwire_info():
    honeyemail_count = Honeyemail.query.count()
    honeyaccount_count = Honeyaccount.query.count()
    honeyfile_count = Honeyfile.query.count()
    return jsonify({"code": 0,
                    "message": "Success",
                    "data": {
                        'honeyfileCount': honeyemail_count,
                        'honeyaccountCount': honeyaccount_count,
                        'honeyemailCount': honeyfile_count,
                    }})


class Config(object):
    SCHEDULER_TIMEZONE = "Asia/Shanghai"
    SCHEDULER_API_ENABLED = True

##################################### 告警 ############################################
# 从文件告警服务器拉取告警信息
#@api.route("/file/alert", methods=["GET"])
def get_file_alert(last_query_time, count=100):
    # current_app.logger.info("1.Get log from remote server")
    url = Server_config.alert_server_manage_address+ "/alert/file"
    # current_app.logger.info(f"last_query_time:{last_query_time}")
    
    time_format = Server_config.time_format
    if time_format == 'datetime':
        last_query_time_str = last_query_time.strftime("%Y-%m-%d %H:%M:%S")
        req_time = last_query_time_str
    else:
        req_time = int(last_query_time.astimezone(timezone.utc).timestamp())    # 转为int只取整数部分
    # current_app.logger.info(f"{time_format}:{req_time}")

    form = {
        "key": Server_config.api_key,
        "count": count,
        "time_format":time_format,  # 时间类型:datetime/timestamp
        "time":req_time,            # 查询的时间
    }
    # 增加 Authorization 头
    headers = {
        "Authorization": f"Bearer {Server_config.api_key}"
    }
    # alert_server 当前版本 GET 里 timestamp 分支读 query，datetime 分支读 form。
    # 同时传 params/data 可以兼容两种读取方式，避免本地部署时拉取不到时间参数。
    req_err, response = _alert_server_request(
        "file alert pull",
        "GET",
        url,
        params=form,
        data=form,
        headers=headers,
        verify=False,
        timeout=15,
    )
    if req_err:
        return 1, str(response)
    if response.status_code != 200:
        return 1, f"Get file alert error:{response.status_code}"
    try:
        res = response.json()
    except Exception as e:
        return 1, f"alert_server returned non-json response: {str(e)}"
    if res.get("code") != 0:
        return 1, f"Get file alert error:{res.get('message')}"
    # current_app.logger.info(f"2.Insert to database")
    data = _extract_alert_server_trigger_infos(res)
    current_app.logger.info(f"[File Alert] alert_server returned {len(data)} trigger records")
    alert_info_objects = []
    source_payloads = []
    batch_logical_alerts = defaultdict(list)
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            dt = _parse_alert_server_time(_first_present(item, "Trigger_time", "trigger_time", "time", "created_at"))
        except Exception as e:
            current_app.logger.warning(f"Skip file alert with invalid trigger time: {e}, item={item}")
            continue
        token = _normalize_file_token(_first_present(item, "Token_url", "Token", "token_url", "token"))
        if not token:
            current_app.logger.warning(f"Skip file alert without token: {item}")
            continue
        token_url = _file_alert_public_token_url(token)
        legacy_token_url = f"{Server_config.alert_server_manage_address.rstrip('/')}/contact/{token}"
        report_ip = _first_present(item, "Trigger_ip", "trigger_ip", "ip", "src_ip", default="")
        alert_message = _first_present(item, "Alert_msg", "alert_msg", "message", "description", default="")
        report_agent = _first_present(item, "Trigger_agent", "trigger_agent", "User-Agent", "user_agent", default="")
        logical_key = _file_alert_logical_key(token, report_ip, report_agent, alert_message)
        if any(_file_alert_in_same_open(dt, seen_dt) for seen_dt in batch_logical_alerts[logical_key]):
            continue
        batch_logical_alerts[logical_key].append(dt)
        duplicate_start = dt - timedelta(seconds=60)
        duplicate_end = dt + timedelta(seconds=60)
        exists = FileAlertInfo.query.filter(
            FileAlertInfo.trigger_time >= duplicate_start,
            FileAlertInfo.trigger_time <= duplicate_end,
            FileAlertInfo.report_ip == report_ip,
            FileAlertInfo.report_agent == report_agent,
            FileAlertInfo.token.in_([token_url, legacy_token_url, token])
        ).first()
        if exists:
            continue
        alert_info = FileAlertInfo(
            trigger_time=dt,
            alert_message=alert_message,
            report_ip=report_ip,
            token=token_url,
            report_agent=report_agent
        )
        alert_info_objects.append(alert_info)
        source_payloads.append(item)
    # 批量插入记录
    try:
        db.session.add_all(alert_info_objects)
        db.session.flush()
        for alert_info, item in zip(alert_info_objects, source_payloads):
            ingest_file_alert(
                source_service="alert_server",
                source_event_id=f"pull-file-{alert_info.id}",
                trigger_time=alert_info.trigger_time,
                token_url=alert_info.token,
                message=alert_info.alert_message,
                report_ip=alert_info.report_ip,
                report_agent=alert_info.report_agent,
                raw_payload=item,
                legacy_row_id=alert_info.id,
            )
        db.session.commit()
        # current_app.logger.info(f"[test] 插入告警信息数量: {len(alert_info_objects)}")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"ERROR: {str(e)}")
        return 1, f"Insert alert info error: {str(e)}"
    # current_app.logger.info(f"Success: Insert total {len(alert_info_objects)}")
    return 0, len(alert_info_objects)  # 返回获取的告警数量


# 拉取文件告警
@api.route("/file/alert", methods=["GET"])
def file_alert_pull():
    with current_app.app_context():
        current_app.logger.info("Get last query time")
        force_days = request.args.get("days", default=0, type=int)
        record = LastQueryTime.query.filter_by(query_type="file_alert_pull").first()
        if force_days and force_days > 0:
            last_query_time = get_time_bj() - timedelta(days=min(force_days, 30))
        elif record:
            last_query_time = record.query_time
        else:
            last_query_time = get_time_bj() - timedelta(days=7)

        current_app.logger.info(f"Time range: {last_query_time} - {get_time_bj()}")
        err, pull_count = get_file_alert(last_query_time)
        if err:
            return jsonify({"code": 1, "message": f"Get file alert error: {str(pull_count)}", "data": []})

        push_kafka = request.args.get("push_kafka", default="0", type=str).lower() in ("1", "true", "yes")
        kafka_result = "skipped"
        if push_kafka:
            current_app.logger.info("Push file alert to kafka")
            err, kafka_result = send_alert_file(last_push_time=last_query_time)
            current_app.logger.info(f"Push total: {kafka_result}")
            if err == 1:
                return jsonify({"code": 1, "message": f"Push file alert error: {str(kafka_result)}", "data": []})
            if err == 2:
                return jsonify({"code": 1, "message": f"Push file alert baseinfo error: {str(kafka_result)}", "data": []})

        if record is None:
            record = LastQueryTime()
            record.query_type = "file_alert_pull"
        record.query_time = get_time_bj()

        try:
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Record query time ERROR:{str(e)}")
            return jsonify({"code": 1, "message": f"Record query time ERROR:{str(e)}", "data": []})

        return jsonify({
            "code": 0,
            "message": "Success",
            "data": {
                "pulled": pull_count,
                "kafka": kafka_result,
                "last_query_time": last_query_time.isoformat() if last_query_time else None,
                "query_time": record.query_time.isoformat() if record.query_time else None,
            },
        })

# @api.route("/file/alert/search", methods=["GET"])
# def file_alert_search():
#     page_num = request.args.get("page_num")
#     page_size = request.args.get("page_size")
#     if page_num == None or page_size == None:
#         # return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
#         page_num = 1
#         page_size = 10
#     # 查询最近的page_size条告警信息,左连接查询告警信息和告警文件信息
#     alerts = FileAlertInfo.query.paginate(page=int(page_num), per_page=int(page_size), error_out=False)
#     total = FileAlertInfo.query.count()
#     infos = []
#     for each in alerts:
#         info = each.to_json()
#         infos.append(info)

#     return jsonify({"code": 0, "message": "Success", "data": infos, "total": total})


@api.route("/file/alert/test", methods=["GET"])
def alert_test():
    # 读取上次查询时间
    res = LastQueryTime.query.filter_by(query_type="file_alert").first()
    if res:
        last_query_time = res.query_time
    else:
        last_query_time = get_time_bj() - timedelta(days=7)
    current_app.logger.info(f"Push file alert: {last_query_time} - now")
    # print("发送文件测试警告日志")
    err, res = send_alert_file(last_push_time=last_query_time)
    if err:
        return jsonify({"code": 1, "message": str(res), "data": ""})
    # print("发送邮件测试警告日志")
    err, res = send_alert_email(last_query_time=last_query_time)
    if err:
        return jsonify({"code": 1, "message": str(res), "data": ""})
    return jsonify({"code": 0, "message": "Success", "data": ""})


# 文件类型字典库新增数据
@api.route("/file/dict/add", methods=["POST"])
def file_dict_add():
    data = request.get_json()
    if data.get("fileType") is None or data.get("fileTypeCN") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})
    # 判断文件类型是否为字母
    if not data.get("fileType").isalpha():
        return jsonify({"code": 1, "message": "File type must be alphabet", "data": {}})

    file_type = data.get("fileType")
    file_type_cn = data.get("fileTypeCN")
    description = data.get("description")

    file_obj = FileTypeDict.query.filter_by(file_type=file_type).first()
    if file_obj:
        return jsonify({"code": 1, "message": "字典数据修改失败：文件类型已经存在", "data": {}})

    file_type_dict = FileTypeDict(file_type=file_type, file_type_cn=file_type_cn, description=description)
    try:
        db.session.add(file_type_dict)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"code": 1, "message": "字典数据新增失败：" + str(e), "data": {}})
    return jsonify({"code": 0, "message": "字典数据新增成功", "data": {}})


# 文件类型字典库查询
@api.route("/file/dict/search", methods=["GET"])
def file_dict_search():
    args = request.args
    page_num = args.get("pageNum", 1)
    page_size = args.get("pageSize", 20)
    file_type = args.get("fileType")
    file_type_cn = args.get("fileTypeCn")

    query = FileTypeDict.query
    if file_type:
        query = query.filter_by(file_type=file_type)
    if file_type_cn:
        query = query.filter_by(file_type_cn=file_type_cn)
    file_type_dicts = query.paginate(page=int(page_num), per_page=int(page_size), error_out=False)
    total = query.count()
    infos = []
    for each in file_type_dicts:
        info = each.to_json()
        infos.append(info)
    return jsonify({"code": 0, "message": "Success", "data": {"total": total, "items": infos}})


# 文件类型字典库删除
@api.route("/file/dict/delete", methods=["POST"])
def file_dict_delete():
    data = request.get_json()
    if data.get("id") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    id = data.get("id")
    file_type_dict = FileTypeDict.query.filter_by(id=id).first()
    if file_type_dict is None:
        return jsonify({"code": 1, "message": "字典数据不存在", "data": {}})
    try:
        db.session.delete(file_type_dict)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"code": 1, "message": "字典数据删除失败：" + str(e), "data": {}})
    return jsonify({"code": 0, "message": "字典数据删除成功", "data": {}})


# 文件类型字典库修改
@api.route("/file/dict/modify", methods=["POST"])
def file_dict_modify():
    data = request.get_json()
    if data.get("id") is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    id = data.get("id")
    file_type = data.get("fileType")
    file_type_cn = data.get("fileTypeCN")
    description = data.get("description")
    file_type_dict = FileTypeDict.query.filter_by(id=id).first()
    if file_type_dict is None:
        return jsonify({"code": 1, "message": "字典数据不存在", "data": {}})
    if file_type is not None and file_type != "":
        if not data.get("fileType").isalpha():
            return jsonify({"code": 1, "message": "File type must be alphabet", "data": {}})
        file_type_dict.file_type = file_type
    if file_type_cn is not None and file_type_cn != "":
        file_type_dict.file_type_cn = file_type_cn
    if description is not None and description != "":
        file_type_dict.description = description

    file_obj = FileTypeDict.query.filter_by(file_type=file_type).first()
    if file_obj:
        return jsonify({"code": 1, "message": "字典数据修改失败：文件类型已经存在", "data": {}})

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"code": 1, "message": "字典数据修改失败：" + str(e), "data": {}})
    return jsonify({"code": 0, "message": "字典数据修改成功", "data": {}})


# 测试
@api.route("/test", methods=["GET"])
def test():
    args = request.args
    ## 部署1 ###
    # data = {
    #     "deploy_type":1,
    #     "id":1,
    #     "user":"api",
    #     "hostname":"honeyterm12345",
    #     "path":"/home/download",
    #     "ope_sys":"linux",
    #     "host_id":9,
    #     "status":1
    # }

    # url = "http://localhost:5001/file/deploy"
    # response = requests.post(url, json=data)

    ### 添加部署2 ###
    # data = {
    #     "deploy_type":args.get("deploy_type"),
    #     "file_id":args.get("honeypoint_id"),
    #     "user":"admin",
    #     "mechine_name":args.get("mechine_name"),
    #     "path":args.get("path"),
    #     "sys":args.get("ope_sys"),
    #     "ip":args.get("host_ip"), # host_ip
    #     "network":args.get("network"),
    # }
    # url = "http://localhost:5001/file/deploy"
    # response = requests.post(url, json=data)
    # print(response)
    # if response.status_code != 200:
    #     return jsonify({"code": 1, "message": "Error", "data": ""})

    ### 文件告警测试 ###
    # err,info = kafka_test()

    # err, info = kafka_test()
    # if err:
    #     return jsonify({"code": 1, "message": str(info), "data": ""})
    return jsonify({"code": 0, "message": "Success", "data": ""})


# 定时任务：拉取邮件并分析
# @scheduler.task("interval", id="task_1", minutes=Server_config.pull_Mailcircle, misfire_grace_time=900)
@scheduler.task("interval", id="task_1", seconds=Server_config.pull_Mailcircle_seconds, misfire_grace_time=900)
def task_pull_email():
    # current_app.logger.info("======== TASK 1 EMAIL ALERT =========")
    new_query_time = get_time_bj()
    with scheduler.app.app_context():
        # print("task_pull_email")
        accounts = Honeyemail.query.all()
        # current_app.logger.info(f"Accounts: {len(accounts)}")
        if accounts is None or len(accounts) == 0:
            # current_app.logger.info("No email account")
            # current_app.logger.info("======== TASK 1 FINISH =========")
            return
        for index, account in enumerate(accounts):
            if account.protocol == "pop3":
                error, receive_count = get_email_pop3(account.username, account.password, account.server)
            else:
                error, receive_count = get_email_imap(account.username, account.password, account.server)
            num = len(  # 获取账号文件夹中邮件数量
                os.listdir(
                    f'./email/{account.protocol}/{account.username.split("@")[0]}'
                )
            )
            account.email_count = num  # 更新数据库中邮件数量
            account.last_receive_count = receive_count  # 更新数据库中最近一次拉取的邮件数量
            current_app.logger.debug(f"[{index}] - {account.username}")
            current_app.logger.debug(f"last_receive_time:{account.last_receive_time}")
            current_app.logger.debug(f"last_receive_count:{receive_count}")
            if error != None:
                account.last_receive_state = error[2:-1]
            else:
                account.last_receive_state = "working"

            account.last_receive_time = new_query_time  # 更新数据库中最近一次拉取的时间
            if account.email_count > 0 and account.last_receive_count >= 0:
                for file in os.listdir(
                        f'./email/{account.protocol}/{account.username.split("@")[0]}'
                ):
                    path = os.path.join(
                        f'./email/{account.protocol}/{account.username.split("@")[0]}',
                        file,
                    )
                    pfish, sender, subject, time_str, header, parser_info = analyze_email(path)  # 解析邮件
                    # print(file)
                    email_id = int(file.split(".")[0].split("_")[1])
                    email_type = "pfish" if pfish else "spam"

                    # 解析邮件内容，获取接收时间
                    datetime_obj = get_time_bj(timestr_to_datetime(time_str)) 

                    emailInfo = EmailInfo.query.filter(
                        and_(
                            EmailInfo.username == account.username,
                            EmailInfo.email_id == email_id,
                        )
                    ).first()
                    if emailInfo is not None:  # 若数据库中已有该邮件
                        # print(emailInfo.email_id)
                        emailInfo.email_type = email_type
                        emailInfo.receive_time = datetime_obj
                        emailInfo.header = header
                    else:
                        emailInfo = EmailInfo(
                            server=account.server,
                            account_id=account.id,
                            username=account.username,
                            sender=sender,
                            subject=subject,
                            receive_time=datetime_obj,
                            email_type=email_type,
                            header=header,
                            email_id=email_id,
                        )
                        # print(emailInfo.email_id)
                        db.session.add(emailInfo)

                    db.session.add(emailInfo)
                    db.session.commit()
            db.session.add(account)
            db.session.commit()

        if accounts is not None or len(accounts) != 0:
            # 分析邮件
            # current_app.logger.info("Analyzing email")
            data = {
                'analyzeall': True
            }
            response = requests.post('http://localhost:5001/email/analyze', json=data)
            if response.status_code != 200:
                current_app.logger.error(f"Analyze email error:{response.status_code}")
                # current_app.logger.error(f"======== ERROR =========")
                return

            # 推送告警信息
            record = LastQueryTime.query.filter_by(query_type="email_alert").first()
            if Server_config.pull_Email_day != 0:  # 若配置文件中设置了拉取天数
                last_query_time = new_query_time - timedelta(days=Server_config.pull_Email_day)
            else:
                if record:
                    # current_app.logger.info("Get last query time record Successfly")
                    # last_query_time = record.query_time - timedelta(minutes=Server_config.pull_Mailcircle)    # 推送前10分钟的邮件信息
                    last_query_time = record.query_time
                else:
                    current_app.logger.info("No last query time record")
                    last_query_time = new_query_time - timedelta(days=7)  # 获取东八区时间

            # current_app.logger.info("Push email alert to kafka:")

        err, info = send_alert_email(last_query_time)  # 推送告警信息至kafka
        if err:
            current_app.logger.error(f"Push email alert error: {str(info)}")
            # current_app.logger.error(f"======== ERROR =========")
            return
        elif info != 0:
            current_app.logger.info(f"Push total: {info}")

        # 记录查询时间
        if record is None:
            record = LastQueryTime()
            record.query_type = "email_alert"
        record.query_time = new_query_time  # 记录查询时间
        try:
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Record query time ERROR:{str(e)}")
            current_app.logger.error(f"======== ERROR =========")
            return


# 定时任务：拉取推送文件告警
# @scheduler.task("interval", id="task_3", minutes=Server_config.pull_Filecircle, misfire_grace_time=900)
@scheduler.task("interval", id="task_3", seconds=Server_config.pull_Filecircle_seconds, misfire_grace_time=900)
def task_file_alert():
    new_pull_time = get_time_bj()
    new_push_time = new_pull_time
    with scheduler.app.app_context():
        ######### 拉取告警 ##########
        pull_record = LastQueryTime.query.filter_by(query_type="file_alert_pull").first()  # 读取上次查询时间
        if Server_config.pull_File_day != 0:  # 若配置文件中设置了拉取天数
            last_pull_time = new_pull_time - timedelta(days=Server_config.pull_File_day)
        else:
            if pull_record:
                last_pull_time = pull_record.query_time
                shanghai_tz = pytz.timezone('Asia/Shanghai')
                last_pull_time = shanghai_tz.localize(last_pull_time)   # 加上时区信息
            else:
                last_pull_time = new_pull_time - timedelta(days=7)  # 获取东八区时间
                
        get_err, get_res = get_file_alert(last_pull_time)  # MAIN:从alert_server拉取告警信息并存入数据库
        if get_err:
            current_app.logger.error(f"[File Alert]Pull error:{str(get_err)}")
            return
        
        # 记录查询时间
        if pull_record is None:
            pull_record = LastQueryTime()
            pull_record.query_type = "file_alert_pull"
        pull_record.query_time = new_pull_time  # 新告警拉取时间
        try:
            db.session.add(pull_record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[File Alert]Record query time ERROR:{str(e)}")
            return
        if get_err:
            current_app.logger.error(f"[File Alert]Get error: {str(get_res)}")
            return
        if get_res == 0:    # 没有新告警，无需进行推送
            return
        
        ######### 推送告警 ##########
        push_record = LastQueryTime.query.filter_by(query_type="file_alert_push").first()
        if Server_config.pull_File_day != 0:
            last_push_time = new_push_time - timedelta(Server_config.pull_File_day)
        elif push_record: # 获取上次推送时间
            last_push_time = push_record.query_time
            # shanghai_tz = pytz.timezone('Asia/Shanghai')
            # last_push_time = shanghai_tz.localize(last_pull_time)   # 加上时区信息
        else:
            last_push_time = new_push_time - timedelta(days=7)          # 未获取到上次推送时间，则设定为前7天
            
        send_err, send_res = send_alert_file(last_push_time=last_push_time)  # MAIN:推送告警信息
        
        if send_err > 0:  # 错误
            current_app.logger.error(f"[File Alert] 文件告警推送失败: {str(send_res)}")
            return
        if send_err==-1:    # 无新告警
            current_app.logger.error(f"[File Alert]未查询到对应部署信息")
        current_app.logger.info(f"[File Alert]Push Success, total: {send_res}")
        # 记录推送时间
        if push_record is None:
            push_record = LastQueryTime()
            push_record.query_type = "file_alert_push"
        push_record.query_time = new_push_time  # 新推送时间
        try:
            db.session.add(push_record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Record push time ERROR:{str(e)}")
            return


# 定时任务：Nacos心跳检测
@scheduler.task("interval", id="task_2", seconds=6, misfire_grace_time=900)
def task_service_beat():
    with scheduler.app.app_context():
        if Server_config.Env_mode == "debug" or Server_config.Nacos_addr =="":  # 如果为debug模式或者没配置nacos
            pass
        elif Server_config.Env_mode == "server":
            beatDict = {
                "cluster": "DEFAULT",
                "ip": Server_config.Local_addr,
                "metadata": {},
                "port": 5001,
                "scheduled": True,
                "serviceName": "systemwire",
                "weight": 1,
            }

            url = Server_config.Nacos_addr + "/nacos/v1/ns/instance/beat"
            params = {
                "serviceName": "systemwire",
                "ip": Server_config.Local_addr,
                "port": 5001,
                "beat": json.dumps(beatDict),
            }
            # 正式环境时发送心跳包，本地测试环境不发送心跳包
            try:
                res = requests.put(url, params=params, timeout=2)
                if res.status_code != 200:
                    current_app.logger.error(f"心跳包发送失败: {res.text}")
                    return
                current_app.logger.debug(f"心跳包发送成功,res:{res.text}")
            except urllib3.exceptions.MaxRetryError as e:
                current_app.logger.error(f"心跳包发送失败: 请求超时")
                return
            except Exception as e:
                current_app.logger.error(f"心跳包发送失败: {str(e)}")
                return


def service_register():
    params = {
        "ip": Server_config.Local_addr,
        "port": 5001,
        "weight": 1,
        "enable": True,
        "healthy": True,
        "ephemeral": True,
        "serviceName": "systemwire",
        "groupName": "DEFAULT_GROUP",
        "clusterName": "DEFAULT",
        "namespaceId": "public",
        "protectThreshold": "0.0",
    }
    url = Server_config.Nacos_addr + "/nacos/v1/ns/instance"
    if Server_config.Env_mode == "server":
        try:
            registerInstance_response = requests.post(url, params=params)
            if registerInstance_response.status_code != 200:
                # print("register failed")
                # print(registerInstance_response.text)
                current_app.logger.error(f"[Nacox]心跳包发送失败: status code={registerInstance_response.status_code}")   
                return
        except urllib3.exceptions.MaxRetryError as e:
            current_app.logger.error(f"[Nacox]心跳包发送失败: 请求超时")
            return
        except Exception as e:
            current_app.logger.error(f"[Nacox]心跳包发送失败: {str(e)}")
            return
        


################# Agent ################# 
# 创建agent
@api.route("/agent/create", methods=["POST"])
def agent_create():
    data = request.get_json()
    client_name = data.get('clientName')    # agent 的名字
    arch = data.get('arch','')              # 架构，如Linux-amd-64
    ope_sys = data.get('opeSys','unknown')  # 操作系统类型
    ip = data.get('ip','')             # 客户端ip，限制指定的ip登录对应的token
    
    agent = ClientInfo()
    agent.client_id = generate_random_str(8)
    agent.ip = ip
    agent.hostname = ''
    agent.token = generate_random_str(24)   # 生成随机tokne
    agent.arch = arch
    agent.ope_sys = ope_sys
    agent.client_name = client_name
    agent.registered = False
    agent.status = 'offline'
    agent.register_time = datetime.min      # 默认设置为0时间 0001-01-01 00:00:00
    agent.last_beat_time = datetime.min     # 默认设置为0时间 0001-01-01 00:00:00
    
    try:
        db.session.add(agent)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("创建Agent失败："+ str(e))
        return jsonify({"code": 1, "message": "Agent创建失败: " + str(e), "data": {}})
    
    # 将agent加入agent_list
    grpc_server = get_grpc_server()
    agent_json = agent.to_json()
    new_agent = Agent(agent_json)
    grpc_server.agent_list[agent_json["client_id"]] = new_agent                        # 初始化 client_id-agent 映射
    grpc_server._secret_to_id[agent_json["token"]] = agent_json["client_id"]        # 初始化 token->client_id 映射
    
    return jsonify({"code": 0, "message": "success", "data": {"shell":"curl http://x.x.x.x/agent/download/"+ agent.client_id}})
# 下载agent
@api.route("/agent/download",methods=['GET'])
def agent_download():
    # TODO:根据id下载
    return send_file('../agent-server/agents/hyclient')
# 获取Agent状态(心跳)
# @api.route("/agent/beat", methods=["GET"])
# def agent_beat():
#     # 获取query参数
#     client_id = request.args.get("client_id")
#     hostname = request.args.get("hostname")
#     ope_sys = request.args.get("ope_sys")
#     status = request.args.get("status")
#     ip = request.remote_addr.split(":")[-1]
#     beat_time = datetime.now()
    
#     # hostinfo_url = "http://172.172.105.50:5050/hostsinfo/allinfo"   # 获取主机信息接口
#     # try:
#     #     response = requests.get(hostinfo_url)
#     #     if response.status_code == 200:
#     #         hostinfo = response.json().get("data")
#     #         if len(hostinfo) != 0:
#     #             host_id = hostinfo[0].get("id")
#     #         else:
#     #             host_id = 0 # 无该ip对应的主机信息
#     #     else:
#     #         current_app.logger.error(f"Hostinfo server error: {str(e)}")
#     #         host_id = 0
            
#     # except Exception as e:
#     #     current_app.logger.error(f"Get host info error: {str(e)}")
#     #     host_id = 0
#     if not client_id or client_id=='':
#         return jsonify({"code": 1, "message": "fail", "data": {}})
#     client = ClientInfo.query.filter_by(client_id=client_id).first()    # 查询表中是否已经存在该客户端
#     if client is None:
#         client = ClientInfo(client_id=client_id,ip=ip,hostname=hostname,ope_sys=ope_sys,status=status,last_beat_time=beat_time,register_time=beat_time)
#         db.session.add(client)
#         current_app.logger.info(f"[Agent]新客户端: \tIP:{ip} \tHostname:{hostname} \tSystem:{ope_sys}")
#     else:
#         if client.status == "offline":  # 若客户端之前是离线状态
#             current_app.logger.info(f"[Agent]上线: \tIP:{ip} \tHostname:{hostname} \tSystem:{ope_sys}")
#         elif status == "offline":   # 若客户端现在是离线状态
#             current_app.logger.info(f"[Agent]下线: \tIP:{ip} \tHostname:{hostname} \tSystem:{ope_sys}")
#         client.hostname = hostname
#         client.ope_sys = ope_sys
#         client.status = status
#         client.last_beat_time = beat_time
#     try:
#         db.session.commit()
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"code": 1, "message": "客户端状态更新失败: " + str(e), "data": {}})
    
#     # 读取命令
#     if client_id in commands_queue and len(commands_queue.get(client_id))>0:   # 有该客户端的命令队列&队列长度>0
#         command_objs = []
#         count = len(commands_queue.get(client_id))
#         for index in range(count):
#             command_objs.append(commands_queue.get(client_id).pop())
#         response_data = {
#             'count' : count,
#             'commands' : command_objs
#         }
#         response_json = json.dumps(response_data)
#         crypto_key = generate_key(client_id,hostname)
#         err,res = encrypt_data(response_json,crypto_key)
#         if err:
#             current_app.logger.error("[Agent]客户端读取命令失败,"+res)
#             return jsonify({"code": 2, "message": "command error", "data": {}})
#         response_json_encode = res
#     else:
#         response_json_encode = ""
#     return jsonify({"code": 0, "message": "Success", "data": response_json_encode})

# 查询Agent Client信息
@api.route("/agent/search", methods=["GET"])
def agent_search():     
    page_num = request.args.get("page_num")
    page_size = request.args.get("page_size")
    if page_num == None or page_size == None:
        page_num = 1
        page_size = 10
    
    query = ClientInfo.query
    if request.args.get("id"):
        query = query.filter_by(id=id)
    if request.args.get("hostname"):
        query = query.filter(ClientInfo.hostname.like("%" + request.args.get("hostname") + "%"))
    if request.args.get("status"):
        query = query.filter_by(status=request.args.get("status"))
    if request.args.get("ope_sys"):
        query = query.filter(ClientInfo.ope_sys.like("%" + request.args.get("ope_sys") + "%"))
    if request.args.get("src_ip"):
        query = query.filter(ClientInfo.ip.like("%" + request.args.get("src_ip") + "%"))
    total = query.count()
    clients = query.paginate(page=int(page_num), per_page=int(page_size), error_out=False)
    infos = []
    for each in clients:
        info = each.to_json()
        infos.append(info)
    return jsonify({"code": 0, "message": "Success", "data": {"items":infos, "count": total}})



# 获取Agent上报的告警信息
@api.route("/agent/report", methods=["POST"])
def agent_report():
    req_data = request.json
    data_encoded = req_data.get('data')
    # client_id = req_data.get('client_id')
    current_app.logger.info(f"[Encrypt]加密:{data_encoded}")
    # current_app.logger.info(f"client_id:{client_id}")
    ip = request.remote_addr.split(":")[-1]
    # if not client_id or client_id == '':
    #     return  jsonify({"code": 1, "message": "inc", "data": {}})
    client = ClientInfo.query.filter_by(ip=ip).first()
    if client:
        crypto_key = generate_key(client.client_id,client.hostname)    # 生成对称密钥
        res,data_decoded_str = decrypt_data(data_encoded,crypto_key)    # 解密数据
        if res:
            current_app.logger.error(f"[Decrypt] 解密出错:{data_decoded_str}")
            return jsonify({"code": 1, "message": f"decode error:{data_decoded_str} ", "data": {}})
        data_decoded = json.loads(data_decoded_str)
    else:   # 未找到ip对应的client信息
        return jsonify({"code": 1, "message": "noc", "data": {}})
    ip = request.remote_addr.split(":")[-1]
    # hostname = data.get('hostname') # 主机名
    hostname = client.hostname
    count = data_decoded.get('count')       # 告警数量
    alert_info = data_decoded.get('data')   # 告警信息

    # client = ClientInfo.query.filter_by(client_id=client_id).first()
    current_app.logger.info(f"[Agent]告警上报:IP:{ip} | 主机名:{hostname}")
    # current_app.logger.info(f"[test]\n{alert_info}")
    
    record_objects = []
    for item in alert_info:
        # current_app.logger.info(f"[test]item:\n{item}")
        trigger_time = item.get('time')  # 触发时间
        current_app.logger.info(trigger_time)
        trigger_time_obj = datetime.strptime(trigger_time, "%Y-%m-%d %H:%M:%S")
        record_objects.append(MonitorAlert(
            hostname=hostname,      # 主机名
            client_id=client.client_id,    # 客户端id
            trigger_time=trigger_time_obj,  # 时间
            proctitle=item.get('PROCTITLE'),  # 进程信息
            cwd=item.get('CWD'),            # 当前工作目录
            syscall=item.get('SYSCALL'),    # 系统信息
            path=item.get('PATH')   # 文件路径
        ))
    try:
        db.session.bulk_save_objects(record_objects)   # 批量插入记录
        db.session.commit()
        current_app.logger.info("记录Agent告警信息成功")
    except Exception as e:
        session.rollback()
        return jsonify({"code": 1, "message": "告警信息插入失败: " + str(e), "data": {}})
    
    return jsonify({"code": 0, "message": "Success", "data": ""})

# 发布命令
@api.route("/agent/command", methods=["POST"])
def agent_command():
    data = request.json
    client_id = data.get("client_id")           # 目标agent
    command = data.get("command_type", '')       # 命令类型
    command_details = data.get("command_data")  # 命令细节（可能是 dict，也可能是 JSON 字符串）

    if not client_id or not command or command_details is None:
        return jsonify({"code": 1, "message": "Incomplete parameters", "data": {}})

    grpc_server = get_grpc_server()
    client = grpc_server.agent_list.get(client_id, None)  # 找到对应agent
    if client is None:
        return jsonify({"code": 1, "message": "Client id not exist", "data": {}})

    queue = grpc_server.commond_queue.get(client_id)  # 找到agent的命令队列
    if queue is None:
        current_app.logger.info(f"[Agent] 命令发布失败 ID:{client_id} 离线或不存在")
        return jsonify({"code": 1, "message": f"[Agent] 命令发布失败 ID:{client_id} 离线或不存在", "data": {}})

    # 定义命令类型
    command_type = {
        "heart_beat": 1,    # 心跳
        "add_dirs": 2,      # 添加路径
        "del_dirs": 3,      # 删除路径
        "add_account": 4,   # 添加账户蜜点
        "send_file": 5      # 下发文件
    }

    cmd_id = generate_uint64_id()                                           # 生成命令id
    cmd_type = command_type.get(command, 0)                                  # 将命令类型转换成对应的类型id

    current_app.logger.info(f"[DEBUG] command={command}, cmd_type={cmd_type}, client_id={client_id}")

    # 若 command_data 是字符串（前端可能传 JSON-string），则尝试解析
    details = command_details
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            # 仍然保留原始字符串（某些命令可能就是 string），但对于 send_file 我们需要 dict
            if command == "send_file":
                return jsonify({"code": 1, "message": "send_file 参数解析失败: command_data 非 JSON 格式", "data": {}})
            # 否则把字符串当作普通 payload
            details = command_details

    # send_file 需要特别处理：前端约定传入 {"file_id": "...", "remote_path": "..."}
    if command == "send_file":
        try:
            file_id = details.get("file_id")
            remote_path = details.get("remote_path")
        except Exception:
            return jsonify({"code": 1, "message": "send_file 参数格式错误", "data": {}})

        if not file_id or not remote_path:
            return jsonify({"code": 1, "message": "send_file 参数缺失 file_id 或 remote_path", "data": {}})

        # 查找 Honeyfile
        file_obj = Honeyfile.query.filter_by(id=file_id).first()
        if not file_obj:
            return jsonify({"code": 1, "message": f"文件不存在: {file_id}", "data": {}})

        # 尝试读取部署记录（如果存在则可以用部署记录的 path）
        deploy_obj = Filedeploy.query.filter_by(honeypoint_id=file_obj.id).first()

        # 如果部署记录存在并且有 path，就把 deploy.path 加入 payload（兼容历史逻辑）
        server_file_path = None
        if deploy_obj and getattr(deploy_obj, "path", None):
            server_file_path = deploy_obj.path

        # 同时构造一个可供 agent 通过 HTTP 下载的 URL（更可靠）
        # 使用本地地址而不是公网地址，让Agent可以直接从管理端下载文件
        filename = None  # 初始化filename变量
        try:
            # 获取本地服务器地址
            local_address = request.host_url.rstrip('/')
            # 修改为使用无需认证的Agent专用文件下载端点
            download_url = f"{local_address}/api/agent/file/download/{file_obj.id}"
            # 获取文件名
            file_info = file_obj.to_json()
            filename = file_info.get("filename", None)
            # 确保filename不为None
            if filename is None:
                # 如果to_json没有返回filename，尝试从name字段构造
                if hasattr(file_obj, 'name'):
                    # 从name字段提取文件名（去掉扩展名部分）
                    name_parts = file_obj.name.rsplit('.', 1)
                    if len(name_parts) > 1:
                        # 去掉随机标签部分
                        name_without_tag = name_parts[0].rsplit('-', 1)[0]
                        filename = f"{name_without_tag}.{file_obj.doc_format}"
                    else:
                        filename = file_obj.name
        except Exception as e:
            current_app.logger.error(f"[Agent] 构造下载URL时出错: {e}")
            download_url = None
            # 即使出错也尝试获取文件名
            try:
                file_info = file_obj.to_json()
                filename = file_info.get("filename", None)
            except:
                filename = None

        # 最终发给 agent 的 payload（JSON 字符串）
        cmd_payload_dict = {
            "file_id": file_obj.id,
            "filename": filename,  # 添加文件名
            "remote_path": remote_path,
            "download_url": download_url,
        }
        # 如果有 server_file_path（部署记录），也带上以兼容其他实现
        if server_file_path:
            cmd_payload_dict["server_path"] = server_file_path

        # 使用 ensure_ascii=False 来避免中文被编码为 Unicode
        cmd_payload = json.dumps(cmd_payload_dict, ensure_ascii=False)
    else:
        # 普通命令直接使用 details（如果是 dict，序列化为字符串）
        if isinstance(details, (dict, list)):
            cmd_payload = json.dumps(details)
        else:
            cmd_payload = str(details)

    # 生成 grpc 命令
    cmd_message = pb2.Cmd(id=cmd_id, type=cmd_type, data=cmd_payload)

    try:
        # 记录命令到数据库
        agnet_control_record = AgentControlLog()
        agnet_control_record.client_id = client_id
        agnet_control_record.operate_type = command
        agnet_control_record.operate_id = cmd_id
        agnet_control_record.detail = cmd_payload

        db.session.add(agnet_control_record)
        db.session.commit()

        # 将命令加入队列，grpc server 会定时从队列中读取命令并发送给 agent
        queue.put(cmd_message)
        current_app.logger.info(f"[Agent] 命令发布成功 ID:{client_id} TYPE:{cmd_type} DATA:{cmd_payload}")

        return jsonify({"code": 0, "message": "命令发布成功", "data": {}})
    except Exception as e:
        db.session.rollback()
        current_app.logger.info(f"[Agent] 命令发布失败:{e}")
        return jsonify({"code": 1, "message": "命令发布失败: " + str(e), "data": {}})





# 检查Agent状态
# @scheduler.task("interval", id="task_4", seconds=60, misfire_grace_time=900)
def tast_check_client_status():
    online_count = 0    # 在线客户端数量
    offline_count = 0   # 离线客户端数量
    with scheduler.app.app_context():
        now = datetime.now()
        all_clients = ClientInfo.query.all()
        total = len(all_clients)
        running_client = ClientInfo.query.filter_by(status='online').all()
        shutdown_clients = []
        for client in running_client:
            if now - client.last_beat_time > timedelta(minutes=1):  # 超过1分钟未收到心跳
                client.status = 'offline'
                offline_count += 1
                shutdown_clients.append(client)
                continue
            online_count += 1
        for client in shutdown_clients: # 客户端下线播报
            current_app.logger.info(f"[Agent]下线: IP:{client.ip} \tHostname:{client.hostname} \tOperate System:{client.ope_sys}")
        current_app.logger.info(f"[Agent]状态更新: 总数{total} \t在线{online_count} \t离线{total-online_count} ")  # 客户端状态更新播报
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[Agent]状态更新失败: \n{str(e)}")
            return
        
################# parasitic #################

# 获取寄生蜜点上报的信息
def _jsonify_with_cors(payload, status=200):
    response = make_response(jsonify(payload), status)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@api.route("/url/report", methods=["POST", "OPTIONS"])
# @cross_origin()
def url_report():
    if request.method == "OPTIONS":
        return _jsonify_with_cors({"code": 0, "message": "ok", "data": {}})

    current_app.logger.warning("Deprecated parasitic direct report received from %s", request.remote_addr)
    return _jsonify_with_cors({
        "code": 1,
        "message": "deprecated: parasitic alerts must go to js/bot first and then be pulled into systemwire2",
        "data": {},
    }, status=410)


@api.route("/parasitism/alert", methods=["GET"])
def parasitic_alert_pull():
    force_days = request.args.get("days", default=0, type=int)
    record = LastQueryTime.query.filter_by(query_type="parasitic_alert_pull").first()
    if force_days and force_days > 0:
        last_query_time = get_time_bj() - timedelta(days=min(force_days, 30))
    elif record:
        last_query_time = record.query_time
    else:
        last_query_time = get_time_bj() - timedelta(days=7)

    try:
        err, pull_count = get_parasitic_alert(last_query_time)
    except Exception as e:
        current_app.logger.error("Get parasitic alert exception: %s", e)
        return jsonify({"code": 1, "message": f"Get parasitic alert error: {e}", "data": []})
    if err:
        return jsonify({"code": 1, "message": f"Get parasitic alert error: {pull_count}", "data": []})

    if record is None:
        record = LastQueryTime()
        record.query_type = "parasitic_alert_pull"
    record.query_time = get_time_bj()
    try:
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Record parasitic query time ERROR:%s", e)
        return jsonify({"code": 1, "message": f"Record query time ERROR:{e}", "data": []})

    return jsonify({
        "code": 0,
        "message": "Success",
        "data": {
            "pulled": pull_count,
            "last_query_time": last_query_time.isoformat() if last_query_time else None,
            "query_time": record.query_time.isoformat() if record.query_time else None,
            "source": "js/bot -> systemwire2",
        },
    })


@scheduler.task("interval", id="task_5", seconds=Server_config.pull_Parasiticcircle_seconds, misfire_grace_time=900)
def task_parasitic_alert():
    new_pull_time = get_time_bj()
    with scheduler.app.app_context():
        record = LastQueryTime.query.filter_by(query_type="parasitic_alert_pull").first()
        last_query_time = record.query_time if record else (new_pull_time - timedelta(days=7))
        try:
            err, pull_count = get_parasitic_alert(last_query_time)
        except Exception as e:
            current_app.logger.error("[Parasitic Alert] pull exception: %s", e)
            return
        if err:
            current_app.logger.error("[Parasitic Alert] pull error: %s", pull_count)
            return
        if record is None:
            record = LastQueryTime()
            record.query_type = "parasitic_alert_pull"
        record.query_time = new_pull_time
        try:
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("[Parasitic Alert] record query time error: %s", e)
            return
        if pull_count:
            current_app.logger.info("[Parasitic Alert] pulled %s official rows", pull_count)


# ───────────────────── 账户蜜点拉取（从 alert_server） ─────────────────────

def get_account_alert(last_query_time, page_size=100):
    """从 alert_server 拉取账户蜜点告警"""
    inserted = 0
    base_url = str(getattr(Server_config, "file_alert_server_address", "") or "").strip()
    base_url = base_url.rstrip("/")
    if not base_url:
        current_app.logger.warning("[Account Alert] alert_server 未配置")
        return 1, "alert_server not configured"

    api_url = f"{base_url}/api/account-alerts"
    # 确保 last_query_time 是 offset-naive 用于 API 请求
    if last_query_time and last_query_time.tzinfo is not None:
        last_query_time = last_query_time.replace(tzinfo=None)
    since_param = last_query_time.strftime("%Y-%m-%dT%H:%M:%S") if last_query_time else ""

    req_err, resp = _alert_server_request(
        "account alert pull",
        "GET",
        api_url,
        params={"page": 1, "size": page_size, "since": since_param},
        timeout=15,
    )
    if req_err:
        return 1, str(resp)

    try:
        if resp.status_code != 200:
            return 1, f"account alerts status={resp.status_code}"

        payload = resp.json()
        rows = payload.get("data") or []
        if not rows:
            return 0, 0

        bj_tz = pytz.timezone("Asia/Shanghai")

        for item in rows:
            trigger_time_str = item.get("trigger_time", "")
            trigger_time = datetime.now(bj_tz)
            if trigger_time_str:
                try:
                    from dateutil.parser import parse
                    trigger_time = parse(trigger_time_str)
                    if trigger_time.tzinfo is None:
                        trigger_time = bj_tz.localize(trigger_time)
                except:
                    pass

            # 转换为 offset-naive 比较（last_query_time 已经是 offset-naive）
            trigger_naive = trigger_time.replace(tzinfo=None) if trigger_time.tzinfo is not None else trigger_time
            if last_query_time and trigger_naive <= last_query_time:
                continue

            # 去重：检查是否已存在相同 src_ip 和 trigger_time 的记录
            dup = AccountAlertInfo.query.filter(
                AccountAlertInfo.src_ip == item.get("src_ip", ""),
                AccountAlertInfo.trigger_time == trigger_time,
            ).first()
            if dup:
                current_app.logger.debug("[Account Alert] 跳过重复: %s @ %s", item.get("src_ip"), trigger_time_str)
                continue

            record = AccountAlertInfo(
                trigger_time=trigger_time,
                report_time=datetime.now(bj_tz),
                src_ip=item.get("src_ip", ""),
                src_port=item.get("src_port", ""),
                dst_ip=item.get("dst_ip", ""),
                dst_port=item.get("dst_port", ""),
                username=item.get("username", ""),
                password=item.get("password", ""),
                client_version=item.get("client_version", ""),
                protocol=item.get("protocol", "ssh"),
                message=item.get("message", ""),
                raw_event=item,
            )
            db.session.add(record)
            db.session.flush()
            ingest_account_alert(
                source_service="alert_server",
                source_event_id=f"pull-account-{record.id}",
                trigger_time=record.trigger_time,
                src_ip=record.src_ip or "",
                src_port=record.src_port or "",
                dst_ip=record.dst_ip or "",
                dst_port=record.dst_port or "",
                username=record.username or "",
                password=record.password or "",
                client_version=record.client_version or "",
                protocol=record.protocol or "ssh",
                message=record.message or "",
                raw_payload=item,
                legacy_row_id=record.id,
            )
            inserted += 1

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return 1, f"insert account alert error: {e}"

        current_app.logger.info("[Account Alert] pulled %s rows since %s", inserted, since_param or "-")
        return 0, inserted
    except Exception as e:
        current_app.logger.error("[Account Alert] pull exception: %s", e)
        return 1, str(e)


def _extract_account_alert_fields(raw_data):
    payload = dict(raw_data or {})
    src_ip = str(payload.get("src_ip") or payload.get("src") or "").strip()
    src_port = str(payload.get("src_port") or payload.get("spt") or "").strip()
    dst_ip = str(payload.get("dst_ip") or payload.get("dst") or "").strip()
    dst_port = str(payload.get("dst_port") or payload.get("dpt") or "").strip()
    username = str(payload.get("username") or payload.get("duser") or "").strip()
    password = str(payload.get("password") or "").strip()
    client_version = str(payload.get("client_version") or "").strip()
    message = str(payload.get("message") or payload.get("msg") or "").strip()
    protocol = str(payload.get("protocol") or "ssh").strip().lower() or "ssh"
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "username": username,
        "password": password,
        "client_version": client_version,
        "message": message,
        "protocol": protocol,
        "raw_event": payload,
    }


def _parse_account_trigger_time(raw_data):
    payload = raw_data or {}
    bj_tz = pytz.timezone("Asia/Shanghai")
    trigger_time = datetime.now(bj_tz)
    value = payload.get("trigger_time", payload.get("time"))
    if value in (None, ""):
        return trigger_time
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=bj_tz)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return trigger_time
            parsed = parse(text)
            if parsed.tzinfo is None:
                parsed = bj_tz.localize(parsed)
            else:
                parsed = parsed.astimezone(bj_tz)
            return parsed
    except Exception:
        return trigger_time
    return trigger_time


def _ingest_account_alert_record(fields, trigger_time, *, source_service, source_event_id, report_time=None):
    trigger_time = trigger_time if trigger_time.tzinfo is not None else pytz.timezone("Asia/Shanghai").localize(trigger_time)
    report_time = report_time or datetime.now(pytz.timezone("Asia/Shanghai"))
    dup = AccountAlertInfo.query.filter(
        AccountAlertInfo.src_ip == fields.get("src_ip", ""),
        AccountAlertInfo.trigger_time == trigger_time,
        AccountAlertInfo.username == fields.get("username", ""),
        AccountAlertInfo.protocol == fields.get("protocol", "ssh"),
        AccountAlertInfo.message == fields.get("message", ""),
    ).first()
    if dup:
        return dup, False

    record = AccountAlertInfo(
        trigger_time=trigger_time,
        report_time=report_time,
        src_ip=fields.get("src_ip", ""),
        src_port=fields.get("src_port", ""),
        dst_ip=fields.get("dst_ip", ""),
        dst_port=fields.get("dst_port", ""),
        username=fields.get("username", ""),
        password=fields.get("password", ""),
        client_version=fields.get("client_version", ""),
        protocol=fields.get("protocol", "ssh"),
        message=fields.get("message", ""),
        raw_event=fields.get("raw_event"),
    )
    db.session.add(record)
    db.session.flush()
    ingest_account_alert(
        source_service=source_service,
        source_event_id=source_event_id.format(id=record.id),
        trigger_time=record.trigger_time,
        src_ip=record.src_ip or "",
        src_port=record.src_port or "",
        dst_ip=record.dst_ip or "",
        dst_port=record.dst_port or "",
        username=record.username or "",
        password=record.password or "",
        client_version=record.client_version or "",
        protocol=record.protocol or "ssh",
        message=record.message or "",
        raw_payload=fields.get("raw_event"),
        legacy_row_id=record.id,
    )
    return record, True


@api.route("/account/alert", methods=["POST"])
def account_alert_receive():
    """兼容旧链路的账户蜜点直连接收入口。"""
    raw_data = request.get_json(silent=True)
    if not isinstance(raw_data, dict):
        return jsonify({"code": 1, "message": "Invalid JSON payload", "data": {}}), 400

    fields = _extract_account_alert_fields(raw_data)
    trigger_time = _parse_account_trigger_time(raw_data)

    try:
        record, created = _ingest_account_alert_record(
            fields,
            trigger_time,
            source_service="systemwire2_direct_account",
            source_event_id="direct-account-{id}",
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("[Account Alert] direct ingest error: %s", e)
        return jsonify({"code": 1, "message": f"Insert account alert error: {e}", "data": {}}), 500

    return jsonify({
        "code": 0,
        "message": "Success",
        "data": {
            "id": record.id,
            "created": created,
            "source": "direct -> systemwire2",
        },
    })


@api.route("/account/alert/pull", methods=["GET"])
def account_alert_pull():
    """手动触发拉取账户蜜点告警"""
    force_days = request.args.get("days", default=0, type=int)
    record = LastQueryTime.query.filter_by(query_type="account_alert_pull").first()
    if force_days and force_days > 0:
        last_query_time = get_time_bj() - timedelta(days=min(force_days, 30))
    elif record:
        last_query_time = record.query_time
    else:
        last_query_time = get_time_bj() - timedelta(days=7)

    try:
        err, pull_count = get_account_alert(last_query_time)
    except Exception as e:
        current_app.logger.error("Get account alert exception: %s", e)
        return jsonify({"code": 1, "message": f"Get account alert error: {e}", "data": []})
    if err:
        return jsonify({"code": 1, "message": f"Get account alert error: {pull_count}", "data": []})

    if record is None:
        record = LastQueryTime()
        record.query_type = "account_alert_pull"
    record.query_time = get_time_bj()
    try:
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Record account query time ERROR:%s", e)
        return jsonify({"code": 1, "message": f"Record query time ERROR:{e}", "data": []})

    return jsonify({
        "code": 0,
        "message": "Success",
        "data": {
            "pulled": pull_count,
            "last_query_time": last_query_time.isoformat() if last_query_time else None,
            "source": "alert_server -> systemwire2",
        },
    })


@scheduler.task("interval", id="task_account_alert", seconds=60, misfire_grace_time=900)
def task_account_alert():
    """定时任务：从 alert_server 拉取账户蜜点告警"""
    try:
        new_pull_time = get_time_bj()
        with scheduler.app.app_context():
            record = LastQueryTime.query.filter_by(query_type="account_alert_pull").first()
            last_query_time = record.query_time if record else (new_pull_time - timedelta(days=7))
            err, pull_count = get_account_alert(last_query_time)
            if err:
                current_app.logger.error("[Account Alert] pull error: %s", pull_count)
                return
            if record is None:
                record = LastQueryTime()
                record.query_type = "account_alert_pull"
            record.query_time = new_pull_time
            try:
                db.session.add(record)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                current_app.logger.error("[Account Alert] record query time error: %s", e)
                return
            if pull_count:
                current_app.logger.info("[Account Alert] pulled %s rows", pull_count)
    except Exception as e:
        current_app.logger.error("[Account Alert] task exception: %s", e)


def _build_local_parasitism_payload(page, size, target_filter=""):
    return build_parasitic_logs_payload(page, size, target_filter)


def _build_local_target_analysis(target):
    return build_parasitic_target_analysis(target)


# def get_logs_api():
#     try:
#         # 1. 获取分页参数
#         page = request.args.get("page", 1, type=int)
#         size = request.args.get("size", 10, type=int)
        
#         # 2. 分页参数修正
#         if page < 1: page = 1
#         if size < 1 or size > 100: size = 10
        
#         # 3. === 核心修改：直接获取数据库中的第一个服务器 ===
#         server = Server.query.first()
        
#         # 4. 判空：如果数据库是空的，报错
#         if not server:
#             return jsonify({
#                 "code": 1,
#                 "message": "数据库中没有配置任何服务器"
#             }), 404
        
#         # 5. 后续逻辑不变：构建 URL 并请求 Go 后端
#         backend_url = f"http://{server.ip_address}:8080/api/logs"
        
#         params = {
#             "page": page,
#             "size": size
#         }
        
#         headers = {
#             "Authorization": f"Bearer {Server_config.api_key}",
#             "Content-Type": "application/json"
#         }
        
#         # 设置超时
#         response = requests.get(backend_url, params=params, headers=headers, timeout=30)
        
#         if response.status_code != 200:
#             return jsonify({
#                 "code": 1,
#                 "message": f"后端服务错误: {response.status_code}"
#             }), 500
        
#         # 直接返回 Go 后端的响应
#         return jsonify(response.json())
        
#     except Exception as e:
#         return jsonify({
#             "code": 1,
#             "message": f"系统错误: {str(e)}"
#         }), 500

@api.route("/api/parasitism/logs")
def get_logs_api():
    try:
        page = request.args.get("page", 1, type=int)
        size = request.args.get("size", 10, type=int)
        target_filter = request.args.get("target", "")

        if page < 1:
            page = 1
        if size < 1 or size > 100:
            size = 10

        return jsonify(_build_local_parasitism_payload(page, size, target_filter))
    except Exception as e:
        return jsonify({
            "code": 1,
            "message": f"????: {str(e)}"
        }), 500


@api.route("/api/parasitism/servers")
def get_servers_list():
    """从数据库获取可用的服务器列表"""
    try:
        # 从数据库查询服务器列表
        servers_query = Server.query.all()
        
        # 如果没有数据，返回空列表
        if not servers_query:
            return jsonify({
                "code": 0,
                "message": "success",
                "data": []
            })
        
        # value和name都使用company_name
        servers = [
            {
                "value": server.company_name,  # value使用公司名
                "name": server.company_name   # name也使用公司名
            }
            for server in servers_query
        ]
        
        return jsonify({
            "code": 0,
            "message": "success",
            "data": servers
        })
        
    except Exception as e:
        return jsonify({
            "code": 1,
            "message": f"获取服务器列表失败: {str(e)}",
            "data": []
        }), 500
    


@api.route("/api/parasitism/target-analysis")
def get_target_analysis_api():
    try:
        target = request.args.get("target", "")
        if not target:
            return jsonify({
                "code": 1,
                "message": "?? target ??"
            }), 400

        return jsonify(_build_local_target_analysis(target))
    except Exception as e:
        return jsonify({
            "code": 1,
            "message": f"????: {str(e)}"
        }), 500
