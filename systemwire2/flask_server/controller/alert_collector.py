"""
Unified alert collector for the management portal.

The alert center reads three honeypot sources:
- file honeypot: FileAlertInfo, normally pulled from alert_server
- account honeypot: AccountAlertInfo, posted by ssh-vpn
- parasitic honeypot: UrlAlertInfo, pulled by systemwire2 from js/bot

Agent host-audit records stay available on the probe audit page, but they are
not mixed into the unified honeypot alert center. Keeping the streams separate
prevents a local file-monitor record from being displayed as a file honeypot
alert.
"""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

from flask import current_app

from flask_server.models import (
    AccountAlertInfo,
    AgentControlLog,
    FileAlertInfo,
    Filedeploy,
    Honeyfile,
    MonitorAlert,
    SessionFactory,
    UrlAlertInfo,
)


@dataclass
class UnifiedAlert:
    alert_id: str
    alert_type: str  # file/account/parasitic
    timestamp: datetime
    attacker_ip: Optional[str] = None
    target_path: Optional[str] = None
    action: Optional[str] = None
    details: Optional[Dict] = None

    def to_dict(self):
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


def _normalize_file_token(token_value):
    token = str(token_value or "").strip()
    if "/static/img/logo-" in token:
        token = token.rsplit("/static/img/logo-", 1)[-1]
        if token.endswith(".png"):
            token = token[:-4]
    if "/contact/" in token:
        token = token.rsplit("/contact/", 1)[-1]
    return token.strip("/")


def _format_endpoint(ip, port):
    ip = str(ip or "").strip()
    port = str(port or "").strip()
    if ip and port:
        return f"{ip}:{port}"
    return ip or "-"


def _safe_json_loads(value):
    if isinstance(value, dict):
        return value
    if value in (None, ""):
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {"raw": str(value)}


def _safe_json_dumps(value):
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def _is_official_parasitic_info(value):
    info = value if isinstance(value, dict) else _safe_json_loads(value)
    source = str(info.get("source") or "").strip().lower()
    ingest_source = str(info.get("ingest_source") or "").strip().lower()
    return source == "js/bot" or ingest_source == "systemwire2_pull_js_bot"


def _compact(value, default="-"):
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list, tuple, set)):
        return _safe_json_dumps(value)
    return str(value)


def _time_threshold(hours: int):
    try:
        hours = int(hours)
    except Exception:
        hours = 24
    if hours <= 0:
        return None
    return datetime.now() - timedelta(hours=hours)


def _time_bucket(value: Optional[datetime], seconds: int = 60):
    if not value:
        return ""
    try:
        return int(value.timestamp() // seconds)
    except Exception:
        return str(value)[:16]


FILE_ALERT_LOGICAL_WINDOW_SECONDS = 60


def _file_alert_logical_key(token, report_ip="", report_agent="", alert_message=""):
    return (
        _normalize_file_token(token),
        str(report_ip or "").strip(),
        str(report_agent or "").strip(),
        str(alert_message or "").strip(),
    )


def _file_alert_in_same_open(left: Optional[datetime], right: Optional[datetime]):
    if not left or not right:
        return False
    try:
        return abs((left - right).total_seconds()) <= FILE_ALERT_LOGICAL_WINDOW_SECONDS
    except Exception:
        return False


def _apply_time_filter(query, column, hours: int):
    threshold = _time_threshold(hours)
    if threshold is None:
        return query
    return query.filter(column >= threshold)


def _classify_ssh_client(client_version):
    value = str(client_version or "").strip()
    lower = value.lower()
    if not value:
        return "未知 SSH 客户端"
    if "finalshell" in lower:
        return "FinalShell 交互客户端"
    if "xshell" in lower:
        return "Xshell 交互客户端"
    if "putty" in lower:
        return "PuTTY 交互客户端"
    if "securecrt" in lower:
        return "SecureCRT 交互客户端"
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
    if "request with key" in text or "keytype" in text or "publickey" in text or "fingerprint" in text:
        return "SSH 公钥认证尝试"
    if "request with password" in text or "password" in message_value or "password" in text:
        return "SSH 密码认证尝试"
    if "keyboard-interactive" in text:
        return "SSH 交互式认证尝试"
    if protocol_value == "ssh":
        return "SSH 登录探测"
    return f"{protocol_value.upper()} 访问尝试"


def _iter_path_values(value) -> Iterable[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values = []
        preferred_keys = ("path", "paths", "file", "files", "filename", "name", "target_path")
        for key in preferred_keys:
            if key in value:
                values.extend(_iter_path_values(value.get(key)))
        if not values:
            for item in value.values():
                values.extend(_iter_path_values(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(_iter_path_values(item))
        return values
    return [str(value)]


def _normalize_path_for_match(value):
    path = str(value or "").strip().strip("\"'")
    if not path:
        return ""
    return os.path.normcase(os.path.normpath(path.replace("\\", os.sep).replace("/", os.sep)))


def _basename_match_aliases(basename):
    """Return filename aliases used by Office lock files and direct file opens."""
    value = str(basename or "").strip().lower()
    if not value:
        return set()

    aliases = {value}
    if value.startswith("~$"):
        # Word lock files replace the first characters with "~$" in names such
        # as "137届广交会.docx" -> "~$7届广交会.docx". Short names can also look
        # like "~$6.docx", so keep both forms for matching.
        tail = value[2:]
        if tail:
            aliases.add(tail)
    else:
        aliases.add("~$" + value)
        if len(value) > 2:
            aliases.add("~$" + value[2:])
    return aliases


def _honeyfile_meta(honeyfile, fallback_filename="-"):
    meta = {
        "filename": fallback_filename or "-",
        "filename_tag": fallback_filename or "-",
        "honeypoint_name": "-",
        "token_raw": "-",
    }
    if not honeyfile:
        return meta
    info = honeyfile.to_json()
    meta.update(
        {
            "filename": info.get("filename") or honeyfile.name or fallback_filename or "-",
            "filename_tag": info.get("filename_tag") or honeyfile.name or fallback_filename or "-",
            "honeypoint_name": info.get("honeypoint_name") or getattr(honeyfile, "honeypoint_name", "-") or "-",
            "token_raw": getattr(honeyfile, "token", "-") or "-",
        }
    )
    return meta


class AlertCollector:
    def __init__(self):
        self.session = SessionFactory()
        self._deployed_file_index = None

    def _build_deployed_file_index(self):
        if self._deployed_file_index is not None:
            return self._deployed_file_index

        exact_paths = {}
        basenames = {}

        def add_alias(path, meta):
            normalized = _normalize_path_for_match(path)
            if not normalized:
                return
            exact_paths[normalized] = meta
            basename = os.path.basename(normalized).lower()
            if basename:
                for alias in _basename_match_aliases(basename):
                    basenames.setdefault(alias, meta)

        def add_entry(path, honeyfile=None, source="filedeploy", deploy=None):
            normalized = _normalize_path_for_match(path)
            filename = os.path.basename(normalized) if normalized else ""
            meta = _honeyfile_meta(honeyfile, filename)
            meta.update(
                {
                    "deployment_summary": str(path or "-"),
                    "source": source,
                }
            )
            if deploy:
                deploy_json = deploy.to_json()
                host = deploy_json.get("hostname") or deploy_json.get("host_ip") or "-"
                meta["deployment_summary"] = f"{host}:{deploy_json.get('path') or '-'}"

            add_alias(path, meta)
            if honeyfile:
                deploy_dir = str(path or "")
                if os.path.splitext(deploy_dir)[1]:
                    deploy_dir = os.path.dirname(deploy_dir)
                for filename_alias in {honeyfile.name, meta.get("filename"), meta.get("filename_tag")}:
                    if filename_alias:
                        add_alias(os.path.join(deploy_dir, str(filename_alias)), meta)

        try:
            deploy_rows = self.session.query(Filedeploy).all()
            for deploy in deploy_rows:
                honeyfile = self.session.query(Honeyfile).filter(Honeyfile.id == deploy.honeypoint_id).first()
                add_entry(deploy.path, honeyfile, "filedeploy", deploy)
                if honeyfile:
                    add_entry(os.path.join(str(deploy.path or ""), honeyfile.name or ""), honeyfile, "filedeploy", deploy)
        except Exception as e:
            current_app.logger.warning("Build deployed file index from Filedeploy failed: %s", e)

        try:
            log_rows = (
                self.session.query(AgentControlLog)
                .filter(AgentControlLog.operate_type == "deploy_file_honeypot")
                .order_by(AgentControlLog.created_at.desc())
                .limit(300)
                .all()
            )
            for log in log_rows:
                detail = log.detail if isinstance(log.detail, dict) else _safe_json_loads(log.detail)
                files = detail.get("files") or []
                if isinstance(files, dict):
                    files = [files]
                if not files and (detail.get("file_id") or detail.get("filename")):
                    # Older local deployments were logged as a single file
                    # instead of the newer "files" array.
                    files = [
                        {
                            "file_id": detail.get("file_id"),
                            "filename": detail.get("filename"),
                            "download_url": detail.get("download_url"),
                        }
                    ]
                deploy_paths = detail.get("deploy_paths") or []
                for item in files:
                    if not isinstance(item, dict):
                        item = {"file_id": item}
                    honeyfile = None
                    try:
                        file_id = int(item.get("file_id"))
                        honeyfile = self.session.query(Honeyfile).filter(Honeyfile.id == file_id).first()
                    except Exception:
                        honeyfile = None
                    filename = item.get("filename") or (honeyfile.name if honeyfile else "")
                    for deploy_path in deploy_paths:
                        add_entry(os.path.join(str(deploy_path or ""), str(filename or "")), honeyfile, "agent_control_log")
        except Exception as e:
            current_app.logger.warning("Build deployed file index from AgentControlLog failed: %s", e)

        self._deployed_file_index = {"exact": exact_paths, "basenames": basenames}
        return self._deployed_file_index

    def _match_deployed_honeyfile(self, path_value):
        index = self._build_deployed_file_index()
        for path in _iter_path_values(path_value):
            normalized = _normalize_path_for_match(path)
            if not normalized:
                continue
            if normalized in index["exact"]:
                return index["exact"][normalized]
            basename = os.path.basename(normalized).lower()
            for alias in _basename_match_aliases(basename):
                if alias in index["basenames"]:
                    return index["basenames"][alias]
        return None

    def collect_all(self, hours: int = 24) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []

        collectors = (
            ("parasitic", self.collect_parasitic_alerts),
            ("file", self.collect_file_alerts),
            ("account", self.collect_account_alerts),
        )
        for name, collector in collectors:
            collected = collector(hours)
            alerts.extend(collected)
            current_app.logger.info("Collected %d %s alerts", len(collected), name)

        alerts.sort(key=lambda x: x.timestamp or datetime.min, reverse=True)
        return self._dedupe_alerts(alerts)

    def _dedupe_alerts(self, alerts: List[UnifiedAlert]) -> List[UnifiedAlert]:
        seen = {}
        deduped: List[UnifiedAlert] = []

        for alert in alerts:
            key = self._dedupe_key(alert)
            if not key:
                deduped.append(alert)
                continue

            existing = seen.get(key)
            if existing is None:
                seen[key] = alert
                deduped.append(alert)
                continue

            details = dict(existing.details or {})
            details["duplicate_count"] = int(details.get("duplicate_count") or 1) + 1
            merged_ids = list(details.get("merged_alert_ids") or [existing.alert_id])
            merged_ids.append(alert.alert_id)
            details["merged_alert_ids"] = merged_ids
            merged_times = list(details.get("merged_alert_times") or [])
            if alert.timestamp:
                merged_times.append(alert.timestamp.isoformat())
            details["merged_alert_times"] = merged_times
            existing.details = details

        return deduped

    def _dedupe_key(self, alert: UnifiedAlert):
        if alert.alert_type != "file":
            return None
        details = alert.details or {}
        return (
            "file",
            _time_bucket(alert.timestamp, 60),
            str(alert.attacker_ip or "").strip(),
            str(details.get("token_raw") or details.get("token_url") or alert.target_path or "").strip(),
            str(details.get("filename") or details.get("filename_tag") or "").strip().lower(),
            str(details.get("report_agent") or "").strip(),
        )

    def collect_audit_alerts(self, hours: int = 24) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []

        try:
            query = self.session.query(MonitorAlert)
            query = _apply_time_filter(query, MonitorAlert.trigger_time, hours)
            records = query.order_by(MonitorAlert.trigger_time.desc()).all()
            for record in records:
                honeyfile_match = self._match_deployed_honeyfile(record.path)
                if honeyfile_match:
                    alerts.append(
                        UnifiedAlert(
                            alert_id=f"file_audit_{record.id}",
                            alert_type="file",
                            timestamp=record.trigger_time,
                            attacker_ip=record.ip,
                            target_path=_compact(record.path),
                            action="file_open_local",
                            details={
                                "message": "agent-go 审计记录命中已部署的文件蜜点",
                                "report_agent": record.client_id,
                                "filename": honeyfile_match.get("filename") or "-",
                                "filename_tag": honeyfile_match.get("filename_tag") or "-",
                                "honeypoint_name": honeyfile_match.get("honeypoint_name") or "-",
                                "deployment_summary": honeyfile_match.get("deployment_summary") or "-",
                                "token_raw": honeyfile_match.get("token_raw") or "-",
                                "audit_record_id": record.id,
                                "audit_source": honeyfile_match.get("source") or "agent-go audit",
                                "proctitle": record.proctitle,
                                "cwd": record.cwd,
                                "client_id": record.client_id,
                                "hostname": record.hostname,
                                "syscall": record.syscall,
                                "path": record.path,
                                "source": "agent-go audit matched deployed file honeypot",
                            },
                        )
                    )
                    continue

                alerts.append(
                    UnifiedAlert(
                        alert_id=f"audit_{record.id}",
                        alert_type="audit",
                        timestamp=record.trigger_time,
                        attacker_ip=record.ip,
                        target_path=_compact(record.path),
                        action="agent_file_access",
                        details={
                            "proctitle": record.proctitle,
                            "cwd": record.cwd,
                            "client_id": record.client_id,
                            "hostname": record.hostname,
                            "syscall": record.syscall,
                            "path": record.path,
                            "summary": "agent-go 主机审计/文件监控记录，未匹配到已部署文件蜜点",
                        },
                    )
                )
        except Exception as e:
            current_app.logger.error("Collect audit alerts failed: %s", e)
        return alerts

    def collect_parasitic_alerts(self, hours: int = 24) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []

        try:
            query = self.session.query(UrlAlertInfo)
            query = _apply_time_filter(query, UrlAlertInfo.trigger_time, hours)
            records = query.order_by(UrlAlertInfo.trigger_time.desc()).all()
            for record in records:
                info = record.info if isinstance(record.info, dict) else _safe_json_loads(record.info)
                if not _is_official_parasitic_info(info):
                    continue
                real_ips = (
                    info.get("IPs")
                    or info.get("ips")
                    or info.get("real_ips")
                    or info.get("webrtc_ips")
                    or ([] if not record.dst_ip else [record.dst_ip])
                )
                browser = info.get("browser") or info.get("Browser") or info.get("browserName") or "-"
                os_name = info.get("os") or info.get("OS") or info.get("osName") or "-"
                user_agent = info.get("userAgent") or info.get("ua") or "-"
                session_token = info.get("sessionToken") or info.get("session_token") or "-"
                bot_score = info.get("botScore") or info.get("bot_score") or info.get("score") or "-"
                proxy_headers = info.get("proxy_headers") or {}
                forwarded_for = info.get("x_forwarded_for") or proxy_headers.get("x_forwarded_for") or "-"
                forwarded = info.get("forwarded") or proxy_headers.get("forwarded") or "-"
                via = info.get("via") or proxy_headers.get("via") or "-"
                proxy_detect = info.get("ProxyDetectResult") or info.get("proxy_detect_result") or "-"
                possible_proxy = info.get("possible_proxy")
                if possible_proxy is None:
                    possible_proxy = bool(
                        (forwarded_for and forwarded_for != "-")
                        or (forwarded and forwarded != "-")
                        or (via and via != "-")
                        or str(proxy_detect).strip().lower() == "true"
                    )
                browser_platform = info.get("platform") or info.get("navigatorPlatform") or "-"
                alerts.append(
                    UnifiedAlert(
                        alert_id=f"parasitic_{record.id}",
                        alert_type="parasitic",
                        timestamp=record.trigger_time,
                        attacker_ip=record.src_ip,
                        target_path=record.url,
                        action="url_access",
                        details={
                            "fingerprint": record.fingerprint,
                            "session_token": session_token,
                            "info": info,
                            "dst_ip": record.dst_ip,
                            "real_ips": real_ips,
                            "browser": browser,
                            "os": os_name,
                            "browser_platform": browser_platform,
                            "user_agent": user_agent,
                            "bot_score": bot_score,
                            "proxy_headers": proxy_headers,
                            "x_forwarded_for": forwarded_for,
                            "forwarded": forwarded,
                            "via": via,
                            "proxy_detect_result": proxy_detect,
                            "possible_proxy": possible_proxy,
                            "proxy_note": "若代理未写入 X-Forwarded-For/Via/Forwarded，服务端只能看到代理出口 IP。",
                            "test_info": f"fingerprint={record.fingerprint or '-'} session={session_token} browser={browser} platform={browser_platform}",
                        },
                    )
                )
        except Exception as e:
            current_app.logger.error("Collect parasitic alerts failed: %s", e)
        return alerts

    def collect_file_alerts(self, hours: int = 24) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []

        try:
            query = self.session.query(FileAlertInfo)
            query = _apply_time_filter(query, FileAlertInfo.trigger_time, hours)
            records = query.order_by(FileAlertInfo.trigger_time.desc()).all()
            grouped_records = []
            for record in records:
                key = _file_alert_logical_key(
                    record.token,
                    record.report_ip,
                    record.report_agent,
                    record.alert_message,
                )
                matched = None
                for group in grouped_records:
                    if group["key"] != key:
                        continue
                    if any(_file_alert_in_same_open(record.trigger_time, seen_time) for seen_time in group["seen_times"]):
                        matched = group
                        break
                if matched:
                    matched["records"].append(record)
                    matched["seen_times"].append(record.trigger_time)
                    if record.trigger_time and record.trigger_time > matched["latest_time"]:
                        matched["latest_time"] = record.trigger_time
                        matched["represent_record"] = record
                    if record.trigger_time and record.trigger_time < matched["first_time"]:
                        matched["first_time"] = record.trigger_time
                    continue
                grouped_records.append(
                    {
                        "key": key,
                        "records": [record],
                        "represent_record": record,
                        "seen_times": [record.trigger_time],
                        "first_time": record.trigger_time,
                        "latest_time": record.trigger_time,
                    }
                )

            for group in grouped_records:
                record = group["represent_record"]
                token_raw = _normalize_file_token(record.token)
                honeyfile = self.session.query(Honeyfile).filter(Honeyfile.token == token_raw).first()
                meta = _honeyfile_meta(honeyfile)
                deployment_summary = "-"
                deployments = []
                if honeyfile:
                    deploy_rows = self.session.query(Filedeploy).filter(Filedeploy.honeypoint_id == honeyfile.id).all()
                    deployments = [row.to_json() for row in deploy_rows]
                    if deployments:
                        parts = []
                        for deploy in deployments[:3]:
                            host = deploy.get("hostname") or deploy.get("host_ip") or "-"
                            path = deploy.get("path") or "-"
                            parts.append(f"{host}:{path}")
                        if len(deployments) > 3:
                            parts.append(f"+{len(deployments) - 3} more")
                        deployment_summary = "; ".join(parts)
                alerts.append(
                    UnifiedAlert(
                        alert_id=f"file_{record.id}",
                        alert_type="file",
                        timestamp=record.trigger_time,
                        attacker_ip=record.report_ip,
                        target_path=record.token,
                        action="file_open",
                        details={
                            "message": record.alert_message,
                            "report_agent": record.report_agent,
                            "token_url": record.token,
                            "token_raw": token_raw,
                            "filename": meta.get("filename") or "-",
                            "filename_tag": meta.get("filename_tag") or "-",
                            "honeypoint_name": meta.get("honeypoint_name") or "-",
                            "deployment_summary": deployment_summary,
                            "deployments": deployments,
                            "request_count": len(group["records"]),
                            "raw_alert_ids": [item.id for item in group["records"]],
                            "first_trigger_time": group["first_time"].isoformat() if group["first_time"] else None,
                            "last_trigger_time": group["latest_time"].isoformat() if group["latest_time"] else None,
                            "logical_window_seconds": FILE_ALERT_LOGICAL_WINDOW_SECONDS,
                            "source": "alert_server -> systemwire2",
                        },
                    )
                )
        except Exception as e:
            current_app.logger.error("Collect file alerts failed: %s", e)
        return alerts

    def collect_account_alerts(self, hours: int = 24) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []

        try:
            query = self.session.query(AccountAlertInfo)
            query = _apply_time_filter(query, AccountAlertInfo.trigger_time, hours)
            records = query.order_by(AccountAlertInfo.trigger_time.desc()).all()
            for record in records:
                attack_type = _infer_account_attack_type(record.protocol, record.message, record.client_version, record.raw_event)
                client_family = _classify_ssh_client(record.client_version)
                alerts.append(
                    UnifiedAlert(
                        alert_id=f"account_{record.id}",
                        alert_type="account",
                        timestamp=record.trigger_time,
                        attacker_ip=record.src_ip,
                        target_path=record.dst_ip,
                        action=attack_type,
                        details={
                            "username": record.username,
                            "password": record.password,
                            "src_port": record.src_port,
                            "dst_port": record.dst_port,
                            "src_endpoint": _format_endpoint(record.src_ip, record.src_port),
                            "dst_endpoint": _format_endpoint(record.dst_ip, record.dst_port),
                            "client_version": record.client_version,
                            "client_family": client_family,
                            "protocol": record.protocol,
                            "attack_type": attack_type,
                            "message": record.message,
                            "raw_event": record.raw_event,
                        },
                    )
                )
        except Exception as e:
            current_app.logger.error("Collect account alerts failed: %s", e)
        return alerts

    def save_to_file(self, alerts: List[UnifiedAlert], output_path: str):
        data = [alert.to_dict() for alert in alerts]
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        current_app.logger.info("Saved %d alerts to %s", len(alerts), output_path)

    def get_statistics(self, hours: int = 24) -> Dict:
        alerts = self.collect_all(hours)
        threshold = _time_threshold(hours)
        stats = {
            "total": len(alerts),
            "by_type": {},
            "by_ip": {},
            "time_range": {
                "start": threshold.isoformat() if threshold else None,
                "end": datetime.now().isoformat(),
                "hours": hours,
            },
        }

        for alert in alerts:
            stats["by_type"][alert.alert_type] = stats["by_type"].get(alert.alert_type, 0) + 1
            if alert.attacker_ip:
                stats["by_ip"][alert.attacker_ip] = stats["by_ip"].get(alert.attacker_ip, 0) + 1

        return stats


def collect_alerts(hours: int = 24) -> List[Dict]:
    collector = AlertCollector()
    alerts = collector.collect_all(hours)
    return [alert.to_dict() for alert in alerts]


def get_alert_statistics(hours: int = 24) -> Dict:
    collector = AlertCollector()
    return collector.get_statistics(hours)
