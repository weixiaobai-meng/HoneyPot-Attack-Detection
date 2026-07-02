"""
Step 1: collect multi-source honeypot alerts into a unified event stream.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .adapters import AdapterFactory
from .campaign import campaign_metadata, extract_campaign_id
from .models import AlertType, UnifiedAlert


class DataCollector:
    """Aggregate file, account, parasitic and audit alerts."""

    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()

    @staticmethod
    def _normalize_dt(value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is not None and value.utcoffset() is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def _in_time_range(
        self,
        value: datetime,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> bool:
        ts = self._normalize_dt(value)
        st = self._normalize_dt(start_time)
        et = self._normalize_dt(end_time)
        if st and ts < st:
            return False
        if et and ts > et:
            return False
        return True

    def _default_config(self) -> Dict:
        base_dir = Path(__file__).resolve().parent.parent
        return {
            "analysis_source_mode": "",
            "analysis_include_alert_types": [],
            "unified_alert_store": {
                "enabled": True,
                "db_path": str(self._resolve_systemwire_db_path(base_dir)),
                "prefer_types": ["file", "account", "parasitic"],
                "fallback_to_raw": True,
            },
            "file_honeypot": {
                "db_path": str(base_dir / "alert_server" / "data" / "alert.db"),
                "type": "sqlite",
            },
            "account_honeypot": {
                "log_path": str(base_dir / "ssh-vpn" / "ssh_auth_log.json"),
                "type": "json",
            },
            "parasitic_honeypot": {
                "log_path": str(base_dir / "agent-go" / "log" / "url_alert.json"),
                "type": "json",
            },
            "audit_log": {
                "enabled": True,
                "log_dir": str(base_dir / "agent-go" / "log"),
                "type": "file",
            },
        }

    @staticmethod
    def _systemwire2_root(base_dir: Path) -> Path:
        return base_dir / "systemwire2"

    @staticmethod
    def _import_systemwire2_unified_api_builder(base_dir: Path):
        systemwire2_root = DataCollector._systemwire2_root(base_dir)
        if not systemwire2_root.exists():
            raise FileNotFoundError(f"systemwire2 root not found: {systemwire2_root}")

        systemwire_root_text = str(systemwire2_root)
        if systemwire_root_text not in sys.path:
            sys.path.insert(0, systemwire_root_text)

        from flask_server.flask_app import flask_app  # type: ignore
        from flask_server.alert_store import build_unified_alert_api_rows  # type: ignore

        return flask_app, build_unified_alert_api_rows

    @staticmethod
    def _resolve_systemwire_db_path(base_dir: Path) -> Path:
        config_path = base_dir / "systemwire2" / "config" / "config.py"
        default_path = base_dir / "systemwire2" / "instance" / "honeysert_live.db"
        if not config_path.exists():
            return default_path

        namespace: Dict[str, object] = {}
        try:
            exec(config_path.read_text(encoding="utf-8"), {}, namespace)
        except Exception:
            return default_path

        db_file_path = str(namespace.get("DB_FILE_PATH") or "").strip()
        if db_file_path:
            return Path(os.path.abspath(os.path.expandvars(db_file_path)))

        db_file_name = str(namespace.get("DB_FILE_NAME") or "").strip() or default_path.name
        return base_dir / "systemwire2" / "instance" / db_file_name

    @staticmethod
    def _parse_time_value(value) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value)
            except Exception:
                return datetime.now()
        text = str(value or "").strip()
        if not text:
            return datetime.now()

        candidates = [
            text,
            text.replace("Z", "+00:00"),
        ]
        if " " in text and "T" not in text:
            candidates.append(text.replace(" ", "T", 1))

        for candidate in candidates:
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                continue
        return datetime.now()

    @staticmethod
    def _parse_alert_type(value) -> AlertType:
        if isinstance(value, AlertType):
            return value
        text = str(value or "").strip().lower()
        return AlertType(text or AlertType.AUDIT_EVENT.value)

    @staticmethod
    def _json_obj(value) -> Dict:
        if value is None:
            return {}
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, dict) else {"value": parsed}
            except Exception:
                return {"raw": value}
        return {"value": value}

    @staticmethod
    def _json_list(value) -> List:
        if value is None:
            return []
        if isinstance(value, list):
            return list(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, list) else [parsed]
            except Exception:
                return [value]
        return [value]

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        text = str(value or "").strip().lower()
        return text in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _parse_target_host(value: str) -> Optional[str]:
        text = str(value or "").strip()
        if not text:
            return None
        parsed = urlparse(text)
        if parsed.hostname:
            return parsed.hostname
        if "://" not in text and "/" not in text and ":" in text:
            return text.split(":", 1)[0]
        return None

    @staticmethod
    def _apply_campaign_metadata(details: Dict, evidence: Dict, campaign_id: Optional[str]) -> None:
        meta = campaign_metadata(campaign_id)
        if not meta:
            return
        details.update(meta)
        evidence.setdefault("campaign_id", meta["campaign_id"])
        evidence.setdefault("scenario_id", meta["scenario_id"])
        evidence.setdefault("scenario_role", meta["scenario_role"])

    def _map_unified_api_row_to_alert(self, row: Dict) -> UnifiedAlert:
        alert_type = self._parse_alert_type(row.get("alert_type"))
        timestamp = self._parse_time_value(row.get("timestamp"))
        details = self._json_obj(row.get("details"))
        source_intel = self._json_obj(row.get("source_intel"))
        actor_intel = self._json_obj(row.get("actor_intel"))
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
        evidence = dict(details)
        campaign_id = extract_campaign_id(row, details, evidence, row.get("target_path"))
        self._apply_campaign_metadata(details, evidence, campaign_id)

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
            target_host = row.get("target_path") or None
            protocol = str(details.get("protocol") or "ssh").strip().lower()
            source_type = "network"
            source_id = f"network:{attacker_ip}" if attacker_ip else "network:unknown"
            source_label = attacker_ip or "unknown account source"
            object_type = "service"
            object_id = f"service:{protocol}@{target_host}" if target_host else f"service:{protocol}"
            object_label = target_host or f"{protocol} service"
            stage = "initial_access"
            tactic = "Initial Access"
            technique = "External Remote Services"
            confidence = 0.95
        elif alert_type == AlertType.PARASITIC_HONEYPOT:
            fingerprint = str(details.get("fingerprint") or "").strip()
            session_id = details.get("session_token") or None
            attacker_info = fingerprint or None
            target_host = self._parse_target_host(target_path or "")
            source_type = "browser"
            source_id = f"browser:{fingerprint}" if fingerprint else (f"browser:{session_id}" if session_id else "browser:unknown")
            source_label = fingerprint or session_id or "unknown browser fingerprint"
            object_type = "url"
            object_id = f"url:{target_path}" if target_path else "url:unknown"
            object_label = target_path or "unknown url"
            stage = "reconnaissance"
            tactic = "Reconnaissance"
            technique = "Honey Web Resource Access"
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
            campaign_id=campaign_id,
            scenario_id=campaign_id,
            scenario_role="controlled_chain" if campaign_id else None,
        )

    def _collect_from_systemwire2_unified_api(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        base_dir = Path(__file__).resolve().parent.parent
        flask_app, build_unified_alert_api_rows = self._import_systemwire2_unified_api_builder(base_dir)

        analysis_types = [
            str(item).strip().lower()
            for item in self.config.get("analysis_include_alert_types", [])
            if str(item).strip()
        ]
        if not analysis_types:
            analysis_types = ["file", "account", "parasitic"]

        end = self._normalize_dt(end_time) or datetime.now()
        start = self._normalize_dt(start_time)
        hours = 24
        if start is not None:
            delta_seconds = max((end - start).total_seconds(), 0)
            hours = max(int((delta_seconds + 3599) // 3600), 1)

        alerts: List[UnifiedAlert] = []
        with flask_app.app_context():
            rows = build_unified_alert_api_rows(hours=hours, alert_type=None)
            for row in rows:
                alert_type = str(row.get("alert_type") or "").strip().lower()
                if alert_type not in analysis_types:
                    continue
                alert = self._map_unified_api_row_to_alert(dict(row))
                if self._in_time_range(alert.timestamp, start_time, end_time):
                    alerts.append(alert)

        alerts.sort(key=lambda item: item.timestamp)
        return alerts

    def _use_unified_store_for(self, alert_type: str) -> bool:
        config = self.config.get("unified_alert_store", {})
        if not config.get("enabled", True):
            return False
        preferred = [str(item).strip().lower() for item in config.get("prefer_types", [])]
        return alert_type in preferred

    def _unified_store_fallback_enabled(self) -> bool:
        return bool(self.config.get("unified_alert_store", {}).get("fallback_to_raw", True))

    def _audit_enabled(self) -> bool:
        return bool(self.config.get("audit_log", {}).get("enabled", True))

    def _collect_from_unified_store(
        self,
        alert_type: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        config = self.config.get("unified_alert_store", {})
        db_path = str(config.get("db_path") or "").strip()
        if not db_path or not os.path.exists(db_path):
            return []

        alerts: List[UnifiedAlert] = []
        parser_map = {
            "file": self._parse_unified_file_alert,
            "account": self._parse_unified_account_alert,
            "parasitic": self._parse_unified_parasitic_alert,
        }
        query_map = {
            "file": self._query_unified_file_rows,
            "account": self._query_unified_account_rows,
            "parasitic": self._query_unified_parasitic_rows,
        }
        parser = parser_map.get(alert_type)
        query = query_map.get(alert_type)
        if parser is None or query is None:
            return []

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = query(conn)
            for row in rows:
                alert = parser(dict(row))
                if self._in_time_range(alert.timestamp, start_time, end_time):
                    alerts.append(alert)
            conn.close()
        except Exception as exc:
            print(f"[-] failed to read unified {alert_type} alerts: {exc}")
            return []

        return alerts

    @staticmethod
    def _query_unified_file_rows(conn: sqlite3.Connection) -> List[sqlite3.Row]:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                e.id AS event_id,
                e.source_service,
                e.source_event_id,
                e.honeypot_id,
                e.honeypot_name,
                e.alert_time,
                e.src_ip,
                e.dst_ip,
                e.severity,
                e.status,
                e.title,
                e.summary,
                e.dedupe_key,
                e.legacy_table,
                e.legacy_row_id,
                f.token,
                f.token_url,
                f.filename,
                f.filename_tag,
                f.honeypoint_name,
                f.deploy_path,
                f.deployment_summary,
                f.report_agent,
                f.message,
                f.open_count,
                f.first_alert_time,
                f.last_alert_time,
                f.raw_alert_ids_json,
                f.deployments_json
            FROM alert_events AS e
            LEFT JOIN file_alert_details AS f ON f.alert_id = e.id
            WHERE e.alert_type = 'file'
            ORDER BY e.alert_time DESC, e.id DESC
            """
        )
        return cursor.fetchall()

    @staticmethod
    def _query_unified_account_rows(conn: sqlite3.Connection) -> List[sqlite3.Row]:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                e.id AS event_id,
                e.source_service,
                e.source_event_id,
                e.honeypot_id,
                e.honeypot_name,
                e.alert_time,
                e.src_ip,
                e.dst_ip,
                e.severity,
                e.status,
                e.title,
                e.summary,
                e.dedupe_key,
                e.legacy_table,
                e.legacy_row_id,
                a.protocol,
                a.username,
                a.password,
                a.src_port,
                a.dst_port,
                a.client_version,
                a.client_family,
                a.auth_type,
                a.message,
                a.raw_event_json
            FROM alert_events AS e
            LEFT JOIN account_alert_details AS a ON a.alert_id = e.id
            WHERE e.alert_type = 'account'
            ORDER BY e.alert_time DESC, e.id DESC
            """
        )
        return cursor.fetchall()

    @staticmethod
    def _query_unified_parasitic_rows(conn: sqlite3.Connection) -> List[sqlite3.Row]:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                e.id AS event_id,
                e.source_service,
                e.source_event_id,
                e.honeypot_id,
                e.honeypot_name,
                e.alert_time,
                e.src_ip,
                e.dst_ip,
                e.severity,
                e.status,
                e.title,
                e.summary,
                e.dedupe_key,
                e.legacy_table,
                e.legacy_row_id,
                p.url,
                p.fingerprint,
                p.session_token,
                p.browser,
                p.os,
                p.browser_platform,
                p.user_agent,
                p.real_ips_json,
                p.bot_score,
                p.is_bot,
                p.proxy_detect_result,
                p.possible_proxy,
                p.x_forwarded_for,
                p.forwarded,
                p.via,
                p.reason,
                p.proxy_note,
                p.detail_json
            FROM alert_events AS e
            LEFT JOIN parasitic_alert_details AS p ON p.alert_id = e.id
            WHERE e.alert_type = 'parasitic'
            ORDER BY e.alert_time DESC, e.id DESC
            """
        )
        return cursor.fetchall()

    def _parse_unified_file_alert(self, row: Dict) -> UnifiedAlert:
        timestamp = self._parse_time_value(row.get("alert_time"))
        deploy_path = str(row.get("deploy_path") or "").strip()
        filename = str(row.get("filename") or "").strip()
        token_url = str(row.get("token_url") or "").strip()
        target_path = deploy_path or filename or token_url or "-"
        message = row.get("message") or row.get("summary") or row.get("title") or "file honeypot alert"
        report_agent = str(row.get("report_agent") or "").strip()

        details = {
            "message": message,
            "token": row.get("token"),
            "token_url": token_url,
            "filename": filename,
            "filename_tag": row.get("filename_tag"),
            "honeypoint_name": row.get("honeypoint_name") or row.get("honeypot_name"),
            "deploy_path": deploy_path,
            "deployment_summary": row.get("deployment_summary"),
            "report_agent": report_agent,
            "open_count": int(row.get("open_count") or 1),
            "raw_alert_ids": self._json_list(row.get("raw_alert_ids_json")),
            "deployments": self._json_list(row.get("deployments_json")),
            "first_alert_time": row.get("first_alert_time"),
            "last_alert_time": row.get("last_alert_time"),
            "source_event_id": row.get("source_event_id"),
            "dedupe_key": row.get("dedupe_key"),
            "status": row.get("status"),
            "legacy_row_id": row.get("legacy_row_id"),
        }
        evidence = {
            "token": row.get("token"),
            "token_url": token_url,
            "filename": filename,
            "deploy_path": deploy_path,
            "report_agent": report_agent,
            "message": message,
            "source_service": row.get("source_service") or "systemwire2",
            "honeypot_name": row.get("honeypot_name"),
        }
        campaign_id = extract_campaign_id(row, details, evidence, token_url, filename, deploy_path)
        self._apply_campaign_metadata(details, evidence, campaign_id)

        return UnifiedAlert(
            alert_id=f"systemwire-file-{row.get('event_id')}",
            alert_type=AlertType.FILE_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=row.get("src_ip"),
            attacker_info=report_agent or None,
            target_host=row.get("dst_ip"),
            target_path=target_path,
            action="file_access",
            details=details,
            source_type="network",
            source_id=f"network:{row.get('src_ip')}" if row.get("src_ip") else "network:unknown",
            source_label=row.get("src_ip") or "unknown network source",
            object_type="file",
            object_id=f"file:{target_path}" if target_path and target_path != "-" else "file:unknown",
            object_label=deploy_path or filename or token_url or "unknown file",
            stage="collection",
            tactic="Collection",
            technique="Honey File Access",
            confidence=0.96,
            severity=row.get("severity") or "high",
            evidence=evidence,
            campaign_id=campaign_id,
            scenario_id=campaign_id,
            scenario_role="controlled_chain" if campaign_id else None,
        )

    def _parse_unified_account_alert(self, row: Dict) -> UnifiedAlert:
        timestamp = self._parse_time_value(row.get("alert_time"))
        protocol = str(row.get("protocol") or "ssh").strip().lower()
        action = "vpn_connect" if protocol == "openvpn" else "ssh_login"
        target_host = str(row.get("dst_ip") or "").strip()
        client_version = str(row.get("client_version") or "").strip()
        username = str(row.get("username") or "").strip()
        auth_type = row.get("auth_type") or row.get("title") or "account honeypot alert"

        details = {
            "protocol": protocol,
            "username": username,
            "password": row.get("password"),
            "src_port": row.get("src_port"),
            "dst_port": row.get("dst_port"),
            "client_version": client_version,
            "client_family": row.get("client_family"),
            "attack_type": auth_type,
            "message": row.get("message") or row.get("summary") or row.get("title"),
            "raw_event": self._json_obj(row.get("raw_event_json")),
            "source_event_id": row.get("source_event_id"),
            "dedupe_key": row.get("dedupe_key"),
            "status": row.get("status"),
            "legacy_row_id": row.get("legacy_row_id"),
        }
        evidence = {
            "protocol": protocol,
            "username": username,
            "client_version": client_version,
            "client_family": row.get("client_family"),
            "attack_type": auth_type,
            "source_service": row.get("source_service") or "systemwire2",
            "honeypot_name": row.get("honeypot_name"),
        }
        campaign_id = extract_campaign_id(row, details, evidence, username, row.get("password"))
        self._apply_campaign_metadata(details, evidence, campaign_id)

        return UnifiedAlert(
            alert_id=f"systemwire-account-{row.get('event_id')}",
            alert_type=AlertType.ACCOUNT_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=row.get("src_ip"),
            attacker_info=client_version or None,
            target_host=target_host or None,
            target_path=target_host or "",
            action=action,
            details=details,
            source_type="network",
            source_id=f"network:{row.get('src_ip')}" if row.get("src_ip") else "network:unknown",
            source_label=row.get("src_ip") or "unknown account source",
            object_type="service",
            object_id=f"service:{protocol}@{target_host}" if target_host else f"service:{protocol}",
            object_label=target_host or f"{protocol} service",
            stage="initial_access",
            tactic="Initial Access",
            technique="External Remote Services",
            confidence=0.95,
            severity=row.get("severity") or "high",
            evidence=evidence,
            campaign_id=campaign_id,
            scenario_id=campaign_id,
            scenario_role="controlled_chain" if campaign_id else None,
        )

    def _parse_unified_parasitic_alert(self, row: Dict) -> UnifiedAlert:
        timestamp = self._parse_time_value(row.get("alert_time"))
        info = self._json_obj(row.get("detail_json"))
        real_ips = [str(item).strip() for item in self._json_list(row.get("real_ips_json")) if str(item).strip()]
        url_value = str(row.get("url") or info.get("path") or info.get("url") or "").strip()
        fingerprint = str(row.get("fingerprint") or info.get("fingerprint") or "").strip()
        session_token = str(row.get("session_token") or info.get("session_token") or "").strip()
        browser = str(row.get("browser") or info.get("browser") or info.get("browserName") or "").strip()
        os_name = str(row.get("os") or info.get("os") or info.get("osName") or "").strip()
        browser_platform = str(row.get("browser_platform") or info.get("platform") or info.get("navigatorPlatform") or "").strip()
        user_agent = str(row.get("user_agent") or info.get("userAgent") or info.get("ua") or "").strip()
        bot_score = int(row.get("bot_score") or info.get("bot_score") or info.get("score") or 0)
        is_bot = self._as_bool(row.get("is_bot")) or self._as_bool(info.get("is_bot"))
        proxy_detect_result = str(row.get("proxy_detect_result") or info.get("proxy_detect_result") or info.get("ProxyDetectResult") or "").strip()
        possible_proxy = self._as_bool(row.get("possible_proxy")) or self._as_bool(info.get("possible_proxy"))
        x_forwarded_for = str(row.get("x_forwarded_for") or info.get("x_forwarded_for") or "").strip()
        forwarded = str(row.get("forwarded") or info.get("forwarded") or "").strip()
        via = str(row.get("via") or info.get("via") or "").strip()
        reason = str(row.get("reason") or info.get("reason") or "").strip()
        proxy_note = str(row.get("proxy_note") or info.get("proxy_note") or "").strip()
        if not possible_proxy:
            possible_proxy = any(header for header in (x_forwarded_for, forwarded, via)) or proxy_detect_result.lower() == "true"

        details = {
            "fingerprint": fingerprint,
            "session_token": session_token,
            "url": url_value,
            "browser": browser,
            "os": os_name,
            "browser_platform": browser_platform,
            "user_agent": user_agent,
            "real_ips": real_ips,
            "bot_score": bot_score,
            "is_bot": is_bot,
            "proxy_detect_result": proxy_detect_result,
            "possible_proxy": possible_proxy,
            "x_forwarded_for": x_forwarded_for,
            "forwarded": forwarded,
            "via": via,
            "reason": reason,
            "proxy_note": proxy_note,
            "group_id": info.get("group_id"),
            "raw_info": info,
            "source_event_id": row.get("source_event_id"),
            "dedupe_key": row.get("dedupe_key"),
            "status": row.get("status"),
            "legacy_row_id": row.get("legacy_row_id"),
        }

        severity = row.get("severity") or ("high" if is_bot or possible_proxy else "medium")
        confidence = 0.94 if is_bot or possible_proxy else 0.9
        evidence = {
            "fingerprint": fingerprint,
            "session_token": session_token,
            "url": url_value,
            "real_ips": real_ips,
            "proxy_detect_result": proxy_detect_result,
            "possible_proxy": possible_proxy,
            "bot_score": bot_score,
            "is_bot": is_bot,
            "source_service": row.get("source_service") or "systemwire2",
            "honeypot_name": row.get("honeypot_name"),
        }
        campaign_id = extract_campaign_id(row, details, evidence, url_value, info)
        self._apply_campaign_metadata(details, evidence, campaign_id)

        return UnifiedAlert(
            alert_id=f"systemwire-parasitic-{row.get('event_id')}",
            alert_type=AlertType.PARASITIC_HONEYPOT,
            timestamp=timestamp,
            attacker_ip=row.get("src_ip"),
            attacker_info=fingerprint or None,
            target_host=self._parse_target_host(url_value),
            target_path=url_value,
            action="url_access",
            details=details,
            session_id=session_token or None,
            source_type="browser",
            source_id=f"browser:{fingerprint}" if fingerprint else (f"browser:{session_token}" if session_token else "browser:unknown"),
            source_label=fingerprint or session_token or "unknown browser fingerprint",
            object_type="url",
            object_id=f"url:{url_value}" if url_value else "url:unknown",
            object_label=url_value or "unknown url",
            stage="reconnaissance",
            tactic="Reconnaissance",
            technique="Honey Web Resource Access",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            campaign_id=campaign_id,
            scenario_id=campaign_id,
            scenario_role="controlled_chain" if campaign_id else None,
        )

    def collect_all(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        start_time = self._normalize_dt(start_time)
        end_time = self._normalize_dt(end_time)
        analysis_source_mode = str(self.config.get("analysis_source_mode") or "").strip().lower()
        if analysis_source_mode == "systemwire2_unified_only":
            return self._collect_from_systemwire2_unified_api(start_time, end_time)

        all_alerts: List[UnifiedAlert] = []

        file_alerts = self.collect_file_honeypot(start_time, end_time)
        all_alerts.extend(file_alerts)
        print(f"[+] file alerts: {len(file_alerts)}")

        account_alerts = self.collect_account_honeypot(start_time, end_time)
        all_alerts.extend(account_alerts)
        print(f"[+] account alerts: {len(account_alerts)}")

        parasitic_alerts = self.collect_parasitic_honeypot(start_time, end_time)
        all_alerts.extend(parasitic_alerts)
        print(f"[+] parasitic alerts: {len(parasitic_alerts)}")

        if self._audit_enabled():
            audit_alerts = self.collect_audit_logs(start_time, end_time)
            all_alerts.extend(audit_alerts)
            print(f"[+] audit events: {len(audit_alerts)}")
        else:
            print("[*] audit event collection disabled")

        all_alerts.sort(key=lambda alert: alert.timestamp)
        return all_alerts

    def describe_sources(self) -> Dict[str, object]:
        unified_cfg = self.config.get("unified_alert_store", {})
        return {
            "unified_alert_store_enabled": bool(unified_cfg.get("enabled", True)),
            "unified_alert_store_db_path": str(unified_cfg.get("db_path") or ""),
            "unified_alert_store_prefer_types": list(unified_cfg.get("prefer_types", [])),
            "unified_alert_store_fallback_to_raw": bool(unified_cfg.get("fallback_to_raw", True)),
            "analysis_source_mode": str(self.config.get("analysis_source_mode") or ""),
            "analysis_include_alert_types": list(self.config.get("analysis_include_alert_types", [])),
            "raw_file_db_path": str(self.config.get("file_honeypot", {}).get("db_path") or ""),
            "raw_account_log_path": str(self.config.get("account_honeypot", {}).get("log_path") or ""),
            "raw_parasitic_log_path": str(self.config.get("parasitic_honeypot", {}).get("log_path") or ""),
            "audit_log_enabled": self._audit_enabled(),
            "audit_log_dir": str(self.config.get("audit_log", {}).get("log_dir") or ""),
        }

    def collect_file_honeypot(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        if self._use_unified_store_for("file"):
            unified_alerts = self._collect_from_unified_store("file", start_time, end_time)
            if unified_alerts or not self._unified_store_fallback_enabled():
                return unified_alerts
            print("[*] unified file alerts unavailable, falling back to raw file alert db")

        alerts: List[UnifiedAlert] = []
        db_path = self.config.get("file_honeypot", {}).get("db_path")

        if not db_path or not os.path.exists(db_path):
            print(f"[-] file honeypot db not found: {db_path}")
            return alerts

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM trigger_infos WHERE 1=1"
            params = []
            if start_time:
                query += " AND trigger_time >= ?"
                params.append(start_time.isoformat())
            if end_time:
                query += " AND trigger_time <= ?"
                params.append(end_time.isoformat())
            query += " ORDER BY trigger_time DESC"
            cursor.execute(query, params)

            adapter = AdapterFactory.get_adapter(AlertType.FILE_HONEYPOT)
            for row in cursor.fetchall():
                for alert in adapter.parse(dict(row)):
                    if self._in_time_range(alert.timestamp, start_time, end_time):
                        alerts.append(alert)

            conn.close()
        except Exception as exc:
            print(f"[-] failed to read file honeypot db: {exc}")

        return alerts

    def collect_account_honeypot(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        if self._use_unified_store_for("account"):
            unified_alerts = self._collect_from_unified_store("account", start_time, end_time)
            if unified_alerts or not self._unified_store_fallback_enabled():
                return unified_alerts
            print("[*] unified account alerts unavailable, falling back to raw account log")

        alerts: List[UnifiedAlert] = []
        log_path = self.config.get("account_honeypot", {}).get("log_path")

        if not log_path or not os.path.exists(log_path):
            print(f"[-] account honeypot log not found: {log_path}")
            return alerts

        try:
            adapter = AdapterFactory.get_adapter(AlertType.ACCOUNT_HONEYPOT)
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for alert in adapter.parse(raw_data):
                        if self._in_time_range(alert.timestamp, start_time, end_time):
                            alerts.append(alert)
        except Exception as exc:
            print(f"[-] failed to read account honeypot log: {exc}")

        return alerts

    def collect_parasitic_honeypot(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        if self._use_unified_store_for("parasitic"):
            unified_alerts = self._collect_from_unified_store("parasitic", start_time, end_time)
            if unified_alerts or not self._unified_store_fallback_enabled():
                return unified_alerts
            print("[*] unified parasitic alerts unavailable, falling back to raw parasitic log")

        alerts: List[UnifiedAlert] = []
        log_path = self.config.get("parasitic_honeypot", {}).get("log_path")

        if not log_path or not os.path.exists(log_path):
            print(f"[-] parasitic honeypot log not found: {log_path}")
            return alerts

        try:
            adapter = AdapterFactory.get_adapter(AlertType.PARASITIC_HONEYPOT)
            with open(log_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return alerts

            if content.startswith("["):
                data_list = json.loads(content)
            else:
                data_list = []
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data_list.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            for raw_data in data_list:
                for alert in adapter.parse(raw_data):
                    if self._in_time_range(alert.timestamp, start_time, end_time):
                        alerts.append(alert)
        except Exception as exc:
            print(f"[-] failed to read parasitic honeypot log: {exc}")

        return alerts

    def collect_audit_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[UnifiedAlert]:
        alerts: List[UnifiedAlert] = []
        audit_cfg = self.config.get("audit_log", {})
        if not audit_cfg.get("enabled", True):
            return alerts
        log_dir = audit_cfg.get("log_dir")

        if not log_dir or not os.path.exists(log_dir):
            print(f"[-] audit log dir not found: {log_dir}")
            return alerts

        try:
            adapter = AdapterFactory.get_adapter(AlertType.AUDIT_EVENT)
            for filename in os.listdir(log_dir):
                if not filename.startswith("file_event_audit"):
                    continue
                filepath = os.path.join(log_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw_data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        for alert in adapter.parse(raw_data):
                            if self._in_time_range(alert.timestamp, start_time, end_time):
                                alerts.append(alert)
        except Exception as exc:
            print(f"[-] failed to read audit logs: {exc}")

        return alerts

    def save_alerts(self, alerts: List[UnifiedAlert], output_path: str) -> None:
        """Save both legacy alerts and canonical thesis events."""
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        alert_payload = [alert.to_dict() for alert in alerts]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(alert_payload, f, ensure_ascii=False, indent=2)

        canonical_path = os.path.join(output_dir, "canonical_events.json")
        canonical_payload = [alert.to_canonical_event() for alert in alerts]
        with open(canonical_path, "w", encoding="utf-8") as f:
            json.dump(canonical_payload, f, ensure_ascii=False, indent=2)

        print(f"[+] saved {len(alerts)} alerts to {output_path}")
        print(f"[+] saved canonical thesis events to {canonical_path}")
