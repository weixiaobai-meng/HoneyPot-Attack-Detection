import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

import pytz
from flask import current_app
from sqlalchemy import func, or_

from config.config import LEGACY_DB_FILE_PATH
from flask_server.exts import db
from flask_server.models import (
    AccountAlertInfo,
    FileAlertInfo,
    Honeyfile,
    Filedeploy,
    LastQueryTime,
    UrlAlertInfo,
)


beijing_tz = pytz.timezone("Asia/Shanghai")
FILE_ALERT_LOGICAL_WINDOW_SECONDS = 60
PARASITIC_ALERT_LOGICAL_WINDOW_SECONDS = 60
LEGACY_BUSINESS_TABLE_ORDER = [
    "file_type_dict",
    "servers",
    "user",
    "honeyfiles",
    "filedeploy",
    "honeyaccount",
    "honeyemail",
    "EmailInfo",
    "agent_client_info",
    "agent_control_log",
    "agent_monitor_record",
    "honeyurl",
]


class UnifiedAlertEvent(db.Model):
    __tablename__ = "alert_events"

    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    alert_type = db.Column(db.String(32), nullable=False, index=True)
    source_service = db.Column(db.String(64), nullable=False, default="systemwire2", index=True)
    source_event_id = db.Column(db.String(128), nullable=True, index=True)
    honeypot_id = db.Column(db.Integer, nullable=True, index=True)
    honeypot_name = db.Column(db.String(128), nullable=True)
    alert_time = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    src_ip = db.Column(db.String(128), nullable=True, index=True)
    dst_ip = db.Column(db.String(128), nullable=True)
    severity = db.Column(db.String(16), nullable=False, default="medium", index=True)
    status = db.Column(db.String(16), nullable=False, default="new", index=True)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.String(1024), nullable=True)
    raw_event_id = db.Column(db.Integer, db.ForeignKey("alert_raw_events.id"), nullable=True, index=True)
    dedupe_key = db.Column(db.String(255), nullable=False, unique=True, index=True)
    legacy_table = db.Column(db.String(64), nullable=True, index=True)
    legacy_row_id = db.Column(db.Integer, nullable=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    raw_event = db.relationship("AlertRawEvent", backref="alert_events", lazy=True)
    file_detail = db.relationship("FileAlertDetail", backref="event", uselist=False, cascade="all, delete-orphan")
    account_detail = db.relationship("AccountAlertDetail", backref="event", uselist=False, cascade="all, delete-orphan")
    parasitic_detail = db.relationship("ParasiticAlertDetail", backref="event", uselist=False, cascade="all, delete-orphan")


class AlertRawEvent(db.Model):
    __tablename__ = "alert_raw_events"

    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    source_service = db.Column(db.String(64), nullable=False, default="systemwire2", index=True)
    source_event_id = db.Column(db.String(128), nullable=True, index=True)
    payload_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)


class FileAlertDetail(db.Model):
    __tablename__ = "file_alert_details"

    alert_id = db.Column(db.Integer, db.ForeignKey("alert_events.id"), primary_key=True)
    token = db.Column(db.String(255), nullable=True, index=True)
    token_url = db.Column(db.String(512), nullable=True)
    filename = db.Column(db.String(255), nullable=True)
    filename_tag = db.Column(db.String(255), nullable=True)
    honeypoint_name = db.Column(db.String(128), nullable=True)
    deploy_path = db.Column(db.String(512), nullable=True)
    deployment_summary = db.Column(db.String(1024), nullable=True)
    report_agent = db.Column(db.String(512), nullable=True)
    message = db.Column(db.String(255), nullable=True)
    open_count = db.Column(db.Integer, nullable=False, default=1)
    first_alert_time = db.Column(db.DateTime(timezone=True), nullable=True)
    last_alert_time = db.Column(db.DateTime(timezone=True), nullable=True)
    raw_alert_ids_json = db.Column(db.Text, nullable=True)
    deployments_json = db.Column(db.Text, nullable=True)


class AccountAlertDetail(db.Model):
    __tablename__ = "account_alert_details"

    alert_id = db.Column(db.Integer, db.ForeignKey("alert_events.id"), primary_key=True)
    protocol = db.Column(db.String(32), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True, index=True)
    password = db.Column(db.String(255), nullable=True)
    src_port = db.Column(db.String(32), nullable=True)
    dst_port = db.Column(db.String(32), nullable=True)
    client_version = db.Column(db.String(512), nullable=True)
    client_family = db.Column(db.String(128), nullable=True)
    auth_type = db.Column(db.String(128), nullable=True)
    message = db.Column(db.String(255), nullable=True)
    raw_event_json = db.Column(db.Text, nullable=True)


class ParasiticAlertDetail(db.Model):
    __tablename__ = "parasitic_alert_details"

    alert_id = db.Column(db.Integer, db.ForeignKey("alert_events.id"), primary_key=True)
    url = db.Column(db.String(1024), nullable=True, index=True)
    fingerprint = db.Column(db.String(255), nullable=True, index=True)
    session_token = db.Column(db.String(255), nullable=True, index=True)
    browser = db.Column(db.String(128), nullable=True)
    os = db.Column(db.String(128), nullable=True)
    browser_platform = db.Column(db.String(128), nullable=True)
    user_agent = db.Column(db.String(1024), nullable=True)
    real_ips_json = db.Column(db.Text, nullable=True)
    bot_score = db.Column(db.Integer, nullable=True)
    is_bot = db.Column(db.Boolean, nullable=False, default=False)
    proxy_detect_result = db.Column(db.String(32), nullable=True)
    possible_proxy = db.Column(db.Boolean, nullable=True)
    x_forwarded_for = db.Column(db.String(512), nullable=True)
    forwarded = db.Column(db.String(512), nullable=True)
    via = db.Column(db.String(512), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    proxy_note = db.Column(db.String(1024), nullable=True)
    detail_json = db.Column(db.Text, nullable=True)


class AlertMigrationState(db.Model):
    __tablename__ = "alert_migration_state"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


def _json_text(value) -> str:
    if value is None:
        return "{}"
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return json.dumps({"value": str(value)}, ensure_ascii=False)


def _json_obj(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
            return {"raw": value}
        except Exception:
            return {"raw": value}
    return {"value": value}


def _clean_placeholder_text(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in {"", "-", "none", "null", "<nil>", "<none>", "undefined"}:
        return ""
    return text


def _coerce_bool(value) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = _clean_placeholder_text(value).lower()
    if not text:
        return None
    if text in {"true", "1", "yes", "y", "on"}:
        return True
    if text in {"false", "0", "no", "n", "off"}:
        return False
    return bool(text)


def _normalize_proxy_fields(*values) -> Tuple[str, ...]:
    return tuple(_clean_placeholder_text(value) or "-" for value in values)


def _resolve_possible_proxy(stored_value, proxy_detect_result, *header_values) -> bool:
    stored_bool = _coerce_bool(stored_value)
    if stored_bool is not None:
        return stored_bool
    proxy_detect_bool = _coerce_bool(proxy_detect_result)
    if proxy_detect_bool is not None:
        return proxy_detect_bool
    return any(_clean_placeholder_text(value) for value in header_values)


def _ensure_bj(value: Optional[datetime]) -> datetime:
    if value is None:
        return datetime.now(beijing_tz)
    if value.tzinfo is None:
        return beijing_tz.localize(value)
    return value.astimezone(beijing_tz)


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


def _classify_ssh_client(client_version):
    text = str(client_version or "").strip().lower()
    if not text:
        return "未知 SSH 客户端"
    if "openssh" in text:
        return "OpenSSH 客户端"
    if "finalshell" in text:
        return "FinalShell"
    if "nsssh" in text or "netsarang" in text or "xshell" in text:
        return "Xshell / NetSarang"
    if "putty" in text:
        return "PuTTY"
    return "未知 SSH 客户端"


def _infer_account_attack_type(protocol_value, message_value, client_version, raw_event):
    protocol_value = str(protocol_value or "ssh").strip().lower()
    message_value = str(message_value or "").strip()
    raw_text = _json_text(raw_event).lower()
    text = f"{message_value.lower()} {raw_text} {str(client_version or '').lower()}"
    if "request with password" in text or "password" in message_value.lower():
        return "SSH 密码认证尝试"
    if "request with key" in text or "keytype" in text or "fingerprint" in text:
        return "SSH 公钥认证尝试"
    if protocol_value == "ssh":
        return "SSH 登录探测"
    return f"{protocol_value.upper()} 访问尝试"


def _file_alert_logical_key(token, report_ip, report_agent, alert_message):
    token_raw = _normalize_file_token(token)
    return "|".join(
        [
            token_raw or "-",
            str(report_ip or "").strip().lower(),
            str(report_agent or "").strip().lower(),
            str(alert_message or "").strip().lower(),
        ]
    )


def _file_alert_bucket(trigger_time: datetime) -> int:
    dt = _ensure_bj(trigger_time)
    return int(dt.timestamp() // FILE_ALERT_LOGICAL_WINDOW_SECONDS)


def _parasitic_logical_key(src_ip, url, fingerprint, session_token, trigger_time):
    dt = _ensure_bj(trigger_time)
    bucket = int(dt.timestamp() // PARASITIC_ALERT_LOGICAL_WINDOW_SECONDS)
    return "|".join(
        [
            str(src_ip or "").strip().lower(),
            str(url or "").strip().lower(),
            str(fingerprint or "").strip().lower(),
            str(session_token or "").strip().lower(),
            str(bucket),
        ]
    )


def _account_dedupe_key(src_ip, dst_ip, username, protocol, message, trigger_time):
    dt = _ensure_bj(trigger_time)
    bucket = int(dt.timestamp())
    return "|".join(
        [
            str(src_ip or "").strip().lower(),
            str(dst_ip or "").strip().lower(),
            str(username or "").strip().lower(),
            str(protocol or "").strip().lower(),
            str(message or "").strip().lower(),
            str(bucket),
        ]
    )


def _find_honeyfile_by_token_raw(token_raw: str):
    token_raw = _normalize_file_token(token_raw)
    if not token_raw:
        return None

    direct = Honeyfile.query.filter_by(token=token_raw).order_by(Honeyfile.id.desc()).first()
    if direct:
        return direct

    suffix = f"/contact/{token_raw}"
    static_suffix = f"/static/img/logo-{token_raw}.png"
    return (
        Honeyfile.query.filter(
            or_(
                Honeyfile.token.like(f"%{static_suffix}"),
                Honeyfile.token.like(f"%{suffix}"),
                Honeyfile.token == f"http://127.0.0.1:9090{static_suffix}",
                Honeyfile.token == f"http://127.0.0.1:9090{suffix}",
            )
        )
        .order_by(Honeyfile.id.desc())
        .first()
    )


def _lookup_honeyfile_meta(token_raw: str):
    meta = {
        "filename": "-",
        "filename_tag": "-",
        "honeypoint_name": "-",
        "deployment_summary": "-",
        "deployments": [],
        "deploy_path": "-",
        "honeypot_id": None,
        "honeypot_name": "-",
    }
    if not token_raw:
        return meta

    honeyfile = _find_honeyfile_by_token_raw(token_raw)
    if not honeyfile:
        return meta

    file_info = honeyfile.to_json()
    deployments = Filedeploy.query.filter_by(honeypoint_id=honeyfile.id).all()
    deploy_infos = [deploy.to_json() for deploy in deployments]
    deploy_path = next((item.get("path") for item in deploy_infos if item.get("path")), "-")
    summary_parts = []
    for deploy in deploy_infos[:3]:
        host = deploy.get("hostname") or deploy.get("host_ip") or "-"
        path = deploy.get("path") or "-"
        summary_parts.append(f"{host}:{path}")
    if len(deploy_infos) > 3:
        summary_parts.append(f"+{len(deploy_infos) - 3} more")
    deployment_summary = "; ".join(summary_parts) if summary_parts else "-"
    meta.update(
        {
            "filename": file_info.get("filename") or honeyfile.name,
            "filename_tag": file_info.get("filename_tag") or honeyfile.name,
            "honeypoint_name": file_info.get("honeypoint_name") or "-",
            "deployment_summary": deployment_summary,
            "deployments": deploy_infos,
            "deploy_path": deploy_path,
            "honeypot_id": honeyfile.id,
            "honeypot_name": file_info.get("honeypoint_name") or honeyfile.name,
        }
    )
    return meta


def _upsert_migration_state(key: str, value: str):
    state = AlertMigrationState.query.filter_by(key=key).first()
    if state is None:
        state = AlertMigrationState(key=key, value=value)
        db.session.add(state)
    else:
        state.value = value


def ensure_unified_alert_schema():
    db.create_all()


def backfill_unified_alerts(app):
    with app.app_context():
        ensure_unified_alert_schema()
        _migrate_legacy_business_tables()
        _migrate_from_legacy_temp_db()
        _backfill_file_alerts()
        _backfill_account_alerts()
        _backfill_parasitic_alerts()
        refresh_file_alert_metadata()
        _upsert_migration_state("backfill_v1_completed", "1")
        _upsert_migration_state("backfill_v1_last_run", datetime.now(beijing_tz).isoformat())
        db.session.commit()
        current_app.logger.info("unified alert backfill synced")


def _current_sqlite_db_path() -> str:
    try:
        return os.path.abspath(str(db.engine.url.database or ""))
    except Exception:
        return ""


def _connect_sqlite(path: str, *, read_only: bool = False, row_factory=None):
    normalized = os.path.abspath(path)
    if read_only:
        uri = "file:" + normalized.replace("\\", "/") + "?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(normalized)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=MEMORY")
        conn.execute("PRAGMA busy_timeout=5000")
    if row_factory is not None:
        conn.row_factory = row_factory
    return conn


def _sqlite_table_names(conn) -> set:
    cur = conn.cursor()
    return {row[0] for row in cur.execute("select name from sqlite_master where type='table'").fetchall()}


def _sqlite_table_columns(conn, table_name: str) -> List[str]:
    cur = conn.cursor()
    return [row[1] for row in cur.execute(f'PRAGMA table_info("{table_name}")').fetchall()]


def _copy_sqlite_table_rows(source_conn, target_conn, table_name: str) -> int:
    source_columns = _sqlite_table_columns(source_conn, table_name)
    target_columns = _sqlite_table_columns(target_conn, table_name)
    common_columns = [column for column in source_columns if column in target_columns]
    if not common_columns:
        return 0

    quoted_columns = ", ".join(f'"{column}"' for column in common_columns)
    placeholders = ", ".join("?" for _ in common_columns)
    rows = source_conn.execute(f'SELECT {quoted_columns} FROM "{table_name}"').fetchall()
    if not rows:
        return 0

    before_changes = target_conn.total_changes
    target_conn.executemany(
        f'INSERT OR IGNORE INTO "{table_name}" ({quoted_columns}) VALUES ({placeholders})',
        rows,
    )
    return target_conn.total_changes - before_changes


def _migrate_legacy_business_tables():
    legacy_path = os.path.abspath(os.path.expandvars(LEGACY_DB_FILE_PATH or ""))
    target_path = _current_sqlite_db_path()
    if not legacy_path or not os.path.exists(legacy_path):
        return
    if not target_path or os.path.abspath(target_path) == legacy_path:
        return

    marker = f"v1:{legacy_path}:{os.path.getmtime(legacy_path)}"
    state = AlertMigrationState.query.filter_by(key="legacy_temp_business_tables_v1").first()
    if state and state.value == marker:
        return

    db.session.commit()
    source_conn = _connect_sqlite(legacy_path, read_only=True)
    target_conn = _connect_sqlite(target_path)
    copied = {}
    failed_tables = []

    try:
        source_tables = _sqlite_table_names(source_conn)
        target_tables = _sqlite_table_names(target_conn)

        for table_name in LEGACY_BUSINESS_TABLE_ORDER:
            if table_name not in source_tables or table_name not in target_tables:
                continue
            try:
                inserted_rows = _copy_sqlite_table_rows(source_conn, target_conn, table_name)
                target_conn.commit()
                if inserted_rows:
                    copied[table_name] = inserted_rows
            except Exception as exc:
                target_conn.rollback()
                failed_tables.append(table_name)
                current_app.logger.warning("copy legacy table %s failed: %s", table_name, exc)
    finally:
        source_conn.close()
        target_conn.close()

    db.session.expire_all()
    if failed_tables:
        current_app.logger.warning("legacy business table sync incomplete, will retry later: %s", failed_tables)
        return

    _upsert_migration_state("legacy_temp_business_tables_v1", marker)
    if copied:
        current_app.logger.info("legacy business tables synced from %s: %s", legacy_path, copied)


def _migrate_from_legacy_temp_db():
    legacy_path = os.path.abspath(os.path.expandvars(LEGACY_DB_FILE_PATH or ""))
    if not legacy_path or not os.path.exists(legacy_path):
        return

    state = AlertMigrationState.query.filter_by(key="legacy_temp_db_migrated").first()
    marker = f"{legacy_path}:{os.path.getmtime(legacy_path)}"
    if state and state.value == marker:
        return

    conn = _connect_sqlite(legacy_path, read_only=True, row_factory=sqlite3.Row)
    try:
        cur = conn.cursor()
        table_names = {row[0] for row in cur.execute("select name from sqlite_master where type='table'").fetchall()}

        if "FileAlertInfo" in table_names:
            rows = cur.execute("select * from FileAlertInfo order by trigger_time asc").fetchall()
            for row in rows:
                if FileAlertInfo.query.filter_by(id=row["id"]).first():
                    continue
                db.session.add(
                    FileAlertInfo(
                        id=row["id"],
                        trigger_time=_ensure_bj(datetime.fromisoformat(row["trigger_time"])),
                        alert_message=row["alert_message"],
                        report_ip=row["report_ip"],
                        report_agent=row["report_agent"],
                        token=row["token"],
                    )
                )

        if "account_alert_info" in table_names:
            rows = cur.execute("select * from account_alert_info order by trigger_time asc").fetchall()
            for row in rows:
                if AccountAlertInfo.query.filter_by(id=row["id"]).first():
                    continue
                db.session.add(
                    AccountAlertInfo(
                        id=row["id"],
                        trigger_time=_ensure_bj(datetime.fromisoformat(row["trigger_time"])),
                        report_time=_ensure_bj(datetime.fromisoformat(row["report_time"])) if row["report_time"] else None,
                        src_ip=row["src_ip"],
                        src_port=row["src_port"],
                        dst_ip=row["dst_ip"],
                        dst_port=row["dst_port"],
                        username=row["username"],
                        password=row["password"],
                        client_version=row["client_version"],
                        protocol=row["protocol"],
                        message=row["message"],
                        raw_event=_json_obj(row["raw_event"]),
                    )
                )

        if "url_alert_info" in table_names:
            rows = cur.execute("select * from url_alert_info order by trigger_time asc").fetchall()
            for row in rows:
                if UrlAlertInfo.query.filter_by(id=row["id"]).first():
                    continue
                db.session.add(
                    UrlAlertInfo(
                        id=row["id"],
                        honeypoint_id=row["honeypoint_id"],
                        url=row["url"],
                        trigger_time=_ensure_bj(datetime.fromisoformat(row["trigger_time"])),
                        report_time=_ensure_bj(datetime.fromisoformat(row["report_time"])) if row["report_time"] else None,
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        fingerprint=row["fingerprint"],
                        info=_json_obj(row["info"]),
                    )
                )

        if "LastQueryTime" in table_names:
            rows = cur.execute("select * from LastQueryTime").fetchall()
            for row in rows:
                existing = LastQueryTime.query.filter_by(query_type=row["query_type"]).first()
                value = _ensure_bj(datetime.fromisoformat(row["query_time"]))
                if existing is None:
                    db.session.add(LastQueryTime(query_type=row["query_type"], query_time=value))
                elif existing.query_time < value:
                    existing.query_time = value

        db.session.flush()
        _upsert_migration_state("legacy_temp_db_migrated", marker)
    finally:
        conn.close()


def _find_or_create_raw_event(source_service: str, source_event_id: str, payload) -> AlertRawEvent:
    payload_text = _json_text(payload)
    raw = None
    if source_event_id:
        raw = AlertRawEvent.query.filter_by(source_service=source_service, source_event_id=source_event_id).first()
    if raw is None:
        raw = AlertRawEvent(source_service=source_service, source_event_id=source_event_id, payload_json=payload_text)
        db.session.add(raw)
        db.session.flush()
    else:
        raw.payload_json = payload_text
    return raw


def _create_or_update_event(
    *,
    alert_type: str,
    source_service: str,
    source_event_id: str,
    alert_time: datetime,
    src_ip: str,
    dst_ip: str,
    severity: str,
    title: str,
    summary: str,
    dedupe_key: str,
    raw_payload,
    legacy_table: Optional[str] = None,
    legacy_row_id: Optional[int] = None,
    honeypot_id: Optional[int] = None,
    honeypot_name: Optional[str] = None,
):
    event = UnifiedAlertEvent.query.filter_by(dedupe_key=dedupe_key).first()
    raw = _find_or_create_raw_event(source_service, source_event_id, raw_payload)
    if event is None:
        event = UnifiedAlertEvent(
            alert_type=alert_type,
            source_service=source_service,
            source_event_id=source_event_id,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            alert_time=_ensure_bj(alert_time),
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity=severity,
            status="new",
            title=title,
            summary=summary,
            raw_event_id=raw.id,
            dedupe_key=dedupe_key,
            legacy_table=legacy_table,
            legacy_row_id=legacy_row_id,
        )
        db.session.add(event)
        db.session.flush()
    else:
        event.alert_time = _ensure_bj(alert_time)
        event.src_ip = src_ip
        event.dst_ip = dst_ip
        event.severity = severity
        event.title = title
        event.summary = summary
        event.raw_event_id = raw.id
        if honeypot_id is not None:
            event.honeypot_id = honeypot_id
        if honeypot_name:
            event.honeypot_name = honeypot_name
        if legacy_table:
            event.legacy_table = legacy_table
        if legacy_row_id:
            event.legacy_row_id = legacy_row_id
    return event


def ingest_file_alert(*, source_service: str, source_event_id: str, trigger_time: datetime, token_url: str, message: str, report_ip: str, report_agent: str, raw_payload, legacy_row_id: Optional[int] = None) -> UnifiedAlertEvent:
    trigger_time_bj = _ensure_bj(trigger_time)
    token_raw = _normalize_file_token(token_url)
    meta = _lookup_honeyfile_meta(token_raw)
    dedupe_key = f"file|{_file_alert_logical_key(token_url, report_ip, report_agent, message)}|{_file_alert_bucket(trigger_time)}"
    title = message or "文件蜜点告警"
    summary = f"文件蜜点触发: {meta.get('filename') or '-'} / {report_ip or '-'}"
    event = _create_or_update_event(
        alert_type="file",
        source_service=source_service,
        source_event_id=source_event_id,
        alert_time=trigger_time_bj,
        src_ip=report_ip,
        dst_ip="",
        severity="high",
        title=title,
        summary=summary,
        dedupe_key=dedupe_key,
        raw_payload=raw_payload,
        legacy_table="FileAlertInfo" if legacy_row_id else None,
        legacy_row_id=legacy_row_id,
        honeypot_id=meta.get("honeypot_id"),
        honeypot_name=meta.get("honeypot_name"),
    )

    detail = event.file_detail or FileAlertDetail(alert_id=event.id)
    existing_raw_ids = []
    if detail.raw_alert_ids_json:
        try:
            existing_raw_ids = json.loads(detail.raw_alert_ids_json)
        except Exception:
            existing_raw_ids = []
    if legacy_row_id and legacy_row_id not in existing_raw_ids:
        existing_raw_ids.append(legacy_row_id)

    count = max(detail.open_count or 1, len(existing_raw_ids) or 1)
    first_time = _ensure_bj(detail.first_alert_time) if detail.first_alert_time else trigger_time_bj
    last_time = _ensure_bj(detail.last_alert_time) if detail.last_alert_time else trigger_time_bj
    if trigger_time_bj < first_time:
        first_time = trigger_time_bj
    if trigger_time_bj > last_time:
        last_time = trigger_time_bj

    detail.token = token_raw
    detail.token_url = token_url
    detail.filename = meta.get("filename")
    detail.filename_tag = meta.get("filename_tag")
    detail.honeypoint_name = meta.get("honeypoint_name")
    detail.deploy_path = meta.get("deploy_path")
    detail.deployment_summary = meta.get("deployment_summary")
    detail.report_agent = report_agent
    detail.message = message
    detail.open_count = count
    detail.first_alert_time = first_time
    detail.last_alert_time = last_time
    detail.raw_alert_ids_json = json.dumps(existing_raw_ids, ensure_ascii=False)
    detail.deployments_json = json.dumps(meta.get("deployments") or [], ensure_ascii=False)
    db.session.add(detail)
    return event


def ingest_account_alert(*, source_service: str, source_event_id: str, trigger_time: datetime, src_ip: str, src_port: str, dst_ip: str, dst_port: str, username: str, password: str, client_version: str, protocol: str, message: str, raw_payload, legacy_row_id: Optional[int] = None) -> UnifiedAlertEvent:
    attack_type = _infer_account_attack_type(protocol, message, client_version, raw_payload)
    dedupe_key = "account|" + _account_dedupe_key(src_ip, dst_ip, username, protocol, message, trigger_time)
    title = attack_type
    summary = f"{_format_endpoint(src_ip, src_port)} -> {_format_endpoint(dst_ip, dst_port)} / {username or '-'}"
    event = _create_or_update_event(
        alert_type="account",
        source_service=source_service,
        source_event_id=source_event_id,
        alert_time=trigger_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        severity="high" if "密码" in attack_type or "公钥" in attack_type else "medium",
        title=title,
        summary=summary,
        dedupe_key=dedupe_key,
        raw_payload=raw_payload,
        legacy_table="account_alert_info" if legacy_row_id else None,
        legacy_row_id=legacy_row_id,
        honeypot_name="账户蜜点",
    )

    detail = event.account_detail or AccountAlertDetail(alert_id=event.id)
    detail.protocol = protocol
    detail.username = username
    detail.password = password
    detail.src_port = src_port
    detail.dst_port = dst_port
    detail.client_version = client_version
    detail.client_family = _classify_ssh_client(client_version)
    detail.auth_type = attack_type
    detail.message = message
    detail.raw_event_json = _json_text(raw_payload)
    db.session.add(detail)
    return event


def ingest_parasitic_alert(*, source_service: str, source_event_id: str, trigger_time: datetime, src_ip: str, dst_ip: str, url: str, fingerprint: str, info_payload, raw_payload, legacy_row_id: Optional[int] = None) -> UnifiedAlertEvent:
    info = _json_obj(info_payload)
    session_token = info.get("sessionToken") or info.get("session_token") or ""
    browser = info.get("browser") or info.get("Browser") or info.get("browserName") or "-"
    os_name = info.get("os") or info.get("OS") or info.get("osName") or "-"
    browser_platform = info.get("platform") or info.get("navigatorPlatform") or "-"
    user_agent = info.get("userAgent") or info.get("ua") or "-"
    bot_score = info.get("botScore") or info.get("bot_score") or info.get("score") or 0
    proxy_headers = info.get("proxy_headers") or {}
    xff, forwarded, via = _normalize_proxy_fields(
        info.get("x_forwarded_for") or proxy_headers.get("x_forwarded_for"),
        info.get("forwarded") or proxy_headers.get("forwarded"),
        info.get("via") or proxy_headers.get("via"),
    )
    proxy_detect_result = str(info.get("ProxyDetectResult") or info.get("proxy_detect_result") or "").strip().lower()
    possible_proxy = _resolve_possible_proxy(info.get("possible_proxy"), proxy_detect_result, xff, forwarded, via)
    dedupe_key = "parasitic|" + _parasitic_logical_key(src_ip, url, fingerprint, session_token, trigger_time)
    title = "寄生蜜点访问"
    summary = f"{src_ip or '-'} 访问 {url or '-'} / fingerprint={fingerprint or '-'}"
    event = _create_or_update_event(
        alert_type="parasitic",
        source_service=source_service,
        source_event_id=source_event_id,
        alert_time=trigger_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        severity="medium",
        title=title,
        summary=summary,
        dedupe_key=dedupe_key,
        raw_payload=raw_payload,
        legacy_table="url_alert_info" if legacy_row_id else None,
        legacy_row_id=legacy_row_id,
        honeypot_name="寄生蜜点",
    )

    detail = event.parasitic_detail or ParasiticAlertDetail(alert_id=event.id)
    detail.url = url
    detail.fingerprint = fingerprint
    detail.session_token = session_token
    detail.browser = browser
    detail.os = os_name
    detail.browser_platform = browser_platform
    detail.user_agent = user_agent
    detail.real_ips_json = json.dumps(
        info.get("IPs") or info.get("ips") or info.get("real_ips") or info.get("webrtc_ips") or ([dst_ip] if dst_ip else []),
        ensure_ascii=False,
    )
    try:
        detail.bot_score = int(bot_score)
    except Exception:
        detail.bot_score = 0
    detail.is_bot = bool(info.get("is_bot") or info.get("isBot"))
    detail.proxy_detect_result = proxy_detect_result
    detail.possible_proxy = possible_proxy
    detail.x_forwarded_for = xff
    detail.forwarded = forwarded
    detail.via = via
    detail.reason = info.get("reason") or info.get("source") or "-"
    detail.proxy_note = info.get("proxy_note") or "若代理未写入 X-Forwarded-For/Via/Forwarded，服务端只能看到代理出口 IP。"
    detail.detail_json = _json_text(info)
    db.session.add(detail)
    return event


def _backfill_file_alerts():
    rows = FileAlertInfo.query.order_by(FileAlertInfo.trigger_time.asc(), FileAlertInfo.id.asc()).all()
    for row in rows:
        ingest_file_alert(
            source_service="alert_server",
            source_event_id=f"legacy-file-{row.id}",
            trigger_time=row.trigger_time,
            token_url=row.token,
            message=row.alert_message,
            report_ip=row.report_ip,
            report_agent=row.report_agent,
            raw_payload=row.to_json(),
            legacy_row_id=row.id,
        )
    db.session.flush()


def _backfill_account_alerts():
    rows = AccountAlertInfo.query.order_by(AccountAlertInfo.trigger_time.asc(), AccountAlertInfo.id.asc()).all()
    for row in rows:
        ingest_account_alert(
            source_service="alert_server",
            source_event_id=f"legacy-account-{row.id}",
            trigger_time=row.trigger_time,
            src_ip=row.src_ip,
            src_port=row.src_port,
            dst_ip=row.dst_ip,
            dst_port=row.dst_port,
            username=row.username,
            password=row.password,
            client_version=row.client_version,
            protocol=row.protocol,
            message=row.message,
            raw_payload=row.raw_event,
            legacy_row_id=row.id,
        )
    db.session.flush()


def _is_official_parasitic_info(info: Dict) -> bool:
    source = str(info.get("source") or info.get("ingest_source") or "").strip().lower()
    return source in ("js/bot", "js_bot", "systemwire2_pull_js_bot")


def _backfill_parasitic_alerts():
    rows = UrlAlertInfo.query.order_by(UrlAlertInfo.trigger_time.asc(), UrlAlertInfo.id.asc()).all()
    for row in rows:
        info = _json_obj(row.info)
        if not _is_official_parasitic_info(info):
            continue
        ingest_parasitic_alert(
            source_service="alert_server",
            source_event_id=f"legacy-parasitic-{row.id}",
            trigger_time=row.trigger_time,
            src_ip=row.src_ip,
            dst_ip=row.dst_ip,
            url=row.url,
            fingerprint=row.fingerprint,
            info_payload=info,
            raw_payload=row.to_json(),
            legacy_row_id=row.id,
        )
    db.session.flush()


def _refresh_file_alert_metadata():
    events = (
        UnifiedAlertEvent.query.filter_by(alert_type="file")
        .order_by(UnifiedAlertEvent.id.asc())
        .all()
    )
    for event in events:
        detail = event.file_detail
        if detail is None:
            continue

        token_raw = (detail.token or "").strip() or _normalize_file_token(detail.token_url or "")
        if not token_raw:
            continue

        meta = _lookup_honeyfile_meta(token_raw)
        if meta.get("honeypot_id") is None and meta.get("filename") == "-":
            continue

        detail.token = token_raw
        detail.filename = meta.get("filename")
        detail.filename_tag = meta.get("filename_tag")
        detail.honeypoint_name = meta.get("honeypoint_name")
        detail.deploy_path = meta.get("deploy_path")
        detail.deployment_summary = meta.get("deployment_summary")
        detail.deployments_json = json.dumps(meta.get("deployments") or [], ensure_ascii=False)

        if meta.get("honeypot_id") is not None:
            event.honeypot_id = meta.get("honeypot_id")
        if meta.get("honeypot_name"):
            event.honeypot_name = meta.get("honeypot_name")

        db.session.add(detail)
        db.session.add(event)


def refresh_file_alert_metadata():
    _refresh_file_alert_metadata()


def get_unified_alert_events(hours: int = 24, alert_type: Optional[str] = None) -> List[UnifiedAlertEvent]:
    query = UnifiedAlertEvent.query.order_by(UnifiedAlertEvent.alert_time.desc(), UnifiedAlertEvent.id.desc())
    if alert_type:
        query = query.filter(UnifiedAlertEvent.alert_type == alert_type)
    if hours and hours > 0:
        threshold = datetime.now(beijing_tz) - timedelta(hours=hours)
        query = query.filter(UnifiedAlertEvent.alert_time >= threshold)
    return query.all()


def _json_list(value) -> List:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            if parsed in (None, ""):
                return []
            return [parsed]
        except Exception:
            return [text]
    return [value]


def _format_time_text(value: Optional[datetime]) -> str:
    if not value:
        return ""
    try:
        return _ensure_bj(value).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _normalize_reason_list(value) -> List[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _file_page_query(days: int):
    query = UnifiedAlertEvent.query.filter_by(alert_type="file")
    if days and days > 0:
        threshold = datetime.now(beijing_tz) - timedelta(days=days)
        query = query.filter(UnifiedAlertEvent.alert_time >= threshold)
    return query.order_by(UnifiedAlertEvent.alert_time.desc(), UnifiedAlertEvent.id.desc())


def _account_page_query(days: int):
    query = UnifiedAlertEvent.query.filter_by(alert_type="account")
    if days and days > 0:
        threshold = datetime.now(beijing_tz) - timedelta(days=days)
        query = query.filter(UnifiedAlertEvent.alert_time >= threshold)
    return query.order_by(UnifiedAlertEvent.alert_time.desc(), UnifiedAlertEvent.id.desc())


def _parasitic_query(hours: int = 0, target_filter: str = ""):
    query = (
        UnifiedAlertEvent.query.join(
            ParasiticAlertDetail,
            ParasiticAlertDetail.alert_id == UnifiedAlertEvent.id,
        )
        .filter(UnifiedAlertEvent.alert_type == "parasitic")
    )
    if hours and hours > 0:
        threshold = datetime.now(beijing_tz) - timedelta(hours=hours)
        query = query.filter(UnifiedAlertEvent.alert_time >= threshold)
    if target_filter:
        query = query.filter(ParasiticAlertDetail.url == target_filter)
    return query.order_by(UnifiedAlertEvent.alert_time.desc(), UnifiedAlertEvent.id.desc())


def get_file_alert_page_rows(days: int = 7) -> Tuple[List[Dict], int]:
    alert_infos: List[Dict] = []
    raw_alert_total = 0

    for event in _file_page_query(days).all():
        detail = event.file_detail
        raw_ids = [item for item in _json_list(detail.raw_alert_ids_json if detail else None) if item not in (None, "")]
        deployments = _json_list(detail.deployments_json if detail else None)
        request_count = int(detail.open_count or 0) if detail else 0
        if request_count <= 0:
            request_count = len(raw_ids) or 1
        raw_alert_total += request_count

        first_time = detail.first_alert_time if detail and detail.first_alert_time else event.alert_time
        last_time = detail.last_alert_time if detail and detail.last_alert_time else event.alert_time
        display_id = raw_ids[-1] if raw_ids else (event.legacy_row_id or event.id)

        alert_infos.append(
            {
                "id": display_id,
                "unified_event_id": event.id,
                "alert_time": _format_time_text(last_time),
                "first_alert_time": _format_time_text(first_time),
                "last_alert_time": _format_time_text(last_time),
                "request_count": request_count,
                "raw_ids": raw_ids or [display_id],
                "raw_ids_text": ", ".join(str(item) for item in (raw_ids or [display_id])),
                "alert_message": (detail.message if detail else "") or event.title or "-",
                "token": (detail.token_url if detail else "") or (detail.token if detail else "") or "-",
                "token_raw": (detail.token if detail else "") or _normalize_file_token((detail.token_url if detail else "") or ""),
                "reportIp": event.src_ip or "-",
                "reportAgent": (detail.report_agent if detail else "") or "-",
                "filename": (detail.filename if detail else "") or "-",
                "filename_tag": (detail.filename_tag if detail else "") or "-",
                "honeypoint_name": (detail.honeypoint_name if detail else "") or event.honeypot_name or "-",
                "deployment_summary": (detail.deployment_summary if detail else "") or "-",
                "deployments": deployments,
                "source": event.source_service or "systemwire2",
            }
        )

    return alert_infos, raw_alert_total


def get_account_alert_page_rows(days: int = 7) -> List[Dict]:
    alert_infos: List[Dict] = []

    for event in _account_page_query(days).all():
        detail = event.account_detail
        raw_event = _json_obj(detail.raw_event_json if detail else None)
        attack_type = (detail.auth_type if detail else "") or event.title or "账户蜜点告警"
        client_version = (detail.client_version if detail else "") or ""
        protocol = (detail.protocol if detail else "") or "ssh"

        alert_infos.append(
            {
                "id": event.legacy_row_id or event.id,
                "unified_event_id": event.id,
                "alert_time": _format_time_text(event.alert_time),
                "trigger_time": event.alert_time,
                "src_ip": event.src_ip or "",
                "src_port": (detail.src_port if detail else "") or "",
                "dst_ip": event.dst_ip or "",
                "dst_port": (detail.dst_port if detail else "") or "",
                "src_endpoint": _format_endpoint(event.src_ip, detail.src_port if detail else ""),
                "dst_endpoint": _format_endpoint(event.dst_ip, detail.dst_port if detail else ""),
                "username": (detail.username if detail else "") or "",
                "password": (detail.password if detail else "") or "",
                "client_version": client_version,
                "client_family": (detail.client_family if detail else "") or _classify_ssh_client(client_version),
                "protocol": protocol,
                "attack_type": attack_type,
                "message": (detail.message if detail else "") or event.summary or event.title or "",
                "raw_event": raw_event,
                "raw_event_json": json.dumps(raw_event or {}, ensure_ascii=False, indent=2),
            }
        )

    return alert_infos


def build_unified_alert_api_rows(hours: int = 24, alert_type: Optional[str] = None) -> List[Dict]:
    alert_rows: List[Dict] = []

    for event in get_unified_alert_events(hours=hours, alert_type=alert_type):
        if event.alert_type == "file":
            detail = event.file_detail
            raw_ids = [item for item in _json_list(detail.raw_alert_ids_json if detail else None) if item not in (None, "")]
            deployments = _json_list(detail.deployments_json if detail else None)
            request_count = int(detail.open_count or 0) if detail else 0
            if request_count <= 0:
                request_count = len(raw_ids) or 1
            first_time = detail.first_alert_time if detail and detail.first_alert_time else event.alert_time
            last_time = detail.last_alert_time if detail and detail.last_alert_time else event.alert_time
            alert_rows.append(
                {
                    "alert_id": f"file_{event.id}",
                    "alert_type": "file",
                    "timestamp": _ensure_bj(last_time).isoformat() if last_time else None,
                    "attacker_ip": event.src_ip,
                    "target_path": (detail.token_url if detail else "") or (detail.token if detail else "") or "",
                    "action": "文件打开触发",
                    "severity": event.severity,
                    "details": {
                        "message": (detail.message if detail else "") or event.title or "-",
                        "report_agent": (detail.report_agent if detail else "") or "-",
                        "token_url": (detail.token_url if detail else "") or "",
                        "token_raw": (detail.token if detail else "") or _normalize_file_token((detail.token_url if detail else "") or ""),
                        "filename": (detail.filename if detail else "") or "-",
                        "filename_tag": (detail.filename_tag if detail else "") or "-",
                        "honeypoint_name": (detail.honeypoint_name if detail else "") or event.honeypot_name or "-",
                        "deployment_summary": (detail.deployment_summary if detail else "") or "-",
                        "deployments": deployments,
                        "request_count": request_count,
                        "raw_alert_ids": raw_ids or ([event.legacy_row_id] if event.legacy_row_id else []),
                        "first_trigger_time": _ensure_bj(first_time).isoformat() if first_time else None,
                        "last_trigger_time": _ensure_bj(last_time).isoformat() if last_time else None,
                        "logical_window_seconds": FILE_ALERT_LOGICAL_WINDOW_SECONDS,
                        "source": event.source_service or "systemwire2",
                    },
                }
            )
            continue

        if event.alert_type == "account":
            detail = event.account_detail
            raw_event = _json_obj(detail.raw_event_json if detail else None)
            protocol = (detail.protocol if detail else "") or "ssh"
            attack_type = (detail.auth_type if detail else "") or event.title or "账户蜜点告警"
            alert_rows.append(
                {
                    "alert_id": f"account_{event.id}",
                    "alert_type": "account",
                    "timestamp": _ensure_bj(event.alert_time).isoformat() if event.alert_time else None,
                    "attacker_ip": event.src_ip,
                    "target_path": event.dst_ip or "",
                    "action": attack_type,
                    "severity": event.severity,
                    "details": {
                        "username": (detail.username if detail else "") or "",
                        "password": (detail.password if detail else "") or "",
                        "src_port": (detail.src_port if detail else "") or "",
                        "dst_port": (detail.dst_port if detail else "") or "",
                        "src_endpoint": _format_endpoint(event.src_ip, detail.src_port if detail else ""),
                        "dst_endpoint": _format_endpoint(event.dst_ip, detail.dst_port if detail else ""),
                        "client_version": (detail.client_version if detail else "") or "",
                        "client_family": (detail.client_family if detail else "") or _classify_ssh_client(detail.client_version if detail else ""),
                        "protocol": protocol,
                        "attack_type": attack_type,
                        "message": (detail.message if detail else "") or event.summary or event.title or "",
                        "raw_event": raw_event,
                    },
                }
            )
            continue

        if event.alert_type == "parasitic":
            detail = event.parasitic_detail
            info = _json_obj(detail.detail_json if detail else None)
            if detail and detail.url and "path" not in info:
                info["path"] = detail.url
            if detail and detail.reason and not info.get("reason"):
                info["reason"] = detail.reason
            if detail and detail.proxy_note and not info.get("proxy_note"):
                info["proxy_note"] = detail.proxy_note
            if detail and detail.bot_score is not None:
                info.setdefault("bot_score", detail.bot_score)
                info.setdefault("score", detail.bot_score)
            if detail and detail.is_bot:
                info.setdefault("is_bot", detail.is_bot)
            real_ips = [item for item in _json_list(detail.real_ips_json if detail else None) if item not in (None, "")]
            if not real_ips and event.dst_ip:
                real_ips = [event.dst_ip]
            xff, forwarded, via = _normalize_proxy_fields(
                (detail.x_forwarded_for if detail else "") or info.get("x_forwarded_for") or (info.get("proxy_headers") or {}).get("x_forwarded_for"),
                (detail.forwarded if detail else "") or info.get("forwarded") or (info.get("proxy_headers") or {}).get("forwarded"),
                (detail.via if detail else "") or info.get("via") or (info.get("proxy_headers") or {}).get("via"),
            )
            proxy_detect_result = (detail.proxy_detect_result if detail else "") or str(info.get("ProxyDetectResult") or info.get("proxy_detect_result") or "")
            possible_proxy = _resolve_possible_proxy(
                detail.possible_proxy if detail else None,
                proxy_detect_result,
                xff,
                forwarded,
                via,
            )
            browser = (detail.browser if detail else "") or info.get("browser") or info.get("Browser") or info.get("browserName") or "-"
            browser_platform = (detail.browser_platform if detail else "") or info.get("platform") or info.get("navigatorPlatform") or "-"
            alert_rows.append(
                {
                    "alert_id": f"parasitic_{event.id}",
                    "alert_type": "parasitic",
                    "timestamp": _ensure_bj(event.alert_time).isoformat() if event.alert_time else None,
                    "attacker_ip": event.src_ip,
                    "target_path": (detail.url if detail else "") or "",
                    "action": event.title or "url_access",
                    "severity": event.severity,
                    "details": {
                        "fingerprint": (detail.fingerprint if detail else "") or "",
                        "session_token": (detail.session_token if detail else "") or "",
                        "info": info,
                        "dst_ip": event.dst_ip or "",
                        "real_ips": real_ips,
                        "browser": browser,
                        "os": (detail.os if detail else "") or info.get("os") or info.get("OS") or info.get("osName") or "-",
                        "browser_platform": browser_platform,
                        "user_agent": (detail.user_agent if detail else "") or info.get("userAgent") or info.get("ua") or "-",
                        "bot_score": int(detail.bot_score or 0) if detail and detail.bot_score is not None else int(info.get("bot_score") or info.get("score") or 0),
                        "proxy_headers": info.get("proxy_headers") or {},
                        "x_forwarded_for": xff,
                        "forwarded": forwarded,
                        "via": via,
                        "proxy_detect_result": proxy_detect_result,
                        "possible_proxy": possible_proxy,
                        "proxy_note": (detail.proxy_note if detail else "") or info.get("proxy_note") or "若代理未写入 X-Forwarded-For/Via/Forwarded，服务端只能看到代理出口 IP。",
                        "test_info": f"fingerprint={(detail.fingerprint if detail else '') or '-'} session={(detail.session_token if detail else '') or '-'} browser={browser} platform={browser_platform}",
                        "group_id": info.get("group_id"),
                    },
                }
            )

    return alert_rows


def build_unified_alert_statistics(hours: int = 24) -> Dict:
    alerts = build_unified_alert_api_rows(hours=hours)
    stats = {
        "total": len(alerts),
        "by_type": {},
        "by_ip": {},
        "time_range": {
            "start": (datetime.now(beijing_tz) - timedelta(hours=hours)).isoformat() if hours and hours > 0 else None,
            "end": datetime.now(beijing_tz).isoformat(),
            "hours": hours,
        },
    }

    for alert in alerts:
        alert_type = alert.get("alert_type") or "unknown"
        attacker_ip = alert.get("attacker_ip")
        stats["by_type"][alert_type] = stats["by_type"].get(alert_type, 0) + 1
        if attacker_ip:
            stats["by_ip"][attacker_ip] = stats["by_ip"].get(attacker_ip, 0) + 1

    return stats


def build_parasitic_logs_payload(page: int, size: int, target_filter: str = "") -> Dict:
    query = _parasitic_query(target_filter=target_filter)
    total = query.count()
    events = query.offset((page - 1) * size).limit(size).all()
    data = []

    for event in events:
        detail = event.parasitic_detail
        info = _json_obj(detail.detail_json if detail else None)
        if detail and detail.url and "path" not in info:
            info["path"] = detail.url
        if detail and detail.reason and not info.get("reason"):
            info["reason"] = detail.reason
        if detail and detail.proxy_note and not info.get("proxy_note"):
            info["proxy_note"] = detail.proxy_note
        if detail and detail.bot_score is not None:
            info.setdefault("bot_score", detail.bot_score)
            info.setdefault("score", detail.bot_score)
        if detail and detail.is_bot:
            info.setdefault("is_bot", detail.is_bot)

        real_ips = [item for item in _json_list(detail.real_ips_json if detail else None) if item not in (None, "")]
        if not real_ips and event.dst_ip:
            real_ips = [event.dst_ip]

        xff, forwarded, via = _normalize_proxy_fields(
            (detail.x_forwarded_for if detail else "") or info.get("x_forwarded_for") or (info.get("proxy_headers") or {}).get("x_forwarded_for"),
            (detail.forwarded if detail else "") or info.get("forwarded") or (info.get("proxy_headers") or {}).get("forwarded"),
            (detail.via if detail else "") or info.get("via") or (info.get("proxy_headers") or {}).get("via"),
        )
        proxy_detect_result = (detail.proxy_detect_result if detail else "") or str(info.get("ProxyDetectResult") or info.get("proxy_detect_result") or "")
        possible_proxy = _resolve_possible_proxy(
            detail.possible_proxy if detail else None,
            proxy_detect_result,
            xff,
            forwarded,
            via,
        )

        data.append(
            {
                "id": event.id,
                "time": _ensure_bj(event.alert_time).isoformat() if event.alert_time else "",
                "RemoteIP": event.src_ip,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "IPs": real_ips,
                "ProxyDetectResult": "true" if possible_proxy else "false",
                "FingerprintData": json.dumps(info, ensure_ascii=False),
                "target": (detail.url if detail else "") or "",
                "url": (detail.url if detail else "") or "",
                "group_id": info.get("group_id") or event.id,
                "fingerprint": (detail.fingerprint if detail else "") or "",
                "score": int(detail.bot_score or 0) if detail and detail.bot_score is not None else int(info.get("bot_score") or info.get("score") or 0),
                "bot_score": int(detail.bot_score or 0) if detail and detail.bot_score is not None else int(info.get("bot_score") or info.get("score") or 0),
                "is_bot": bool((detail.is_bot if detail else False) or info.get("is_bot") or info.get("IsBot")),
                "isBot": bool((detail.is_bot if detail else False) or info.get("is_bot") or info.get("IsBot")),
                "reasons": _normalize_reason_list(info.get("bot_reasons") or info.get("reasons")),
                "info": info,
                "details": info,
                "x_forwarded_for": xff,
                "forwarded": forwarded,
                "via": via,
                "possible_proxy": possible_proxy,
            }
        )

    return {
        "code": 0,
        "message": "success",
        "data": data,
        "total": total,
    }


def build_parasitic_target_analysis(target: str) -> Dict:
    events = _parasitic_query(target_filter=target).all()
    attackers: List[str] = []

    for event in events:
        if event.src_ip and event.src_ip not in attackers:
            attackers.append(event.src_ip)

    return {
        "code": 0,
        "message": "Success",
        "target": target,
        "attackers": attackers,
        "count": len(attackers),
        "source": "systemwire2-alert-store",
    }
