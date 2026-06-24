import base64
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path

import requests

from config.config import FILE_ALERT_SERVER, MANAGE_ADDRESS
from flask_server.utils.common import Server_config


def _normalize_public_token_url(token_value):
    token = str(token_value or "").strip()
    if "/static/img/logo-" in token:
        token = token.rsplit("/static/img/logo-", 1)[-1]
        if token.endswith(".png"):
            token = token[:-4]
    if "/contact/" in token:
        token = token.rsplit("/contact/", 1)[-1]
    token = token.strip("/")
    if not token:
        return ""
    base = (
        getattr(Server_config, "file_alert_server_address", "")
        or FILE_ALERT_SERVER
        or MANAGE_ADDRESS
    )
    return f"{str(base).rstrip('/')}/static/img/logo-{token}.png"


def _repo_root_path(*parts):
    return Path(__file__).resolve().parents[3].joinpath(*parts)


def _build_local_token(mail_addr, alert_msg):
    payload = f"{str(mail_addr or '')}{str(alert_msg or '')}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _alert_server_token_db_path():
    return _repo_root_path("alert_server", "data", "token.db")


def _ensure_local_token_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS token_infos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME,
            updated_at DATETIME,
            deleted_at DATETIME,
            token TEXT,
            alert_addr TEXT,
            alert_msg TEXT,
            company_id INTEGER DEFAULT 1
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_token_infos_token ON token_infos(token)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_token_infos_deleted_at ON token_infos(deleted_at)"
    )


def _register_token_locally(mail_addr, alert_msg):
    token = _build_local_token(mail_addr, alert_msg)
    token_url = _normalize_public_token_url(token)
    return _register_token_value_locally(token, mail_addr, alert_msg), token_url


def _register_token_value_locally(token, mail_addr, alert_msg):
    db_path = _alert_server_token_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    now_text = datetime.now().isoformat(sep=" ", timespec="seconds")

    conn = sqlite3.connect(str(db_path), timeout=5)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        _ensure_local_token_table(conn)
        row = conn.execute(
            """
            SELECT id, deleted_at
            FROM token_infos
            WHERE token = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (token,),
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE token_infos
                SET deleted_at = NULL,
                    updated_at = ?,
                    alert_addr = ?,
                    alert_msg = ?,
                    company_id = 1
                WHERE id = ?
                """,
                (now_text, mail_addr, alert_msg, row[0]),
            )
            conn.commit()
            return 0

        conn.execute(
            """
            INSERT INTO token_infos (
                created_at,
                updated_at,
                deleted_at,
                token,
                alert_addr,
                alert_msg,
                company_id
            )
            VALUES (?, ?, NULL, ?, ?, ?, 1)
            """,
            (now_text, now_text, token, mail_addr, alert_msg),
        )
        conn.commit()
        return 0
    finally:
        conn.close()


def _fallback_local_token(mail_addr, alert_msg, remote_reason):
    try:
        err, token_url = _register_token_locally(mail_addr, alert_msg)
        if err:
            return 1, f"{remote_reason}; local fallback failed"
        return 0, token_url
    except Exception as exc:
        return 1, f"{remote_reason}; local fallback failed: {exc}"


def getToken(maillAddr, msg):
    url = MANAGE_ADDRESS + "/token"
    json_data = {
        "mail_addr": maillAddr,
        "alert_msg": msg,
    }
    headers = {
        "Authorization": f"{Server_config.api_key}"
    }

    try:
        response = requests.post(
            url,
            json=json_data,
            headers=headers,
            verify=False,
            timeout=3,
        )
    except requests.RequestException as exc:
        return _fallback_local_token(maillAddr, msg, f"Get token request failed: {exc}")

    if response.status_code != 200:
        err_msg = f"Get token error. Status code:{response.status_code} message:{response.text}"
        return _fallback_local_token(maillAddr, msg, err_msg)

    try:
        payload = response.json()
    except ValueError as exc:
        return _fallback_local_token(maillAddr, msg, f"Get token decode error: {exc}")

    if payload.get("code") != 0:
        err_msg = f"Get token error, message:{payload.get('message')}"
        return _fallback_local_token(maillAddr, msg, err_msg)

    token_url = _normalize_public_token_url(payload.get("token")) or payload.get("token")
    token = token_url.rsplit("/static/img/logo-", 1)[-1] if "/static/img/logo-" in str(token_url) else str(token_url)
    if token.endswith(".png"):
        token = token[:-4]
    try:
        _register_token_value_locally(token.strip("/"), maillAddr, msg)
    except Exception:
        pass
    return 0, token_url


if __name__ == "__main__":
    email = "1026883034@qq.com"
    alert_msg = "test_msg"
    getToken(email, alert_msg)
