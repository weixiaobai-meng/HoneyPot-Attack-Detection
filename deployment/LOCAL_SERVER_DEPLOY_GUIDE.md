# Local + Server Deployment Guide

This guide is aligned with the current runnable code paths in this repo.

## 1) What is verified as working on this machine

Verified on **2026-05-31** with real command dispatch:

- `systemwire2` web + gRPC:
  - web: `http://127.0.0.1:5001`
  - gRPC: `127.0.0.1:50051`
- `agent-go` connected as:
  - `agent_id = localprobe01`
- `js/latest/bot`:
  - `http://127.0.0.1:8080`
- `alert_server`:
  - public: `127.0.0.1:9090`
  - admin: `127.0.0.1:9091`

Functional checks already passed:

- Account honeypot deployment (`cmd_type=4`) creates files under:
  - `agent-go/runtime_artifacts/account_deploy/`
- File honeypot deployment (`cmd_type=6`) writes into probe-side directories.
- Parasitic honeypot deployment (`cmd_type=7`) injects into HTML files.
- Unified alerts API returns both `audit` and `parasitic` records.

## 2) One-click local run (new scripts)

From repo root (`D:\研究生毕设`):

```powershell
powershell -ExecutionPolicy Bypass -File deployment/scripts/start_local_env.ps1
powershell -ExecutionPolicy Bypass -File deployment/scripts/check_local_env.ps1
```

Stop all:

```powershell
powershell -ExecutionPolicy Bypass -File deployment/scripts/stop_local_env.ps1
```

## 3) Required config files

### 3.1 `systemwire2`

- Active file: `systemwire2/config/config.py`
- Local sample: `systemwire2/config/config.local.py.example`
- Server sample: `systemwire2/config/config.server.py.example`

Key fields:

- `FLASK_PORT` (web)
- `GRPC_PORT` (agent control)
- `FILE_ALERT_SERVER` (`alert_server` public endpoint)
- `MANAGE_ADDRESS` (`alert_server` admin endpoint)
- `LOCAL_API_BYPASS_AUTH`
  - local lab can be `True`
  - server deployment should be `False`

### 3.2 `agent-go`

- Active file: `agent-go/config/config.ini`
- Local sample: `agent-go/config/config.local.ini.example`
- Server sample: `agent-go/config/config.server.ini.example`

Key fields:

- `ServerAddress` must point to management node `:50051`
- `Token` must match probe token in `systemwire2`

### 3.3 `alert_server`

- Active file: `alert_server/config/config.ini`
- Local sample: `alert_server/config/config.local.ini.example`
- Server sample: `alert_server/config/config.server.ini.example`

Key fields:

- `public_ip/public_port` (trigger endpoint)
- `local_port` (admin endpoint)
- `api-key` (must match `systemwire2 API_KEY`)

## 4) Frontend parameter examples (copy-and-fill)

All examples below match current backend validation and agent implementation.

### 4.1 Account honeypot page (`/manage/honeypot/account`)

#### Local test example

- Agent: `localprobe01`
- Type: `xshell`
- Host: `127.0.0.1`
- Port: `22`
- Username: `admin`
- Password: `Admin@2024`

Backend payload equivalent:

```json
{
  "agent_id": "localprobe01",
  "cmd_type": 4,
  "cmd_data": "xshell:127.0.0.1:22:admin:Admin@2024"
}
```

#### Server deployment example

- Agent: `probe-sh-01`
- Type: `finalshell`
- Host: `10.10.30.21`
- Port: `22`
- Username: `opsadmin`
- Password: `Ops@2026!`

### 4.2 File honeypot page (`/manage/honeypot/file`)

#### Local test example

- Agent: `localprobe01`
- File ID: `1` (existing honeyfile)
- Deploy paths (recommended ASCII relative paths):
  - `tmp_output/file_drop_a`
  - `tmp_output/file_drop_b`
- Monitor: checked

Backend payload equivalent:

```json
{
  "agent_id": "localprobe01",
  "cmd_type": 6,
  "cmd_data": "{\"file_id\":1,\"filename\":\"demo.docx\",\"download_url\":\"http://127.0.0.1:5001/api/agent/file/download/1\",\"deploy_paths\":[\"tmp_output/file_drop_a\",\"tmp_output/file_drop_b\"],\"monitor\":true}"
}
```

#### Server deployment example

- Agent: `probe-bj-01`
- File ID: `12`
- Deploy paths:
  - `/home/security/share/docs`
  - `/data/ops/dropbox`
- Monitor: checked
- Download URL:
  - `http://10.10.10.10:5001/api/agent/file/download/12`

### 4.3 Parasitic honeypot page (`/manage/honeypot/parasitic`)

#### Local test example

- Agent: `localprobe01`
- Target directory: `tmp_output/parasitic_webroot`
- JS source: URL mode
- JS URL: `tmp_output/parasitic_webroot/inject.js`
- Inject mode: `script_tag`
- Backup: checked

Backend payload equivalent:

```json
{
  "agent_id": "localprobe01",
  "cmd_type": 7,
  "cmd_data": "{\"target_dir\":\"tmp_output/parasitic_webroot\",\"js_url\":\"tmp_output/parasitic_webroot/inject.js\",\"js_content\":\"\",\"inject_mode\":\"script_tag\",\"backup\":true}"
}
```

#### Server deployment example

- Agent: `probe-web-01`
- Target directory: `/var/www/html`
- JS source: URL mode
- JS URL: `http://10.10.10.20:8080/static/inject.js`
- Inject mode: `script_tag`
- Backup: checked

## 5) Multi-server topology (recommended)

### Management node

Run:

- `systemwire2`
- `alert_server`
- optional `js/latest/bot` (or host JS from nginx/CDN)

### Probe node(s)

Run:

- `agent-go`

Connectivity:

- probe -> management gRPC `50051`
- probe -> management web `5001` (for honeyfile download URL)
- management -> alert endpoints `9090/9091` as configured

## 6) Known current limits

- No final LLM inference stage in this repo yet (your note is correct).
- Account honeypot only supports currently implemented types:
  - `xshell`, `finalshell`, `openvpn`
- Parasitic deployment is filesystem-based (directory injection), not direct URL rewrite.
- Avoid Chinese filesystem paths in deploy parameters for Windows probe local tests.

