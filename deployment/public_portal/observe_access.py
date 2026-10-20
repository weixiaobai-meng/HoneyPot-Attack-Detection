"""Read scoped nginx JSON logs with commit-before-checkpoint, using local PG peer auth."""
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

LOG = Path(os.getenv("HONEYPOT_ACCESS_LOG", "/var/log/nginx/honeypot-observations.log"))
STATE = Path(os.getenv("HONEYPOT_OBSERVER_STATE", "/var/lib/honeypot-web-observer/state.json"))
INSERT = """INSERT INTO web_access_observations VALUES
    (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id) DO NOTHING"""


def normalize(item):
    request_id = str(item["request_id"])
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ValueError("invalid request id")
    path = str(item["path"]).split("?", 1)[0][:2048]
    status = int(item["status"])
    if path.startswith("/downloads/"):
        kind = "file_download_request"
    elif path.startswith(("/static/img/logo-", "/contact/")):
        kind = "file_callback_request"
    elif path.startswith("/cdn/"):
        kind = "browser_telemetry_request"
    elif path in ("/", "/index.html", "/resources/"):
        kind = "page_request"
    elif status == 404:
        kind = "unmatched_path_request"
    else:
        kind = "web_request"
    marker = str(item.get("diagnostic", ""))
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", marker):
        marker = ""
    return (request_id, datetime.fromtimestamp(float(item["time"]), timezone.utc),
            str(ipaddress.ip_address(item["ip"])), str(item["host"])[:255], int(item["port"]),
            str(item["method"])[:16], path, status, int(item["bytes"]),
            float(item["duration"]) * 1000, str(item.get("ua", ""))[:1024], kind, marker)


def read_batch(path, state, limit=250):
    """Never checkpoint an incomplete final line; rotation preserves inode identity."""
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        key = f"{stat.st_dev}:{stat.st_ino}"
        offset = int(state.get(key, 0))
        if offset > stat.st_size:
            offset = 0
        stream.seek(offset)
        rows = []
        for _ in range(limit):
            position = stream.tell()
            line = stream.readline(65537)
            if not line or not line.endswith(b"\n"):
                stream.seek(position)
                break
            try:
                rows.append(normalize(json.loads(line)))
            except (ValueError, KeyError, TypeError):
                logging.warning("skipped malformed observation at offset %s", position)
        return key, stream.tell(), rows


def checkpoint(state):
    temp = STATE.with_suffix(".next")
    temp.write_text(json.dumps(state), encoding="utf-8")
    temp.replace(STATE)


def retain(conn):
    # Only this observation table is pruned. Business alert tables are untouched.
    conn.execute("DELETE FROM web_access_observations WHERE observed_at < now()-interval '30 days'")
    conn.execute("""DELETE FROM web_access_observations WHERE (observed_at,event_id) <
        (SELECT observed_at,event_id FROM web_access_observations
         ORDER BY observed_at DESC,event_id DESC OFFSET 199999 LIMIT 1)""")


def main():
    import psycopg

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    last_retention = 0
    while True:
        try:
            with psycopg.connect("dbname=honeypot user=honeypot_web_observer connect_timeout=5",
                                 options="-c statement_timeout=15000") as conn:
                for path in (LOG.with_name(LOG.name + ".1"), LOG):
                    if not path.exists():
                        continue
                    key, offset, rows = read_batch(path, state)
                    if rows:
                        with conn.cursor() as cursor:
                            cursor.executemany(INSERT, rows)
                    conn.commit()
                    if state.get(key) != offset:
                        state[key] = offset
                        state = dict(list(state.items())[-32:])
                        checkpoint(state)
                    if rows:
                        logging.info("committed batch of %d observations", len(rows))
                if time.monotonic() - last_retention > 3600:
                    retain(conn)
                    conn.commit()
                    last_retention = time.monotonic()
        except Exception:
            logging.exception("observation collection failed; uncommitted offsets will be retried")
        time.sleep(5)


if __name__ == "__main__":
    main()
