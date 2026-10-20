"""Read-only, bounded queries over HTTP observations, separate from honeypot alerts."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from .exts import db


def observation_page(hours=24, page=1, size=50, kind="", keyword=""):
    params = {"since": datetime.now(timezone.utc) - timedelta(hours=hours),
              "limit": size, "offset": (page - 1) * size}
    condition = "observed_at >= :since"
    if kind:
        condition += " AND observation_kind = :kind"
        params["kind"] = kind
    if keyword:
        condition += " AND (path ILIKE :keyword OR host ILIKE :keyword OR src_ip::text ILIKE :keyword OR diagnostic_marker ILIKE :keyword)"
        params["keyword"] = "%" + keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    total = db.session.execute(text(f"SELECT count(*) FROM web_access_observations WHERE {condition}"), params).scalar_one()
    rows = db.session.execute(text(f"""SELECT * FROM web_access_observations WHERE {condition}
        ORDER BY observed_at DESC,event_id DESC LIMIT :limit OFFSET :offset"""), params).mappings().all()
    summary = db.session.execute(text("""SELECT observation_kind,count(*) AS requests,
        count(*) FILTER (WHERE status>=200 AND status<300) AS succeeded,
        count(DISTINCT src_ip) AS source_ips FROM web_access_observations
        WHERE observed_at>=:since GROUP BY observation_kind ORDER BY requests DESC"""), params).mappings().all()
    result = []
    for row in rows:
        item = dict(row)
        item["src_ip"] = str(item["src_ip"])
        item["observed_at"] = item["observed_at"].isoformat()
        result.append(item)
    return {"rows": result, "total": total, "page": page, "size": size,
            "hours": hours, "summary": [dict(row) for row in summary]}
