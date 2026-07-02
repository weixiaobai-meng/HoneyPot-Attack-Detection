"""Controlled-experiment campaign metadata helpers.

The controlled chain experiment still uses real alerts.  A campaign id is only
an evidence anchor carried by the real trigger traffic, such as a URL query
parameter or a bait credential marker.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional
from urllib.parse import parse_qs, urlparse


CAMPAIGN_KEYS = {
    "campaign",
    "campaign_id",
    "campaignid",
    "controlled_id",
    "chain_id",
    "experiment",
    "experiment_id",
    "exp_id",
    "scenario",
    "scenario_id",
}

CAMPAIGN_TOKEN_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])((?:controlled|campaign|scenario|experiment|exp|chain)[-_][A-Za-z0-9][A-Za-z0-9_.:-]{2,80})",
    re.IGNORECASE,
)


def _clean_campaign_id(value: Any) -> Optional[str]:
    text = str(value or "").strip().strip("\"'`")
    if not text:
        return None
    text = re.split(r"[\s,;&?#]+", text, maxsplit=1)[0].strip().strip("\"'`")
    if not 3 <= len(text) <= 96:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", text):
        return None
    return text


def _extract_from_text(text: str) -> Optional[str]:
    value = str(text or "").strip()
    if not value:
        return None

    parsed = urlparse(value)
    if parsed.query:
        query = parse_qs(parsed.query, keep_blank_values=False)
        for key, values in query.items():
            if key.lower() in CAMPAIGN_KEYS:
                for item in values:
                    campaign_id = _clean_campaign_id(item)
                    if campaign_id:
                        return campaign_id

    query_like = parse_qs(value, keep_blank_values=False)
    for key, values in query_like.items():
        if key.lower() in CAMPAIGN_KEYS:
            for item in values:
                campaign_id = _clean_campaign_id(item)
                if campaign_id:
                    return campaign_id

    match = CAMPAIGN_TOKEN_RE.search(value)
    if match:
        return _clean_campaign_id(match.group(1))
    return None


def _walk_values(source: Any, depth: int = 0) -> Iterable[tuple[str, Any]]:
    if depth > 5 or source is None:
        return
    if isinstance(source, dict):
        for key, value in source.items():
            yield str(key), value
            if isinstance(value, (dict, list, tuple, set)):
                yield from _walk_values(value, depth + 1)
    elif isinstance(source, (list, tuple, set)):
        for item in source:
            yield "", item
            if isinstance(item, (dict, list, tuple, set)):
                yield from _walk_values(item, depth + 1)
    else:
        yield "", source


def extract_campaign_id(*sources: Any) -> Optional[str]:
    """Return a campaign id from explicit fields, URLs, or bait markers."""
    for source in sources:
        for key, value in _walk_values(source):
            key_text = str(key or "").strip().lower()
            if key_text in CAMPAIGN_KEYS:
                campaign_id = _clean_campaign_id(value)
                if campaign_id:
                    return campaign_id
            if isinstance(value, (str, int, float)):
                campaign_id = _extract_from_text(str(value))
                if campaign_id:
                    return campaign_id
    return None


def campaign_metadata(campaign_id: Optional[str], role: str = "controlled_chain") -> dict:
    campaign_id = _clean_campaign_id(campaign_id)
    if not campaign_id:
        return {}
    return {
        "campaign_id": campaign_id,
        "scenario_id": campaign_id,
        "scenario_role": role,
        "experiment": {
            "campaign_id": campaign_id,
            "scenario_id": campaign_id,
            "scenario_role": role,
            "data_source": "real_alert_controlled_campaign",
            "annotation_only": False,
        },
    }
