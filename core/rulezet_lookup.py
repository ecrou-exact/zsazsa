import json
import logging

import requests

import config as _cfg

logger = logging.getLogger(__name__)


def _search(endpoint: str, param: str, ids: list[str]) -> list[dict] | None:
    """GET a Rulezet public search endpoint. Returns None on any failure so
    callers can tell "nothing configured/reachable" apart from "no matches"."""
    base_url = (getattr(_cfg, "RULEZET_URL", "") or "").rstrip("/")
    if not base_url or not ids:
        return None
    try:
        r = requests.get(
            f"{base_url}/api/rule/public/{endpoint}",
            params={param: ",".join(ids)},
            timeout=10,
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception as exc:
        logger.warning("Rulezet lookup (%s) for %s failed: %s", endpoint, ids, exc)
        return None

    rules = []
    for item in data.get("results") or []:
        raw_cve = item.get("cve_id")
        if isinstance(raw_cve, str):
            try:
                raw_cve = json.loads(raw_cve) if raw_cve else []
            except ValueError:
                raw_cve = [raw_cve]
        rules.append({
            "id": item.get("id"),
            "uuid": item.get("uuid") or "",
            "title": item.get("title") or f"Rule {item.get('id')}",
            "format": item.get("format") or "",
            "source": item.get("source") or "",
            "license": item.get("license") or "",
            "author": item.get("author") or "",
            "last_modif": item.get("formatted_date") or item.get("last_modif") or "",
            "cve_ids": raw_cve or [],
            "matched_techniques": item.get("matched_techniques") or [],
            "quality_score": item.get("quality_score"),
            "content": item.get("to_string") or "",
            # Rulezet's public search API hardcodes detail_url to
            # https://rulezet.org regardless of which instance answered —
            # rebuild it from the configured RULEZET_URL so a local/dev
            # instance links to itself, not to production.
            "url": f"{base_url}/rule/detail_rule/{item.get('id')}" if item.get("id") else base_url,
        })
    return rules


def search_rules_by_cve(cve_ids: list[str]) -> list[dict]:
    """Query a Rulezet instance's public API for detection rules matching CVE IDs.

    Returns a list of {id, title, format, source, cve_ids, quality_score, url}
    dicts, or an empty list on any failure, when RULEZET_URL is not configured,
    or when no CVE ID is given — so callers can treat this as optional
    enrichment, the same way core.vuln_lookup.fetch_cve_info does.
    """
    return _search("search_rules_by_cve", "cve_ids", cve_ids) or []


def search_rules_by_attack(technique_ids: list[str]) -> list[dict]:
    """Query a Rulezet instance's public API for detection rules mapped to
    MITRE ATT&CK technique IDs (e.g. T1071, T1566.001).

    Same shape and failure handling as search_rules_by_cve.
    """
    return _search("search_rules_by_attack", "technique_ids", technique_ids) or []
