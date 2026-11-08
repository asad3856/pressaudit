"""Build a large local vulnerability database from the WPScan API.

``pressaudit update-db --wpscan-api-key KEY`` fetches the WPScan API
records for WordPress core and for the popular plugin/theme slugs
PressAudit knows about, and writes them to ``~/.pressaudit/vulndb.json``
(the first place the scanner looks). The curated starter entries are
kept; WPScan entries are merged in and de-duplicated by title.

The free WPScan tier allows 25 API requests per day, so a full refresh
needs several days or a paid token. The updater fetches sequentially
with a small delay and stops after 5 consecutive failures (for example
when the daily quota is exhausted), saving whatever it already fetched.
"""

from __future__ import annotations

import datetime
import json
import os
import time

from . import vulndb, wpscan


def _extract_vulns(payload, kind):
    """Collect {title, fixed_in, cve, references} dicts from a WPScan payload."""
    entries = []
    if kind == "core":
        # /wordpresses returns {"<version>": {"vulnerabilities": [...]}, ...}
        sources = payload.values() if isinstance(payload, dict) else []
    else:
        sources = [payload]
    seen = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        for vuln in wpscan.parse_vulnerabilities(source, None):
            key = (vuln["title"], vuln["fixed_in"])
            if key in seen:
                continue
            seen.add(key)
            entries.append(vuln)
    return entries


def _to_db_entry(vuln):
    return {
        "title": vuln["title"],
        "fixed_in": vuln["fixed_in"],
        "cve": vuln.get("cve"),
        "remediation": "Update to %s or later." % vuln["fixed_in"],
    }


def update_db(api_key, out_path=None, timeout=10, delay=0.5,
              max_failures=5, progress=None):
    """Fetch WPScan data and write the merged database.

    Returns (fetched_slugs, total_entries, out_path).
    Raises ValueError when no API key is given.
    """
    if not api_key:
        raise ValueError("a WPScan API key is required (free at "
                         "https://wpscan.com/api)")
    from .scanner import COMMON_THEMES, HIGH_RISK_PLUGINS, POPULAR_PLUGINS

    out_path = out_path or vulndb.default_db_path()
    jobs = ([("core", None)]
            + [("plugins", slug) for slug in sorted(
                set(POPULAR_PLUGINS + HIGH_RISK_PLUGINS))]
            + [("themes", slug) for slug in sorted(set(COMMON_THEMES))])

    # Start from the current database so curated entries are kept.
    current = vulndb._load_json() or {}
    data = {
        "version": 1,
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "source": "WPScan API v3 via pressaudit update-db (merged over curated starter DB)",
        "core": list(current.get("core", []) or []),
        "plugins": dict(current.get("plugins", {}) or {}),
        "themes": dict(current.get("themes", {}) or {}),
    }
    existing_titles = {entry.get("title")
                       for entry in data["core"]}
    for entries in list(data["plugins"].values()) + list(data["themes"].values()):
        existing_titles.update(entry.get("title") for entry in entries)

    fetched = 0
    failures = 0
    for kind, slug in jobs:
        url = wpscan.build_url(kind, slug)
        payload = wpscan.fetch_json(url, api_key, timeout=timeout)
        if payload is None:
            failures += 1
            if progress:
                progress(kind, slug, False)
            if failures >= max_failures:
                break
            continue
        failures = 0
        fetched += 1
        if progress:
            progress(kind, slug, True)
        entries = [_to_db_entry(v) for v in _extract_vulns(payload, kind)
                   if v["title"] not in existing_titles]
        for entry in entries:
            existing_titles.add(entry["title"])
        if not entries:
            continue
        if kind == "core":
            data["core"].extend(entries)
        elif kind == "plugins":
            data["plugins"].setdefault(slug, []).extend(entries)
        else:
            data["themes"].setdefault(slug, []).extend(entries)
        if delay:
            time.sleep(delay)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp_path, out_path)
    total = (len(data["core"])
             + sum(len(v) for v in data["plugins"].values())
             + sum(len(v) for v in data["themes"].values()))
    return fetched, total, out_path
