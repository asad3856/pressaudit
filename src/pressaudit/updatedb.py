"""Build a large local vulnerability database from a free API.

Default source — WPVulnerability (https://www.wpvulnerability.net):
``pressaudit update-db`` with no key at all fetches the WPVulnerability
API records for WordPress core and for the popular plugin/theme slugs
PressAudit knows about, and writes them to ``~/.pressaudit/vulndb.json``
(the first place the scanner looks). The API is 100% open and free, no
API key, and its data is dedicated to the public domain under CC0 1.0.
The curated starter entries are kept; fetched entries are merged in and
de-duplicated by title.

Optional source — WPScan (``--source wpscan --wpscan-api-key KEY``):
the same job against the WPScan API v3. The free WPScan tier allows 25
API requests per day, so a full refresh needs several days or a paid
token. Both updaters fetch sequentially with a small delay and stop
after several consecutive failures, saving whatever they already fetched.
"""

from __future__ import annotations

import datetime
import json
import os
import time

from . import vulndb, wpscan, wpvuln

SOURCES = ("wpvulnerability", "wpscan")


def _load_current(out_path):
    """Start from the current database so curated entries are kept."""
    current = vulndb._load_json() or {}
    return {
        "version": 1,
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "core": list(current.get("core", []) or []),
        "plugins": dict(current.get("plugins", {}) or {}),
        "themes": dict(current.get("themes", {}) or {}),
    }


def _existing_titles(data):
    titles = {entry.get("title") for entry in data["core"]}
    for entries in list(data["plugins"].values()) + list(data["themes"].values()):
        titles.update(entry.get("title") for entry in entries)
    return titles


def _save(data, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp_path, out_path)
    return (len(data["core"])
            + sum(len(v) for v in data["plugins"].values())
            + sum(len(v) for v in data["themes"].values()))


def _merge(data, existing_titles, kind, slug, entries):
    new = [e for e in entries if e["title"] not in existing_titles]
    for entry in new:
        existing_titles.add(entry["title"])
    if not new:
        return 0
    if kind == "core":
        data["core"].extend(new)
    elif kind == "plugins":
        data["plugins"].setdefault(slug, []).extend(new)
    else:
        data["themes"].setdefault(slug, []).extend(new)
    return len(new)


def update_db_wpvulnerability(out_path=None, timeout=15, delay=0.2,
                              max_failures=8, progress=None):
    """Fetch WPVulnerability data (no key) and write the merged database.

    Returns (fetched, total_entries, out_path, stats) where stats holds
    added/skipped counts per kind.
    """
    from .scanner import COMMON_THEMES, HIGH_RISK_PLUGINS, POPULAR_PLUGINS

    out_path = out_path or vulndb.default_db_path()
    jobs = ([("plugins", slug) for slug in sorted(
                set(POPULAR_PLUGINS + HIGH_RISK_PLUGINS))]
            + [("themes", slug) for slug in sorted(set(COMMON_THEMES))]
            + [("core", version) for version in wpvuln.CORE_VERSIONS])
    data = _load_current(out_path)
    data["source"] = ("WPVulnerability API (CC0 1.0 public domain) via "
                      "pressaudit update-db (merged over curated starter DB)")
    existing_titles = _existing_titles(data)
    stats = {"added": 0, "skipped": 0, "failed": 0}
    fetched = 0
    failures = 0
    for kind, slug in jobs:
        if kind == "plugins":
            payload = wpvuln.fetch_plugin(slug, timeout=timeout)
            entries, skipped = wpvuln.parse_vulnerabilities(payload) \
                if payload is not None else ([], 0)
        elif kind == "themes":
            payload = wpvuln.fetch_theme(slug, timeout=timeout)
            entries, skipped = wpvuln.parse_vulnerabilities(payload) \
                if payload is not None else ([], 0)
        else:
            payload = wpvuln.fetch_core(slug, timeout=timeout)
            entries, skipped = wpvuln.parse_core_vulnerabilities(payload) \
                if payload is not None else ([], 0)
        if payload is None:
            failures += 1
            stats["failed"] += 1
            if progress:
                progress(kind, slug, False)
            if failures >= max_failures:
                break
            continue
        failures = 0
        fetched += 1
        stats["skipped"] += skipped
        if progress:
            progress(kind, slug, True)
        stats["added"] += _merge(data, existing_titles, kind,
                                  slug if kind != "core" else None, entries)
        if delay:
            time.sleep(delay)
    total = _save(data, out_path)
    return fetched, total, out_path, stats


def _extract_wpscan_vulns(payload, kind):
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


def update_db_wpscan(api_key, out_path=None, timeout=10, delay=0.5,
                     max_failures=5, progress=None):
    """Fetch WPScan data and write the merged database.

    Returns (fetched, total_entries, out_path, stats).
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
    data = _load_current(out_path)
    data["source"] = ("WPScan API v3 via pressaudit update-db "
                      "(merged over curated starter DB)")
    existing_titles = _existing_titles(data)
    stats = {"added": 0, "skipped": 0, "failed": 0}
    fetched = 0
    failures = 0
    for kind, slug in jobs:
        url = wpscan.build_url(kind, slug)
        payload = wpscan.fetch_json(url, api_key, timeout=timeout)
        if payload is None:
            failures += 1
            stats["failed"] += 1
            if progress:
                progress(kind, slug, False)
            if failures >= max_failures:
                break
            continue
        failures = 0
        fetched += 1
        if progress:
            progress(kind, slug, True)
        entries = [_to_db_entry(v)
                   for v in _extract_wpscan_vulns(payload, kind)]
        stats["added"] += _merge(data, existing_titles, kind, slug, entries)
        if delay:
            time.sleep(delay)
    total = _save(data, out_path)
    return fetched, total, out_path, stats


def update_db(api_key=None, out_path=None, timeout=10, delay=None,
              max_failures=None, progress=None, source="wpvulnerability"):
    """Build the local database from the chosen source (default: WPVulnerability).

    Returns (fetched, total_entries, out_path, stats).
    """
    if source not in SOURCES:
        raise ValueError("unknown source %r (choose from %s)"
                         % (source, ", ".join(SOURCES)))
    if source == "wpscan":
        return update_db_wpscan(
            api_key, out_path=out_path, timeout=timeout,
            delay=0.5 if delay is None else delay,
            max_failures=5 if max_failures is None else max_failures,
            progress=progress)
    return update_db_wpvulnerability(
        out_path=out_path, timeout=15 if timeout in (None, 10) else timeout,
        delay=0.2 if delay is None else delay,
        max_failures=8 if max_failures is None else max_failures,
        progress=progress)
