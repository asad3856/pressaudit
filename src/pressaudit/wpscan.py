"""Optional live vulnerability lookups against the WPScan API (v3).

WPScan maintains the largest public WordPress vulnerability database. A
free API token (https://wpscan.com/api) unlocks live lookups for core,
plugins, and themes; without a token PressAudit falls back to its small
curated offline database and never contacts WPScan. Any API failure is
treated as "no live data", never as a scan failure.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://wpscan.com/api/v3"
USER_AGENT = "PressAudit/0.3.0 (+https://github.com/asad3856/pressaudit)"


def build_url(kind, slug=None):
    """Build a WPScan API URL. kind is 'core', 'plugins', or 'themes'."""
    if kind == "core":
        path = "/wordpresses"
    else:
        path = "/%s/%s" % (kind, urllib.parse.quote(slug))
    return API_BASE + path


def fetch_json(url, api_key, timeout=10):
    """GET a WPScan API URL and return the parsed JSON, or None on failure."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Authorization", "Token token=%s" % api_key)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def parse_vulnerabilities(data, version):
    """Extract the vulnerabilities affecting `version` from a WPScan payload.

    Returns a list of dicts: {title, fixed_in, cve, references}.
    Entries without a fixed_in version, or fixed at/below the installed
    version, are skipped. `data` is the JSON object returned for one
    plugin/theme, or the single-entry dict for a core version lookup.
    """
    from . import vulndb

    if not isinstance(data, dict):
        return []
    results = []
    for vuln in data.get("vulnerabilities", []) or []:
        fixed_in = vuln.get("fixed_in")
        if not fixed_in:
            continue
        if version and not vulndb.version_lt(version, fixed_in):
            continue
        raw_refs = vuln.get("references", []) or []
        refs = []
        if isinstance(raw_refs, dict):
            # WPScan v3 returns {"cve": ["2014-9735"], "url": [...], ...}
            for value in raw_refs.values():
                if isinstance(value, list):
                    refs.extend(str(item) for item in value)
                elif value:
                    refs.append(str(value))
        elif isinstance(raw_refs, list):
            for ref in raw_refs:
                if isinstance(ref, dict) and ref.get("url"):
                    refs.append(ref["url"])
                elif isinstance(ref, str):
                    refs.append(ref)
        cve = None
        for ref in refs:
            if "cve.mitre.org" in ref:
                cve = ref
                break
            if re.match(r"^CVE-\d{4}-\d{4,}$", ref):
                cve = ref
                break
            if re.match(r"^\d{4}-\d{4,}$", ref):
                cve = "CVE-" + ref
                break
        results.append({
            "title": vuln.get("title") or "Vulnerability",
            "fixed_in": fixed_in,
            "cve": cve,
            "references": refs[:5],
        })
    return results


def lookup(kind, slug, version, api_key, timeout=10):
    """Look up live vulnerabilities for one component. Returns a list (possibly empty)."""
    if not api_key:
        return []
    url = build_url(kind, slug)
    data = fetch_json(url, api_key, timeout=timeout)
    if data is None:
        return []
    if kind == "core":
        # /wordpresses returns {"<version>": {...}}; pick the entry matching
        # the installed version, or the first one.
        entry = data.get(version) if isinstance(data, dict) else None
        if entry is None and isinstance(data, dict) and data:
            entry = next(iter(data.values()))
        return parse_vulnerabilities(entry or {}, version)
    return parse_vulnerabilities(data, version)
