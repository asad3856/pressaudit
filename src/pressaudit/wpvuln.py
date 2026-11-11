"""WPVulnerability API client — the free, key-free vulnerability database.

WPVulnerability (https://www.wpvulnerability.net) is a 100% open and free
API: no API key, no account. Its data is dedicated to the public domain
under CC0 1.0, so PressAudit may copy it into a local database without
permission (attribution is voluntary; PressAudit credits it in its README
and in the generated database file). Sources behind it: CVE, EUVD, JVN,
Patchstack, Wordfence, WPScan.

Endpoints (all public, JSON, no auth):
    /core/{version}/    vulnerabilities affecting that core version
    /plugin/{slug}/     all known vulnerabilities for a plugin slug
    /theme/{slug}/      all known vulnerabilities for a theme slug

Bulk endpoints (/all/...) need an API key, so update-db fetches per slug
instead — about 80 requests for the built-in slug lists, with a small
delay between them ("use it reasonably", per the API docs).

Response shape (plugin/theme):
    {"error": 0, "message": null, "data": {"name": ..., "plugin": ...,
     "latest": ..., "closed": ..., "vulnerability": [
        {"uuid": ..., "name": "Contact Form 7 [contact-form-7] < 5.3.2",
         "operator": {"min_version": null, "min_operator": null,
                      "max_version": "5.3.2", "max_operator": "lt",
                      "unfixed": "0", "closed": "0"},
         "source": [{"id": "CVE-2020-35489", "name": ..., "link": ...,
                     "description": ..., "date": ...}, ...],
         "impact": {"cvss3": {"score": "10.0", "severity": "critical", ...},
                    ...}}, ...]},
     "updated": <unix timestamp>}

Core responses have the same wrapper but no per-item operator: the
endpoint returns the vulnerabilities affecting the requested version, and
the fixed version must be recovered from the source texts (see
extract_core_fixed_in). Entries whose bound cannot be recovered are
skipped and counted, never guessed.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from .wpscan import USER_AGENT

BASE_URL = "https://www.wpvulnerability.net"

# Core versions to query for the offline database. A query for an old
# version returns the most vulnerabilities (everything still affecting
# it); the spread also catches flaws introduced in newer versions.
CORE_VERSIONS = ["4.7.1", "5.0.3", "5.8.2", "6.0.3", "6.5.5", "6.8.2"]

_FIXED_PATTERNS = [
    # "fixed in version 5.8.3" / "fixed in 5.8.3"
    re.compile(r"fixed in (?:WordPress )?version (\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"patched in (?:WordPress )?version (\d+\.\d+(?:\.\d+)?)", re.I),
    # "prior to 6.8.2" means affected < 6.8.2
    re.compile(r"prior to (?:version )?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"before (?:version )?(\d+\.\d+(?:\.\d+)?)", re.I),
]

# "versions <= 5.8.2" / "up to and including 5.8.2" / "5.8.2 and earlier"
# mean affected <= that version.
_MAX_PATTERNS = [
    re.compile(r"versions? <= (\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"<= (\d+\.\d+(?:\.\d+)?)"),
    re.compile(r"up to and including (\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"(\d+\.\d+(?:\.\d+)?) and earlier", re.I),
]


def fetch_json(path, timeout=15):
    """GET one API path and return the parsed JSON dict, or None on failure."""
    url = BASE_URL + path
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def fetch_plugin(slug, timeout=15):
    return fetch_json("/plugin/%s/" % slug, timeout=timeout)


def fetch_theme(slug, timeout=15):
    return fetch_json("/theme/%s/" % slug, timeout=timeout)


def fetch_core(version, timeout=15):
    return fetch_json("/core/%s/" % version, timeout=timeout)


def fetch_stats(timeout=15):
    return fetch_json("/", timeout=timeout)


def _first_cve(item):
    for source in item.get("source") or []:
        ident = (source.get("id") or "").strip()
        if ident.upper().startswith("CVE-"):
            return ident.upper()
    return None


def _cvss(item):
    impact = item.get("impact")
    if not isinstance(impact, dict):
        return None, None
    for key in ("cvss3", "cvss"):
        entry = impact.get(key)
        if isinstance(entry, dict) and entry.get("score"):
            return str(entry["score"]), str(entry.get("severity") or "")
    return None, None


def _description(item, limit=500):
    for source in item.get("source") or []:
        text = (source.get("description") or "").strip()
        if text:
            text = text.replace("\r", " ").replace("\n", " ")
            if len(text) > limit:
                text = text[:limit].rstrip() + "..."
            return text
    return ""


def parse_vulnerabilities(payload):
    """Convert one plugin/theme payload into DB entries.

    Returns (entries, skipped) where each entry is a dict with the keys
    PressAudit's vulndb.json uses: title, fixed_in or max_affected, cve,
    remediation, plus cvss score/severity when available. Entries whose
    version range cannot be expressed as a single bound (unfixed, ranged,
    unknown operator) are skipped and counted, never guessed.
    """
    entries, skipped = [], 0
    if not isinstance(payload, dict):
        return entries, 1
    data = payload.get("data")
    if not isinstance(data, dict):
        return entries, 1
    for item in data.get("vulnerability") or []:
        operator = item.get("operator")
        if not isinstance(operator, dict):
            skipped += 1
            continue
        if str(operator.get("unfixed")) == "1":
            skipped += 1
            continue
        if operator.get("min_version"):
            # Affects a version range (min..max); the offline DB only
            # expresses "up to X", so skip rather than misrepresent it.
            skipped += 1
            continue
        max_version = operator.get("max_version")
        max_operator = (operator.get("max_operator") or "").lower()
        if not max_version or max_operator not in ("lt", "le"):
            skipped += 1
            continue
        title = (item.get("name") or "").strip()
        if not title:
            skipped += 1
            continue
        score, severity = _cvss(item)
        entry = {
            "title": title,
            "cve": _first_cve(item),
            "remediation": "",
            "description": _description(item),
        }
        if score:
            entry["cvss_score"] = score
        if severity:
            entry["cvss_severity"] = severity
        if max_operator == "lt":
            entry["fixed_in"] = max_version
            entry["remediation"] = "Update to %s or later." % max_version
        else:
            entry["max_affected"] = max_version
            entry["remediation"] = ("Update to a version above %s."
                                     % max_version)
        entries.append(entry)
    return entries, skipped


def extract_core_fixed_in(item):
    """Recover the fixed version of a core vulnerability from its sources.

    Returns (fixed_in, max_affected, found): exactly one of fixed_in /
    max_affected is set when a bound is found. "fixed/patched in X" and
    "prior to/before X" mean affected < X (fixed_in); "<= X", "up to and
    including X" and "X and earlier" mean affected <= X (max_affected).
    """
    texts = []
    for source in item.get("source") or []:
        texts.append((source.get("name") or "") + " "
                     + (source.get("description") or ""))
    for text in texts:
        for pattern in _FIXED_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(1), None, True
        for pattern in _MAX_PATTERNS:
            match = pattern.search(text)
            if match:
                return None, match.group(1), True
    return None, None, False


def parse_core_vulnerabilities(payload):
    """Convert one core payload (vulns affecting a version) into entries.

    Same return shape as parse_vulnerabilities. The item title comes from
    the most descriptive source name; entries without a recoverable bound
    are skipped and counted.
    """
    entries, skipped = [], 0
    if not isinstance(payload, dict):
        return entries, 1
    data = payload.get("data")
    if not isinstance(data, dict):
        return entries, 1
    for item in data.get("vulnerability") or []:
        fixed_in, max_affected, found = extract_core_fixed_in(item)
        if not found:
            skipped += 1
            continue
        sources = item.get("source") or []
        title = ""
        for source in sources:
            name = (source.get("name") or "").strip()
            if name and not name.upper().startswith("CVE-"):
                title = name
                break
        if not title:
            cve = _first_cve(item)
            title = ("WordPress core vulnerability %s" % cve) if cve \
                else "WordPress core vulnerability"
        score, severity = _cvss(item)
        entry = {
            "title": title,
            "cve": _first_cve(item),
            "description": _description(item),
        }
        if score:
            entry["cvss_score"] = score
        if severity:
            entry["cvss_severity"] = severity
        if fixed_in:
            entry["fixed_in"] = fixed_in
            entry["remediation"] = "Update WordPress core to %s or later." \
                % fixed_in
        else:
            entry["max_affected"] = max_affected
            entry["remediation"] = ("Update WordPress core to a version "
                                    "above %s." % max_affected)
        entries.append(entry)
    return entries, skipped
