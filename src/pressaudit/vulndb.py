"""Offline vulnerability data for PressAudit.

The database lives in ``data/vulndb.json`` next to this module: a curated
starter set of widely documented, high-confidence entries. Every entry was
checked against public CVE records on 8 Nov 2026. A missing entry is NOT
proof that a component is safe — run ``pressaudit update-db`` with a WPScan
API token to build a much larger local database from the WPScan API.

If the JSON file is missing (e.g. a minimal install), the embedded
fallback below is used instead.
"""

from __future__ import annotations

import json
import os

# (max_affected_version_inclusive, cve_or_note, title, remediation)
_FALLBACK_CORE = [
    (
        "4.7.1",
        "CVE-2017-5487",
        "WordPress 4.7.0/4.7.1 REST API content injection",
        "Update WordPress core to 4.7.2 or later. This flaw lets an "
        "unauthenticated attacker edit any post via the REST API.",
    ),
    (
        "4.7.1",
        "CVE-2017-5491",
        "WordPress 4.7.x taxonomy-term SQL injection (authenticated)",
        "Update WordPress core to 4.7.2 or later.",
    ),
]

_FALLBACK_PLUGINS = {
    "revslider": [
        (
            "4.1.4",
            "Publicly documented arbitrary file upload, 2014; fixed in 4.2",
            "Slider Revolution (revslider) <= 4.1.4 arbitrary file upload",
            "Update Slider Revolution to 4.2 or later, or remove it. "
            "Older versions allow unauthenticated file upload.",
        ),
    ],
    "wp-mobile-detector": [
        (
            "3.5",
            "Publicly documented unauthenticated arbitrary file upload, 2016; fixed in 3.6",
            "WP Mobile Detector < 3.6 arbitrary file upload",
            "Update WP Mobile Detector to 3.6 or later, or remove it.",
        ),
    ],
    "wysija-newsletters": [
        (
            "2.6.7",
            "Publicly documented unauthenticated file upload, 2014; fixed in 2.6.8",
            "MailPoet (Wysija) < 2.6.8 file upload",
            "Update MailPoet to 2.6.8 or later, or remove it.",
        ),
    ],
}

# WordPress core versions below this no longer receive security updates.
CORE_EOL_BELOW = "6.0"


def _load_json():
    """Load the vulnerability database.

    Search order: $PRESSAUDIT_DB, ~/.pressaudit/vulndb.json (written by
    `pressaudit update-db`), then the bundled data/vulndb.json.
    """
    candidates = []
    env_path = os.environ.get("PRESSAUDIT_DB")
    if env_path:
        candidates.append(env_path)
    candidates.append(os.path.join(os.path.expanduser("~"),
                                    ".pressaudit", "vulndb.json"))
    candidates.append(os.path.join(os.path.dirname(__file__),
                                    "data", "vulndb.json"))
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            continue
    return None


def _fixed_in_to_max(fixed_in):
    """Convert a 'fixed in X.Y.Z' version into the highest affected version.

    '5.3.2' -> '5.3.1'; '6.9' -> '6.8.999'. Approximation, but correct for
    the version comparisons PressAudit does (affected means < fixed_in).
    """
    parts = parse_version(fixed_in)
    if parts is None:
        return None
    major, minor, patch = parts
    if patch > 0:
        patch -= 1
    elif minor > 0:
        minor -= 1
        patch = 999
    elif major > 0:
        major -= 1
        minor = 999
        patch = 999
    else:
        return None
    return "%d.%d.%d" % (major, minor, patch)


def _entry_to_tuple(entry):
    bound = entry.get("max_affected")
    if not bound and entry.get("fixed_in"):
        bound = _fixed_in_to_max(entry["fixed_in"])
    if not bound:
        return None
    return (
        bound,
        entry.get("cve") or entry.get("note", ""),
        entry["title"],
        entry["remediation"],
    )


def _from_json(data):
    """Convert vulndb.json into the (CORE_VULNS, PLUGIN_VULNS) tuple format."""
    core = []
    for entry in data.get("core", []) or []:
        item = _entry_to_tuple(entry)
        if item is not None:
            core.append(item)
    plugins = {}
    for slug, entries in (data.get("plugins", {}) or {}).items():
        items = []
        for entry in entries:
            item = _entry_to_tuple(entry)
            if item is not None:
                items.append(item)
        if items:
            plugins[slug] = items
    for slug, entries in (data.get("themes", {}) or {}).items():
        items = []
        for entry in entries:
            item = _entry_to_tuple(entry)
            if item is not None:
                items.append(item)
        if items:
            plugins.setdefault(slug, []).extend(items)
    return core, plugins


def default_db_path():
    """Default location for `pressaudit update-db` output."""
    return os.path.join(os.path.expanduser("~"), ".pressaudit", "vulndb.json")


def db_stats():
    """Return (core_entries, plugin_slugs, plugin_entries) for reporting."""
    return (len(CORE_VULNS), len(PLUGIN_VULNS),
            sum(len(v) for v in PLUGIN_VULNS.values()))


def parse_version(text):
    """Parse '6.2.1' (or '6.2') into a tuple of ints; returns None if unparsable."""
    if not text:
        return None
    parts = []
    for piece in str(text).strip().split("."):
        piece = piece.split("-")[0].split("+")[0]
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def version_lte(version, maximum):
    """True when `version` <= `maximum` (both dotted strings)."""
    parsed, limit = parse_version(version), parse_version(maximum)
    if parsed is None or limit is None:
        return False
    return parsed <= limit


def version_lt(version, maximum):
    """True when `version` < `maximum` (both dotted strings)."""
    parsed, limit = parse_version(version), parse_version(maximum)
    if parsed is None or limit is None:
        return False
    return parsed < limit


def core_vulns_for(version):
    """Return the CORE_VULNS entries that affect `version`."""
    return [
        entry
        for entry in CORE_VULNS
        if version_lte(version, entry[0])
    ]


def plugin_vulns_for(slug, version):
    """Return the PLUGIN_VULNS entries that affect `slug` at `version`."""
    if version is None:
        return []
    return [
        entry
        for entry in PLUGIN_VULNS.get(slug, [])
        if version_lte(version, entry[0])
    ]


# Load the database last: _from_json needs parse_version (defined above).
_DATA = _load_json()
if _DATA is not None:
    CORE_VULNS, PLUGIN_VULNS = _from_json(_DATA)
else:  # pragma: no cover - only when the data file is missing
    CORE_VULNS, PLUGIN_VULNS = _FALLBACK_CORE, _FALLBACK_PLUGINS
